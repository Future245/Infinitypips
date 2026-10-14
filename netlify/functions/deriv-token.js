   // netlify/functions/deriv-token.js
//
// Runs server-side on Netlify (never in the browser). Deriv's own docs
// require the authorization code to be exchanged for a token from a
// backend, so this function is that backend.
//
// After exchanging the code, this function identifies the real,
// authenticated Deriv account (its account_id, e.g. "DOT90004580") via
// Deriv's own API — never from anything the browser supplies. That
// verified identity is then AUTOMATICALLY linked to an app_user in
// Postgres (Neon): first connection auto-creates the link, later
// connections recognize it, and a Deriv identity already linked to a
// different app_user is rejected rather than silently reassigned. Nothing
// here needs manual SQL after deploying.
//
// FOUR-APP SUPPORT
// The portal connects up to eight separate Deriv apps ("slots" 1-8), one
// after another, all for the SAME Deriv account. The browser says which
// slot it is finishing (`slot` in the request body); this function picks
// that slot's App ID from its own environment, so the code exchange always
// uses the same client_id the login was started with. Slot 1 behaves
// exactly like the old single-app flow. Slots 2-4 are only accepted when
//   - this browser already has a session (slot 1 was done first),
//   - the previous slot is already recorded as connected, and
//   - the Deriv login is the one already linked to that session.
// Each successful connection is recorded in app_connections
// (db/app_connections_schema.sql).
//
// Environment variables required:
//   DERIV_CLIENT_ID    - App ID for slot 1 (unchanged from before)
//   DERIV_CLIENT_ID_2  - App ID for slot 2
//   DERIV_CLIENT_ID_3  - App ID for slot 3
//   DERIV_CLIENT_ID_4  - App ID for slot 4
//   DERIV_CLIENT_ID_5..8 - App IDs for slots 5-8 (Nuclear Mode)
//   DATABASE_URL       - the Neon Postgres connection string

const { Client } = require('pg');
const crypto = require('crypto');

const DERIV_TOKEN_URL = 'https://auth.deriv.com/oauth2/token';
const ACCOUNTS_URL = 'https://api.derivws.com/trading/v1/options/accounts';

const SESSION_COOKIE = 'app_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const MAX_SLOT = 8;

// Slot 1 keeps using the original DERIV_CLIENT_ID variable so existing
// deployments keep working without any change.
function clientIdForSlot(slot) {
  return slot === 1 ? process.env.DERIV_CLIENT_ID : process.env['DERIV_CLIENT_ID_' + slot];
}

function jsonError(statusCode, error, message) {
  return { statusCode: statusCode, body: JSON.stringify({ error: error, message: message }) };
}

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach(function (pair) {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

// Prefer the real-money account as the canonical identity for this Deriv
// login; fall back to a demo account if the user has no real account yet.
function pickCanonicalAccount(accounts) {
  var real = accounts.find(function (a) { return a.account_type === 'real'; });
  return (real || accounts[0]).account_id;
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL env var is not set');
    return { statusCode: 500, body: JSON.stringify({ error: 'server_misconfigured', message: 'DATABASE_URL env var is not set' }) };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (err) {
    console.error('Failed to parse request body:', event.body);
    return { statusCode: 400, body: JSON.stringify({ error: 'invalid_json' }) };
  }

  const { code, code_verifier: codeVerifier, redirect_uri: redirectUri } = payload;

  // Which of the four apps is this login for? Missing = slot 1 (old flow).
  const slot = payload.slot === undefined || payload.slot === null ? 1 : Number(payload.slot);
  if (!Number.isInteger(slot) || slot < 1 || slot > MAX_SLOT) {
    return jsonError(400, 'invalid_slot', 'Unknown app slot.');
  }

  const DERIV_CLIENT_ID = clientIdForSlot(slot);
  if (!DERIV_CLIENT_ID) {
    const varName = slot === 1 ? 'DERIV_CLIENT_ID' : 'DERIV_CLIENT_ID_' + slot;
    console.error(varName + ' env var is not set');
    return jsonError(500, 'server_misconfigured', varName + ' env var is not set');
  }

  if (!code || !codeVerifier || !redirectUri) {
    console.error('Missing params:', { code: !!code, codeVerifier: !!codeVerifier, redirectUri: !!redirectUri });
    return { statusCode: 400, body: JSON.stringify({ error: 'missing_params' }) };
  }

  // --- Exchange the authorization code for a token (server-side, PKCE) ---
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: DERIV_CLIENT_ID,
    code: code,
    code_verifier: codeVerifier,
    redirect_uri: redirectUri
  });

  let accessToken, expiresIn, tokenType;
  try {
    const response = await fetch(DERIV_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    const data = await response.json();
    console.log('Deriv token endpoint responded:', response.status);

    if (!response.ok) {
      return { statusCode: response.status, body: JSON.stringify(data) };
    }
    accessToken = data.access_token;
    expiresIn = data.expires_in;
    tokenType = data.token_type;
  } catch (err) {
    console.error('Upstream error calling Deriv token endpoint:', err.message);
    return { statusCode: 502, body: JSON.stringify({ error: 'upstream_error', message: err.message }) };
  }

  // --- Identify the real, authenticated Deriv account server-side ---
  let accounts;
  try {
    const acctResponse = await fetch(ACCOUNTS_URL, {
      headers: { 'Authorization': 'Bearer ' + accessToken, 'Deriv-App-ID': DERIV_CLIENT_ID }
    });
    const acctData = await acctResponse.json();
    console.log('accounts endpoint responded:', acctResponse.status);

    if (!acctResponse.ok) {
      return { statusCode: 502, body: JSON.stringify({ error: 'account_lookup_failed', message: 'Could not identify the Deriv account.' }) };
    }

    accounts = acctData.data || [];
  } catch (err) {
    console.error('Failed to identify Deriv account:', err.message);
    return { statusCode: 502, body: JSON.stringify({ error: 'account_lookup_failed', message: err.message }) };
  }

  if (!accounts.length) {
    console.error('No accounts found for this token.');
    return { statusCode: 403, body: JSON.stringify({ error: 'no_account_found', message: 'Could not identify a Deriv account for this login.' }) };
  }

  const canonicalLoginid = pickCanonicalAccount(accounts);
  const loginids = accounts.map(function (a) { return a.account_id; });
  const cookies = parseCookies(event.headers && (event.headers.cookie || event.headers.Cookie));
  const incomingSessionToken = cookies[SESSION_COOKIE];

  // --- Automatic account linking (no manual whitelist step) ---
  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();

  try {
    await client.query('BEGIN');

    // Resolve the app_user already tied to this browser, if any valid session exists.
    let sessionAppUserId = null;
    if (incomingSessionToken) {
      const sessionRes = await client.query(
        'SELECT app_user_id FROM app_sessions WHERE session_token = $1 AND expires_at > now()',
        [incomingSessionToken]
      );
      if (sessionRes.rows.length) sessionAppUserId = sessionRes.rows[0].app_user_id;
    }

    // Has this verified Deriv identity been linked before?
    const existingRes = await client.query(
      'SELECT app_user_id FROM deriv_accounts WHERE deriv_loginid = $1',
      [canonicalLoginid]
    );

    // Slots 2-4 may only EXTEND an existing setup: same browser session,
    // same Deriv account as slot 1, and the previous slot already done.
    // They never create users or link a new Deriv identity.
    if (slot > 1) {
      if (!sessionAppUserId) {
        await client.query('ROLLBACK');
        return jsonError(409, 'previous_slot_required', 'Connect App 1 first, then continue in order.');
      }
      if (!existingRes.rows.length || String(existingRes.rows[0].app_user_id) !== String(sessionAppUserId)) {
        await client.query('ROLLBACK');
        console.warn('Slot', slot, 'login did not match the linked Deriv account');
        return jsonError(409, 'different_account', 'App ' + slot + ' must be connected with the same Deriv account as App 1.');
      }
      const prevRes = await client.query(
        "SELECT 1 FROM app_connections WHERE app_user_id = $1 AND app_slot = $2 AND status = 'connected'",
        [sessionAppUserId, slot > 5 ? 4 : slot - 1]   // Nuclear apps 5-8 only need Apps 1-4 done, in any order
      );
      if (!prevRes.rows.length) {
        await client.query('ROLLBACK');
        return jsonError(409, 'previous_slot_required', 'Connect App ' + (slot - 1) + ' first, then continue in order.');
      }
    }

    let appUserId;
    if (existingRes.rows.length) {
      const linkedAppUserId = existingRes.rows[0].app_user_id;

      if (sessionAppUserId && sessionAppUserId !== linkedAppUserId) {
        // This Deriv account is already linked to a DIFFERENT app user.
        // Never silently reassign it.
        await client.query('ROLLBACK');
        console.warn('Deriv identity/app_user conflict:', canonicalLoginid);
        return {
          statusCode: 409,
          body: JSON.stringify({
            error: 'account_conflict',
            message: 'This Deriv account is already linked to a different account here.'
          })
        };
      }

      appUserId = linkedAppUserId;
      await client.query(
        'UPDATE deriv_accounts SET trading_accounts = $2, last_seen_at = now() WHERE deriv_loginid = $1',
        [canonicalLoginid, JSON.stringify(loginids)]
      );
    } else {
      // First time this Deriv identity has ever connected — auto-provision it.
      appUserId = sessionAppUserId;
      if (!appUserId) {
        const userRes = await client.query('INSERT INTO app_users DEFAULT VALUES RETURNING id');
        appUserId = userRes.rows[0].id;
      }
      await client.query(
        'INSERT INTO deriv_accounts (deriv_loginid, app_user_id, trading_accounts) VALUES ($1, $2, $3)',
        [canonicalLoginid, appUserId, JSON.stringify(loginids)]
      );
    }

    // Issue a fresh server-side session for this browser.
    const newSessionToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
    await client.query(
      'INSERT INTO app_sessions (session_token, app_user_id, deriv_loginid, expires_at) VALUES ($1, $2, $3, $4)',
      [newSessionToken, appUserId, canonicalLoginid, expiresAt]
    );

    // Record that this slot is connected. For slot 1 this is best-effort
    // (a SAVEPOINT keeps the normal login working even if the new table has
    // not been created yet). For slots 2-4 the record IS the point, so a
    // failure aborts the request.
    await client.query('SAVEPOINT record_connection');
    try {
      await client.query(
        "INSERT INTO app_connections (app_user_id, app_slot, client_id, deriv_loginid, status, connected_at, last_checked_at, last_error) " +
        "VALUES ($1, $2, $3, $4, 'connected', now(), now(), NULL) " +
        "ON CONFLICT (app_user_id, app_slot) DO UPDATE SET client_id = EXCLUDED.client_id, " +
        "deriv_loginid = EXCLUDED.deriv_loginid, status = 'connected', connected_at = now(), " +
        "last_checked_at = now(), last_error = NULL",
        [appUserId, slot, DERIV_CLIENT_ID, canonicalLoginid]
      );
      await client.query('RELEASE SAVEPOINT record_connection');
    } catch (connErr) {
      // Slots 2-4 must be recorded. Slots 5-8 (Nuclear Mode) stay usable even if
      // the database has not been widened to 8 slots yet (see db/app_connections_8_slots.sql).
      if (slot > 1 && slot <= 4) throw connErr;
      console.error('Could not record slot ' + slot + ' connection (is db/app_connections_schema.sql applied?):', connErr.message);
      await client.query('ROLLBACK TO SAVEPOINT record_connection');
    }

    await client.query('COMMIT');

    return {
      statusCode: 200,
      headers: {
        'Set-Cookie': SESSION_COOKIE + '=' + newSessionToken + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + SESSION_TTL_SECONDS
      },
      body: JSON.stringify({
        // Still returned so the existing frontend (Ariana.html) can keep
        // talking to Deriv's own trading WebSocket API directly, exactly as
        // it does today — that connection isn't proxied through our
        // backend, so the client genuinely needs this token.
        access_token: accessToken,
        expires_in: expiresIn,
        token_type: tokenType,
        loginid: canonicalLoginid,
        slot: slot
      })
    };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('Account linking failed:', err.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'linking_failed', message: err.message }) };
  } finally {
    await client.end();
  }
};
