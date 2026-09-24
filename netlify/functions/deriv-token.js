// netlify/functions/deriv-token.js
//
// Runs server-side on Netlify (never in the browser). Deriv's own docs
// require the authorization code to be exchanged for a token from a
// backend, so this function is that backend.
//
// After exchanging the code, this function identifies the real,
// authenticated Deriv login ID (e.g. "CR123456") via Deriv's own API —
// never from anything the browser supplies. That verified identity is then
// AUTOMATICALLY linked to an app_user in Postgres (Neon): first connection
// auto-creates the link, later connections recognize it, and a Deriv
// identity already linked to a different app_user is rejected rather than
// silently reassigned. Nothing here needs manual SQL after deploying.
//
// Environment variables required:
//   DERIV_CLIENT_ID  - your Deriv App ID
//   DATABASE_URL     - the Neon Postgres connection string

const { Client } = require('pg');
const crypto = require('crypto');

const DERIV_TOKEN_URL = 'https://auth.deriv.com/oauth2/token';
const LEGACY_ACCOUNTS_URL = 'https://api.derivws.com/trading/v1/options/legacy/accounts';

const SESSION_COOKIE = 'app_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach(function (pair) {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

// Prefer the real-money (CR-prefixed) account as the canonical identity for
// this Deriv login; fall back to whatever the first account is (e.g. a
// virtual/demo-only login) if no CR account is present.
function pickCanonicalLoginid(loginids) {
  return loginids.find(function (id) { return /^CR/i.test(id); }) || loginids[0];
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const DERIV_CLIENT_ID = process.env.DERIV_CLIENT_ID;
  if (!DERIV_CLIENT_ID) {
    console.error('DERIV_CLIENT_ID env var is not set');
    return { statusCode: 500, body: JSON.stringify({ error: 'server_misconfigured', message: 'DERIV_CLIENT_ID env var is not set' }) };
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
  let loginids;
  try {
    const acctResponse = await fetch(LEGACY_ACCOUNTS_URL, {
      headers: { 'Authorization': 'Bearer ' + accessToken, 'Deriv-App-ID': DERIV_CLIENT_ID }
    });
    const acctData = await acctResponse.json();
    console.log('legacy/accounts responded:', acctResponse.status);

    if (!acctResponse.ok) {
      return { statusCode: 502, body: JSON.stringify({ error: 'account_lookup_failed', message: 'Could not identify the Deriv account.' }) };
    }

    const source = acctData.loginids || (acctData.data && acctData.data.loginids) || acctData.data || acctData;
    loginids = Object.keys(source || {});
  } catch (err) {
    console.error('Failed to identify Deriv account:', err.message);
    return { statusCode: 502, body: JSON.stringify({ error: 'account_lookup_failed', message: err.message }) };
  }

  if (!loginids || loginids.length === 0) {
    console.error('No loginid found for this token.');
    return { statusCode: 403, body: JSON.stringify({ error: 'no_account_found', message: 'Could not identify a Deriv account for this login.' }) };
  }

  const canonicalLoginid = pickCanonicalLoginid(loginids);
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
        loginid: canonicalLoginid
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
