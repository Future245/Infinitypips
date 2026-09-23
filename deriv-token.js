// netlify/functions/deriv-token.js
//
// Runs server-side on Netlify (never in the browser). Deriv's own docs
// require the authorization code to be exchanged for a token from a
// backend, so this function is that backend.
//
// After exchanging the code, this function identifies the real,
// authenticated Deriv login ID (e.g. "CR123456") via Deriv's own API —
// never from anything the browser supplies — and checks it against the
// deriv_whitelist table in Neon/Postgres. This function only ever READS
// that table. Nothing here adds, removes, or otherwise modifies whitelist
// entries — that's managed directly in Neon's own SQL Editor, outside the
// app entirely.
//
// Environment variables required:
//   DERIV_CLIENT_ID  - your Deriv App ID
//   DATABASE_URL     - the Neon Postgres connection string

const { Client } = require('pg');

const DERIV_TOKEN_URL = 'https://auth.deriv.com/oauth2/token';
const LEGACY_ACCOUNTS_URL = 'https://api.derivws.com/trading/v1/options/legacy/accounts';

async function isWhitelisted(loginids) {
  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    const result = await client.query(
      'SELECT deriv_loginid FROM deriv_whitelist WHERE deriv_loginid = ANY($1) LIMIT 1',
      [loginids]
    );
    return result.rows.length > 0 ? result.rows[0].deriv_loginid : null;
  } finally {
    await client.end();
  }
}

async function touchConnection(loginid) {
  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    await client.query(
      `INSERT INTO deriv_connections (deriv_loginid, created_at, updated_at)
       VALUES ($1, now(), now())
       ON CONFLICT (deriv_loginid) DO UPDATE SET updated_at = now()`,
      [loginid]
    );
  } finally {
    await client.end();
  }
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const DERIV_CLIENT_ID = process.env.DERIV_CLIENT_ID;

  if (!DERIV_CLIENT_ID) {
    console.error('DERIV_CLIENT_ID env var is not set');
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'server_misconfigured', message: 'DERIV_CLIENT_ID env var is not set' })
    };
  }

  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL env var is not set');
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'server_misconfigured', message: 'DATABASE_URL env var is not set' })
    };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (err) {
    console.error('Failed to parse request body:', event.body);
    return { statusCode: 400, body: JSON.stringify({ error: 'invalid_json' }) };
  }

  const { code, code_verifier: codeVerifier, redirect_uri: redirectUri } = payload;

  console.log('Token exchange request:', {
    hasCode: !!code,
    hasCodeVerifier: !!codeVerifier,
    redirectUri: redirectUri
  });

  if (!code || !codeVerifier || !redirectUri) {
    console.error('Missing params:', { code: !!code, codeVerifier: !!codeVerifier, redirectUri: !!redirectUri });
    return { statusCode: 400, body: JSON.stringify({ error: 'missing_params' }) };
  }

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
    console.log('Deriv token endpoint responded:', response.status, JSON.stringify(data));

    if (!response.ok) {
      return { statusCode: response.status, body: JSON.stringify(data) };
    }

    accessToken = data.access_token;
    expiresIn = data.expires_in;
    tokenType = data.token_type;
  } catch (err) {
    console.error('Upstream error calling Deriv token endpoint:', err.message, err.stack);
    return { statusCode: 502, body: JSON.stringify({ error: 'upstream_error', message: err.message }) };
  }

  // --- Identify the real, authenticated Deriv account server-side ---
  let loginids;
  try {
    const acctResponse = await fetch(LEGACY_ACCOUNTS_URL, {
      headers: {
        'Authorization': 'Bearer ' + accessToken,
        'Deriv-App-ID': DERIV_CLIENT_ID
      }
    });

    const acctData = await acctResponse.json();
    console.log('legacy/accounts responded:', acctResponse.status, JSON.stringify(acctData));

    if (!acctResponse.ok) {
      return {
        statusCode: 502,
        body: JSON.stringify({ error: 'account_lookup_failed', message: 'Could not identify the Deriv account.' })
      };
    }

    const source = acctData.loginids || (acctData.data && acctData.data.loginids) || acctData.data || acctData;
    loginids = Object.keys(source || {});
  } catch (err) {
    console.error('Failed to identify Deriv account:', err.message);
    return { statusCode: 502, body: JSON.stringify({ error: 'account_lookup_failed', message: err.message }) };
  }

  if (!loginids || loginids.length === 0) {
    console.error('No loginid found for this token.');
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'no_account_found', message: 'Could not identify a Deriv account for this login.' })
    };
  }

  // --- Check the whitelist (read-only; managed directly in Neon) ---
  let matchedLoginid;
  try {
    matchedLoginid = await isWhitelisted(loginids);
  } catch (err) {
    console.error('Whitelist check failed:', err.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'whitelist_check_failed', message: err.message }) };
  }

  if (!matchedLoginid) {
    console.log('Deriv account not whitelisted:', loginids.join(', '));
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'not_authorized', message: 'This Deriv account is not authorized to use this app.' })
    };
  }

  // --- Record/refresh this account's connection record ---
  try {
    await touchConnection(matchedLoginid);
  } catch (err) {
    // Not fatal — the account is already verified and whitelisted, so log
    // it but don't block access over a bookkeeping write.
    console.error('Failed to update connections record:', err.message);
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      access_token: accessToken,
      expires_in: expiresIn,
      token_type: tokenType,
      loginid: matchedLoginid
    })
  };
};
