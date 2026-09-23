// netlify/functions/session-status.js
//
// Answers ONE question for the frontend: "does the person making this
// request already have a registered, authorized identity in our
// database?" It reads the persistent, httpOnly `app_session` cookie
// (set by deriv-token.js) rather than anything the browser can fake —
// there is no client-supplied identity here, only the cookie.
//
// This is what lets "Access Robot" recognize a returning user even after
// they've closed the browser completely and sessionStorage is gone.

const { Client } = require('pg');

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach(function (pair) {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: JSON.stringify({ error: 'method_not_allowed' }) };
  }

  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL env var is not set');
    return { statusCode: 500, body: JSON.stringify({ error: 'server_misconfigured' }) };
  }

  const cookies = parseCookies(event.headers && (event.headers.cookie || event.headers.Cookie));
  const sessionToken = cookies['app_session'];

  if (!sessionToken) {
    return { statusCode: 200, body: JSON.stringify({ registered: false }) };
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();

  try {
    const res = await client.query(
      'SELECT app_user_id, deriv_loginid FROM app_sessions WHERE session_token = $1 AND expires_at > now()',
      [sessionToken]
    );

    if (!res.rows.length) {
      return { statusCode: 200, body: JSON.stringify({ registered: false }) };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ registered: true, loginid: res.rows[0].deriv_loginid })
    };
  } catch (err) {
    console.error('session-status lookup failed:', err.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'lookup_failed', message: err.message }) };
  } finally {
    await client.end();
  }
};
