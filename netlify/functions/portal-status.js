// netlify/functions/portal-status.js
//
// Answers ONE question for the frontend: "has this browser already
// proven, server-side, that it holds a valid Infinity Pips serial key?"
// It reads the persistent, httpOnly `portal_session` cookie set by
// verify-serial-key.js — never anything the client claims.
//
// The Client Portal view (renderPortal, in index.html) calls this BEFORE
// rendering anything. That means a forced/direct call to the portal view
// — from the browser console, from the ?deriv_connected=1 OAuth-return
// URL, or from a bookmark — cannot display the portal without a real,
// database-backed serial key session behind it. Anyone without one is
// bounced back to the Serial Key page.
//
// This is the serial-key equivalent of session-status.js (which answers
// the same kind of question for the Deriv OAuth session). The two are
// intentionally separate cookies/tables — a serial key session does not
// imply a Deriv session, and vice versa.
//
// Environment variables required:
//   DATABASE_URL - the Neon Postgres connection string

const core = require('../lib/auth-core');

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
  const sessionToken = cookies['portal_session'];

  if (!sessionToken) {
    return { statusCode: 200, body: JSON.stringify({ authorized: false }) };
  }

  let client;
  try {
    client = await core.connectDb();
  } catch (err) {
    console.error('database unavailable:', err.message);
    return { statusCode: 503, headers: { 'Cache-Control': 'no-store' }, body: JSON.stringify({ error: 'backend_unavailable', retryable: true }) };
  }

  try {
    const res = await client.query(
      'SELECT s.serial_key FROM serial_key_sessions s JOIN serial_keys k ON k.serial_key = s.serial_key ' +
      "WHERE s.session_token = $1 AND s.expires_at > now() AND k.status = 'active'",
      [sessionToken]
    );

    return { statusCode: 200, body: JSON.stringify({ authorized: res.rows.length > 0 }) };
  } catch (err) {
    console.error('portal-status lookup failed:', err.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'lookup_failed', message: err.message }) };
  } finally {
    await client.end();
  }
};
