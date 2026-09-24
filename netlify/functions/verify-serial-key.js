// netlify/functions/verify-serial-key.js
//
// Server-side gateway for the Serial Key page. The browser sends the key
// the person typed; this function is the ONLY place that decides whether
// it's real — it looks the key up in Postgres (Neon) itself and never
// trusts anything the client claims about validity.
//
// On success it issues a separate, httpOnly `portal_session` cookie that
// proves "this browser has presented a valid Infinity Pips serial key."
// This is kept deliberately separate from the `app_session` cookie that
// deriv-token.js issues (which proves "this browser is linked to a
// specific Deriv account"). The two are different facts about the
// visitor — a serial key proves license ownership, Deriv OAuth later
// proves which Deriv account they're connecting — and are checked
// independently, per the access-control design.
//
// Environment variables required:
//   DATABASE_URL - the Neon Postgres connection string (same one already
//                   used by deriv-token.js / session-status.js)
//
// Expects the tables created by db/serial_keys_schema.sql:
//   serial_keys(serial_key, status, ...)
//   serial_key_sessions(session_token, serial_key, expires_at, ...)
//
// This function does NOT create, generate, or modify serial keys. Keys
// are added to serial_keys manually (e.g. via the Neon SQL console), by
// design, per the current (temporary) key-management approach.

const { Client } = require('pg');
const crypto = require('crypto');

const SESSION_COOKIE = 'portal_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const KEY_FORMAT = /^\d{4}-\d{4}-\d{4}$/; // e.g. 4827-1936-7504

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'method_not_allowed' }) };
  }

  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL env var is not set');
    return { statusCode: 500, body: JSON.stringify({ error: 'server_misconfigured' }) };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (err) {
    return { statusCode: 400, body: JSON.stringify({ error: 'invalid_json', authorized: false }) };
  }

  const key = String(payload.key || '').trim();

  // Reject malformed keys before ever touching the database. This is a
  // format check only (shape, not existence) — it is NOT the security
  // boundary. The database lookup below is what actually authorizes.
  if (!KEY_FORMAT.test(key)) {
    return { statusCode: 400, body: JSON.stringify({ error: 'invalid_format', authorized: false }) };
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();

  try {
    // A key is valid only if it exists AND is active. Nothing here ever
    // creates a row in serial_keys — only looks one up.
    const res = await client.query(
      "SELECT serial_key FROM serial_keys WHERE serial_key = $1 AND status = 'active'",
      [key]
    );

    if (!res.rows.length) {
      return { statusCode: 401, body: JSON.stringify({ error: 'invalid_key', authorized: false }) };
    }

    const sessionToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);

    await client.query(
      'INSERT INTO serial_key_sessions (session_token, serial_key, expires_at) VALUES ($1, $2, $3)',
      [sessionToken, key, expiresAt]
    );

    return {
      statusCode: 200,
      headers: {
        'Set-Cookie': SESSION_COOKIE + '=' + sessionToken + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + SESSION_TTL_SECONDS
      },
      body: JSON.stringify({ authorized: true })
    };
  } catch (err) {
    console.error('Serial key verification failed:', err.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'lookup_failed', message: err.message }) };
  } finally {
    await client.end();
  }
};
