// netlify/functions/connections-status.js
//
// Answers ONE question for the Client Portal: "which of this person's four
// Deriv apps (slots 1-4) have been authorized so far?" It reads the
// persistent, httpOnly `app_session` cookie set by deriv-token.js, never
// anything the browser claims. It returns only slot numbers and statuses:
// no tokens, no App IDs.
//
// The portal uses this to decide which step of the four-step connection
// wizard is next, so progress survives the redirects to Deriv and back.
//
// Environment variables required:
//   DATABASE_URL - the Neon Postgres connection string

const { Client } = require('pg');

const MAX_SLOT = 8;

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach(function (pair) {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

function emptySlots() {
  const slots = [];
  for (let n = 1; n <= MAX_SLOT; n++) slots.push({ slot: n, status: 'pending', connected_at: null });
  return slots;
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

  // No session yet = nothing connected yet (the wizard starts at App 1).
  if (!sessionToken) {
    return {
      statusCode: 200,
      headers: { 'Cache-Control': 'no-store' },
      body: JSON.stringify({ registered: false, slots: emptySlots(), connected_count: 0, all_connected: false })
    };
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();

  try {
    const sessionRes = await client.query(
      'SELECT app_user_id FROM app_sessions WHERE session_token = $1 AND expires_at > now()',
      [sessionToken]
    );

    if (!sessionRes.rows.length) {
      return {
        statusCode: 200,
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify({ registered: false, slots: emptySlots(), connected_count: 0, all_connected: false })
      };
    }

    const connRes = await client.query(
      'SELECT app_slot, status, connected_at FROM app_connections WHERE app_user_id = $1',
      [sessionRes.rows[0].app_user_id]
    );

    const slots = emptySlots();
    connRes.rows.forEach(function (row) {
      const entry = slots[Number(row.app_slot) - 1];
      if (!entry) return;
      entry.status = row.status;
      entry.connected_at = row.connected_at;
    });

    const connectedCount = slots.filter(function (s) { return s.status === 'connected'; }).length;

    return {
      statusCode: 200,
      headers: { 'Cache-Control': 'no-store' },
      body: JSON.stringify({
        registered: true,
        slots: slots,
        connected_count: connectedCount,
        all_connected: connectedCount === MAX_SLOT
      })
    };
  } catch (err) {
    console.error('connections-status lookup failed:', err.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'lookup_failed', message: err.message }) };
  } finally {
    await client.end();
  }
};
