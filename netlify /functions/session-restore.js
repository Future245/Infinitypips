// netlify/functions/session-restore.js
//
// "Welcome back" check, run when the user opens Infinity Pips. It answers, from
// the BACKEND, three separate questions:
//   1. Is the licence (serial key) session still valid AND is the key still active?
//   2. Is the website session (app_session) still valid? (renewed if half-used)
//   3. For EACH of the 8 Deriv apps independently: are the saved credentials
//      still usable? Each slot is refreshed if needed (when Deriv issued a
//      refresh token) and then really checked against Deriv. A row existing in
//      the database never counts as "connected" by itself.
//
// It returns NO tokens. A temporary Deriv/network/database problem is reported
// as 'temporary' (retryable) and is never confused with a revoked authorization.
//
// Response (also shaped like the old connections-status so the portal can reuse it):
//   { license_ok, license_reason, session_ok, session_reason,
//     slots:[{slot,status,valid,state,detail,connected_at}], valid_slots:[..],
//     reauth_slots:[..], temp_slots:[..], all_valid, connected_count, all_connected,
//     redirect, registered }
// The bot is never started by this endpoint: Ariana.html waits for Start Bot.

const core = require('../lib/auth-core');

function emptySlots() {
  const s = [];
  for (let n = 1; n <= core.MAX_SLOT; n++) s.push({ slot: n, status: 'pending', valid: false, state: 'unknown', detail: null, connected_at: null });
  return s;
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'GET') return core.respond(405, { error: 'method_not_allowed' });

  let client;
  try {
    client = await core.connectDb();
  } catch (err) {
    if (err instanceof core.ConfigError) {
      console.error(err.message);
      return core.respond(500, { error: 'server_misconfigured', message: err.message });
    }
    console.error('session-restore: database unavailable:', err.message);
    // Not "logged out": the caller must retry, not send the user to Deriv.
    return core.respond(503, { state: 'backend_unavailable', retryable: true });
  }

  try {
    const cookies = core.cookiesOf(event);
    const license = await core.getLicense(client, cookies);
    const session = await core.getAppSession(client, cookies);
    const setCookies = [].concat(license.setCookies || [], session.setCookies || []);

    const base = {
      license_ok: !!license.ok, license_reason: license.ok ? null : license.reason,
      session_ok: !!session.ok, session_reason: session.ok ? null : session.reason,
      registered: !!session.ok,
      slots: emptySlots(), valid_slots: [], reauth_slots: [], temp_slots: [],
      all_valid: false, connected_count: 0, all_connected: false, redirect: null
    };

    // Not licensed / not signed in: report it, do not touch Deriv.
    if (!license.ok || !session.ok) return core.respond(200, base, setCookies);

    const appUserId = session.appUserId;
    // Netlify stops functions after ~10 s, so each app gets a hard deadline. A check that
    // runs out of time is 'temporary' (retry), never "revoked".
    const deadline = function (p) {
      return Promise.race([p, new Promise(function (resolve) {
        setTimeout(function () { resolve({ state: 'temporary', detail: 'Check timed out; will retry.' }); }, 7500);
      })]);
    };
    const results = await Promise.all(emptySlots().map(function (s) {
      return deadline(core.checkSlot(appUserId, s.slot)).catch(function (err) {
        if (err instanceof core.DbUnavailable) return { state: 'temporary', detail: 'Database temporarily unavailable.' };
        console.error('slot ' + s.slot + ' check failed:', err.message);
        return { state: 'temporary', detail: 'Check could not be completed.' };
      });
    }));

    const connectedAt = {};
    try {
      const cr = await client.query('SELECT app_slot, connected_at FROM app_connections WHERE app_user_id = $1', [appUserId]);
      cr.rows.forEach(function (r) { connectedAt[Number(r.app_slot)] = r.connected_at; });
    } catch (_) {}

    const out = base;
    for (let i = 0; i < results.length; i++) {
      const slot = i + 1, r = results[i];
      const entry = out.slots[i];
      entry.state = r.state;
      entry.detail = r.state === 'ok' ? null : (r.detail || null);
      entry.connected_at = connectedAt[slot] || null;
      if (r.state === 'ok') { entry.status = 'connected'; entry.valid = true; out.valid_slots.push(slot); }
      else if (r.state === 'reauth_required') { entry.status = 'expired'; out.reauth_slots.push(slot); }
      else if (r.state === 'temporary') { entry.status = 'pending'; out.temp_slots.push(slot); }
      else { entry.status = 'pending'; } // not_connected
      await core.recordConnectionState(client, appUserId, slot, r.state, r.detail);
    }
    out.connected_count = out.valid_slots.length;
    out.all_valid = out.valid_slots.length === core.MAX_SLOT;
    out.all_connected = out.all_valid;
    out.redirect = out.all_valid ? '/Ariana.html' : null;
    return core.respond(200, out, setCookies);
  } catch (err) {
    if (err instanceof core.DbUnavailable) return core.respond(503, { state: 'backend_unavailable', retryable: true });
    console.error('session-restore failed:', err.message);
    return core.respond(500, { error: 'restore_failed' });
  } finally {
    try { await client.end(); } catch (_) {}
  }
};
