// netlify/functions/logout.js
//
// Explicit logout / revoke.
// POST {}                      -> ends THIS browser's website sessions (app_session and
//                                 portal_session) and clears the cookies. Saved Deriv
//                                 authorizations stay, so signing in again is quick.
// POST { revoke_deriv: true }  -> additionally DELETES this user's stored Deriv
//                                 credentials and marks all 8 apps as not connected, so
//                                 every app must be authorized again.
// Note: this removes OUR copy of the credentials. Deriv's docs do not describe a
// revocation endpoint for these OAuth tokens, so to also invalidate them on Deriv's
// side the user should remove the apps in their Deriv account's authorized-apps settings.

const core = require('../lib/auth-core');

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') return core.respond(405, { error: 'method_not_allowed' });
  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch (_) {}

  const clear = [core.clearCookie('app_session'), core.clearCookie('portal_session')];
  let client;
  try { client = await core.connectDb(); }
  catch (err) {
    // Cookies are cleared either way, but be honest that the server-side rows could not be removed.
    return core.respond(503, { error: 'backend_unavailable', cookies_cleared: true, server_session_revoked: false }, clear);
  }
  try {
    const cookies = core.cookiesOf(event);
    let revokedDeriv = false;
    if (cookies.app_session) {
      const s = await client.query('SELECT app_user_id FROM app_sessions WHERE session_token = $1', [cookies.app_session]);
      if (body.revoke_deriv && s.rows.length) {
        await client.query('DELETE FROM deriv_credentials WHERE app_user_id = $1', [s.rows[0].app_user_id]);
        try { await client.query("UPDATE app_connections SET status = 'pending', last_error = NULL WHERE app_user_id = $1", [s.rows[0].app_user_id]); } catch (_) {}
        revokedDeriv = true;
      }
      await client.query('DELETE FROM app_sessions WHERE session_token = $1', [cookies.app_session]);
    }
    if (cookies.portal_session) {
      await client.query('DELETE FROM serial_key_sessions WHERE session_token = $1', [cookies.portal_session]);
    }
    return core.respond(200, { logged_out: true, deriv_credentials_deleted: revokedDeriv }, clear);
  } catch (err) {
    console.error('logout failed:', err.message);
    return core.respond(500, { error: 'logout_failed', cookies_cleared: true, server_session_revoked: false }, clear);
  } finally {
    try { await client.end(); } catch (_) {}
  }
};
