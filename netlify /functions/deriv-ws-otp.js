// netlify/functions/deriv-ws-otp.js
//
// The browser needs an authenticated WebSocket to trade, but it must never hold
// the Deriv access token. So the BROWSER asks THIS function, the function uses
// the stored (encrypted) token for that slot, calls Deriv's OTP endpoint, and
// returns only the one-time wss:// URL. Deriv's own docs describe this URL as
// the way to open the authenticated socket.
//
// POST { slot: 1-8, account_id?: string }
//   account_id omitted (App 1 on first connect): the same account rule Ariana.html
//   always used - prefer the demo account, else the first one.
//   account_id given (reconnects and Apps 2-8): used as-is, so every app trades
//   the same account.
//
// Error codes the page reacts to:
//   not_authenticated | session_expired | license_inactive  -> go to the sign-in flow
//   reauth_required   (+ slot)  -> ONLY this app needs authorizing again
//   deriv_unreachable | backend_unavailable (503) -> temporary: just retry, do not log in again
//   account_mismatch (409), slot_not_connected (409)

const core = require('../lib/auth-core');

function pickAccount(accounts) {
  const demo = accounts.find(function (a) { return a.account_type === 'demo' || a.is_virtual === true || a.type === 'demo'; });
  const a = demo || accounts[0];
  return a && (a.id || a.account_id || a.loginid);
}

async function requestOtp(accessToken, accountId) {
  return core.httpJson(core.derivApiBase() + '/trading/v1/options/accounts/' + encodeURIComponent(accountId) + '/otp', {
    method: 'POST', headers: { Authorization: 'Bearer ' + accessToken }
  });
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') return core.respond(405, { error: 'method_not_allowed' });

  let body;
  try { body = JSON.parse(event.body || '{}'); } catch (_) { return core.respond(400, { error: 'invalid_json' }); }
  const slot = Number(body.slot);
  if (!Number.isInteger(slot) || slot < 1 || slot > core.MAX_SLOT) return core.respond(400, { error: 'invalid_slot' });
  const wantedAccount = body.account_id ? String(body.account_id) : '';

  let client;
  try { client = await core.connectDb(); }
  catch (err) {
    if (err instanceof core.ConfigError) return core.respond(500, { error: 'server_misconfigured', message: err.message });
    return core.respond(503, { error: 'backend_unavailable', retryable: true, slot: slot });
  }

  let appUserId, setCookies;
  try {
    const cookies = core.cookiesOf(event);
    const license = await core.getLicense(client, cookies);
    if (!license.ok) return core.respond(401, { error: license.reason === 'license_inactive' ? 'license_inactive' : 'not_authenticated', reason: license.reason, slot: slot });
    const session = await core.getAppSession(client, cookies);
    if (!session.ok) return core.respond(401, { error: session.reason === 'session_expired' ? 'session_expired' : 'not_authenticated', reason: session.reason, slot: slot });
    appUserId = session.appUserId;
    setCookies = [].concat(license.setCookies || [], session.setCookies || []);
  } catch (err) {
    if (err instanceof core.DbUnavailable) return core.respond(503, { error: 'backend_unavailable', retryable: true, slot: slot });
    console.error('deriv-ws-otp session check failed:', err.message);
    return core.respond(500, { error: 'session_check_failed' });
  } finally {
    try { await client.end(); } catch (_) {}
  }

  try {
    let t = await core.getAccessToken(appUserId, slot);
    if (t.state === 'not_connected') return core.respond(409, { error: 'slot_not_connected', slot: slot }, setCookies);
    if (t.state === 'reauth_required') return core.respond(401, { error: 'reauth_required', slot: slot, message: t.detail }, setCookies);
    if (t.state === 'temporary') return core.respond(503, { error: 'deriv_unreachable', retryable: true, slot: slot, message: t.detail }, setCookies);

    let accountId = wantedAccount;
    if (!accountId) {
      const v = await core.verifyAccessToken(t.accessToken);
      if (v.result === 'temporary') return core.respond(503, { error: 'deriv_unreachable', retryable: true, slot: slot }, setCookies);
      if (v.result === 'invalid') {
        t = await core.getAccessToken(appUserId, slot, { force: true });
        if (t.state === 'reauth_required') return core.respond(401, { error: 'reauth_required', slot: slot, message: t.detail }, setCookies);
        if (t.state !== 'ok') return core.respond(503, { error: 'deriv_unreachable', retryable: true, slot: slot }, setCookies);
        const v2 = await core.verifyAccessToken(t.accessToken);
        if (v2.result !== 'ok') { await core.markReauth(appUserId, slot, v2.detail); return core.respond(401, { error: 'reauth_required', slot: slot, message: v2.detail }, setCookies); }
        accountId = pickAccount(v2.accounts);
      } else {
        accountId = pickAccount(v.accounts);
      }
      if (!accountId) return core.respond(409, { error: 'account_mismatch', slot: slot }, setCookies);
    }

    let res;
    try { res = await requestOtp(t.accessToken, accountId); }
    catch (err) { return core.respond(503, { error: 'deriv_unreachable', retryable: true, slot: slot }, setCookies); }

    if (res.status === 401) {
      // Token rejected although our clock said it was fine -> one forced refresh, one retry.
      const t2 = await core.getAccessToken(appUserId, slot, { force: true });
      if (t2.state === 'reauth_required') return core.respond(401, { error: 'reauth_required', slot: slot, message: t2.detail }, setCookies);
      if (t2.state !== 'ok') return core.respond(503, { error: 'deriv_unreachable', retryable: true, slot: slot }, setCookies);
      try { res = await requestOtp(t2.accessToken, accountId); }
      catch (err) { return core.respond(503, { error: 'deriv_unreachable', retryable: true, slot: slot }, setCookies); }
      if (res.status === 401) { await core.markReauth(appUserId, slot, 'Deriv rejected the token when opening the WebSocket.'); return core.respond(401, { error: 'reauth_required', slot: slot }, setCookies); }
    }
    if (res.status === 403 || res.status === 404 || res.status === 400) return core.respond(409, { error: 'account_mismatch', slot: slot }, setCookies);
    const url = res.ok && res.data && res.data.data && res.data.data.url;
    if (!url) return core.respond(503, { error: 'deriv_unreachable', retryable: true, slot: slot }, setCookies);

    return core.respond(200, { url: url, account_id: accountId, slot: slot }, setCookies);
  } catch (err) {
    if (err instanceof core.DbUnavailable) return core.respond(503, { error: 'backend_unavailable', retryable: true, slot: slot }, setCookies);
    console.error('deriv-ws-otp failed:', err.message);
    return core.respond(500, { error: 'otp_failed', slot: slot });
  }
};
