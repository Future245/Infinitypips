// netlify/lib/auth-core.js
//
// Shared helpers for persistent Deriv authorization. This file is NOT a
// Netlify function (it lives outside netlify/functions); the functions
// require() it and Netlify bundles it with them.
//
// Two separate things are handled here and they must never be confused:
//   1. WEBSITE sessions   - app_session (Deriv-linked user) and portal_session
//                           (serial-key licence), both httpOnly cookies backed
//                           by database rows.
//   2. DERIV authorization - one OAuth access token (+ refresh token, if Deriv
//                           issued one) PER APP SLOT (1-8), encrypted at rest in
//                           deriv_credentials, never sent to the browser.

'use strict';

const crypto = require('crypto');
const { Client } = require('pg');

const MAX_SLOT = 8;
const DB_CONNECT_TIMEOUT_MS = 6000;
const HTTP_TIMEOUT_MS = 8000;
const ACCESS_SKEW_MS = 120 * 1000; // treat a token as expired 2 minutes early

// Test-only overrides (leave unset in production).
function derivTokenUrl() { return process.env.DERIV_TOKEN_URL || 'https://auth.deriv.com/oauth2/token'; }
function derivApiBase() { return process.env.DERIV_API_BASE || 'https://api.derivws.com'; }

class ConfigError extends Error {}
class DbUnavailable extends Error {}

// ---------- configuration (read at call time so it can be changed in tests) ----------
function sessionTtlSeconds() {
  const days = Number(process.env.SESSION_TTL_DAYS);
  return Math.round((days > 0 ? days : 30) * 86400);
}
function licenseTtlSeconds() {
  const days = Number(process.env.SERIAL_SESSION_TTL_DAYS);
  return Math.round((days > 0 ? days : 30) * 86400);
}

function clientIdForSlot(slot) {
  return slot === 1 ? process.env.DERIV_CLIENT_ID : process.env['DERIV_CLIENT_ID_' + slot];
}

// ---------- database ----------
async function connectDb() {
  if (!process.env.DATABASE_URL) throw new ConfigError('DATABASE_URL env var is not set');
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'off' ? false : { rejectUnauthorized: false },
    connectionTimeoutMillis: DB_CONNECT_TIMEOUT_MS,
    statement_timeout: 10000,
    query_timeout: 12000
  });
  client.on('error', function () {}); // an idle-connection error must not crash the function
  try {
    await client.connect();
  } catch (err) {
    try { await client.end(); } catch (_) {}
    throw new DbUnavailable(err.message);
  }
  return client;
}

// ---------- cookies ----------
function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach(function (pair) {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    try { out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim()); } catch (_) {}
  });
  return out;
}
function cookiesOf(event) {
  return parseCookies(event.headers && (event.headers.cookie || event.headers.Cookie));
}
function setCookie(name, value, maxAgeSeconds) {
  return name + '=' + value + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + maxAgeSeconds;
}
function clearCookie(name) { return setCookie(name, '', 0); }

function respond(statusCode, bodyObj, setCookies) {
  const res = {
    statusCode: statusCode,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    body: JSON.stringify(bodyObj)
  };
  if (setCookies && setCookies.length) res.multiValueHeaders = { 'Set-Cookie': setCookies };
  return res;
}

// ---------- encryption at rest (AES-256-GCM) ----------
// TOKEN_ENCRYPTION_KEY = 32 random bytes, base64.  Generate one with:
//   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
// The AAD binds each ciphertext to its user + slot + purpose, so a stolen or
// copied value cannot be replayed into a different row.
function encryptionKey() {
  const raw = process.env.TOKEN_ENCRYPTION_KEY || '';
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) throw new ConfigError('TOKEN_ENCRYPTION_KEY must be 32 random bytes, base64-encoded');
  return key;
}
function assertEncryptionConfigured() { encryptionKey(); }

function encrypt(plain, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64'), cipher.getAuthTag().toString('base64'), ct.toString('base64')].join(':');
}
function decrypt(blob, aad) {
  const parts = String(blob).split(':');
  if (parts.length !== 4 || parts[0] !== 'v1') throw new Error('unsupported ciphertext format');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(parts[1], 'base64'));
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(Buffer.from(parts[2], 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64')), decipher.final()]).toString('utf8');
}
const aadAccess = function (userId, slot) { return String(userId) + ':' + slot + ':access'; };
const aadRefresh = function (userId, slot) { return String(userId) + ':' + slot + ':refresh'; };

// ---------- HTTP to Deriv (always with a timeout) ----------
async function httpJson(url, options, timeoutMs) {
  const ac = new AbortController();
  const timer = setTimeout(function () { ac.abort(); }, timeoutMs || HTTP_TIMEOUT_MS);
  try {
    const res = await fetch(url, Object.assign({}, options, { signal: ac.signal }));
    let data = null;
    try { data = await res.json(); } catch (_) {}
    return { status: res.status, ok: res.ok, data: data };
  } catch (err) {
    const e = new Error(err && err.name === 'AbortError' ? 'timeout' : (err && err.message) || 'network error');
    e.network = true;
    throw e;
  } finally {
    clearTimeout(timer);
  }
}
function fetchWithTimeout(url, options, timeoutMs) {
  const ac = new AbortController();
  const timer = setTimeout(function () { ac.abort(); }, timeoutMs || HTTP_TIMEOUT_MS);
  return fetch(url, Object.assign({}, options, { signal: ac.signal })).finally(function () { clearTimeout(timer); });
}

// ---------- website sessions ----------
// Persistent login (app_session): valid until expires_at, renewed ("sliding")
// whenever less than half of its lifetime is left.
async function getAppSession(client, cookies) {
  const token = cookies.app_session;
  if (!token) return { ok: false, reason: 'no_session' };
  const r = await client.query(
    'SELECT app_user_id, deriv_loginid, expires_at FROM app_sessions WHERE session_token = $1', [token]);
  if (!r.rows.length) return { ok: false, reason: 'session_invalid' };
  const expiresAt = new Date(r.rows[0].expires_at).getTime();
  if (expiresAt <= Date.now()) return { ok: false, reason: 'session_expired' };
  const out = { ok: true, appUserId: r.rows[0].app_user_id, derivLoginid: r.rows[0].deriv_loginid, setCookies: [] };
  const ttl = sessionTtlSeconds();
  if (expiresAt - Date.now() < (ttl * 1000) / 2) {
    await client.query('UPDATE app_sessions SET expires_at = now() + ($2 || \' seconds\')::interval WHERE session_token = $1', [token, String(ttl)]);
    out.setCookies.push(setCookie('app_session', token, ttl));
    out.renewed = true;
  }
  return out;
}

// Licence (portal_session): the serial key must STILL be active. (The older
// portal-status check only looked at the session row, so disabling a key did
// not end sessions that already existed.)
async function getLicense(client, cookies) {
  const token = cookies.portal_session;
  if (!token) return { ok: false, reason: 'no_license_session' };
  const r = await client.query(
    'SELECT s.expires_at, k.status FROM serial_key_sessions s ' +
    'JOIN serial_keys k ON k.serial_key = s.serial_key WHERE s.session_token = $1', [token]);
  if (!r.rows.length) return { ok: false, reason: 'license_session_invalid' };
  const expiresAt = new Date(r.rows[0].expires_at).getTime();
  if (expiresAt <= Date.now()) return { ok: false, reason: 'license_session_expired' };
  if (r.rows[0].status !== 'active') return { ok: false, reason: 'license_inactive' };
  const out = { ok: true, setCookies: [] };
  const ttl = licenseTtlSeconds();
  if (expiresAt - Date.now() < (ttl * 1000) / 2) {
    await client.query('UPDATE serial_key_sessions SET expires_at = now() + ($2 || \' seconds\')::interval WHERE session_token = $1', [token, String(ttl)]);
    out.setCookies.push(setCookie('portal_session', token, ttl));
  }
  return out;
}

// ---------- stored Deriv credentials ----------
// Called by deriv-token.js inside its transaction after a successful code exchange.
async function saveCredentials(client, p) {
  const accessEnc = encrypt(p.accessToken, aadAccess(p.appUserId, p.slot));
  const refreshEnc = p.refreshToken ? encrypt(p.refreshToken, aadRefresh(p.appUserId, p.slot)) : null;
  const expiresIn = Number(p.expiresIn) > 0 ? Number(p.expiresIn) : 3600;
  await client.query(
    'INSERT INTO deriv_credentials (app_user_id, app_slot, client_id, deriv_loginid, access_token_enc, access_expires_at, ' +
    '  refresh_token_enc, scope, status, last_error, last_verified_at, last_refreshed_at, updated_at) ' +
    "VALUES ($1, $2, $3, $4, $5, now() + ($6 || ' seconds')::interval, $7, $8, 'valid', NULL, now(), now(), now()) " +
    'ON CONFLICT (app_user_id, app_slot) DO UPDATE SET client_id = EXCLUDED.client_id, deriv_loginid = EXCLUDED.deriv_loginid, ' +
    '  access_token_enc = EXCLUDED.access_token_enc, access_expires_at = EXCLUDED.access_expires_at, ' +
    '  refresh_token_enc = EXCLUDED.refresh_token_enc, scope = EXCLUDED.scope, status = \'valid\', last_error = NULL, ' +
    '  last_verified_at = now(), last_refreshed_at = now(), updated_at = now()',
    [p.appUserId, p.slot, p.clientId, p.loginid, accessEnc, String(expiresIn), refreshEnc, p.scope || null]
  );
}

// Returns { state, accessToken?, detail? } for ONE slot. Runs in its own
// transaction with the row locked, so two requests can never both spend the
// same (single-use) refresh token.
//   state 'ok'              - a usable access token is returned
//   state 'reauth_required' - Deriv rejected the credentials, or there is nothing to refresh with
//   state 'temporary'       - Deriv / network trouble; credentials are NOT judged invalid
//   state 'not_connected'   - no credentials stored for this slot
async function getAccessToken(appUserId, slot, opts) {
  const force = !!(opts && opts.force);
  const client = await connectDb();
  try {
    await client.query('BEGIN');
    const r = await client.query(
      'SELECT * FROM deriv_credentials WHERE app_user_id = $1 AND app_slot = $2 FOR UPDATE', [appUserId, slot]);
    if (!r.rows.length) { await client.query('ROLLBACK'); return { state: 'not_connected' }; }
    const row = r.rows[0];

    if (row.status === 'reauth_required' && !force) {
      await client.query('ROLLBACK');
      return { state: 'reauth_required', detail: row.last_error || 'Authorization is no longer valid.' };
    }

    const accessValid = new Date(row.access_expires_at).getTime() - Date.now() > ACCESS_SKEW_MS;
    if (accessValid && !force) {
      const token = decrypt(row.access_token_enc, aadAccess(appUserId, slot));
      await client.query('ROLLBACK');
      return { state: 'ok', accessToken: token, refreshed: false };
    }

    async function markDead(msg) {
      await client.query("UPDATE deriv_credentials SET status = 'reauth_required', last_error = $3, updated_at = now() WHERE app_user_id = $1 AND app_slot = $2", [appUserId, slot, msg]);
      await client.query('COMMIT');
      return { state: 'reauth_required', detail: msg };
    }

    if (!row.refresh_token_enc) {
      return await markDead('The access token expired and Deriv did not issue a refresh token, so this app must be authorized again.');
    }

    const refreshToken = decrypt(row.refresh_token_enc, aadRefresh(appUserId, slot));
    let res;
    try {
      res = await httpJson(derivTokenUrl(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', client_id: row.client_id, refresh_token: refreshToken }).toString()
      });
    } catch (netErr) {
      await client.query('ROLLBACK');
      return { state: 'temporary', detail: 'Could not reach Deriv to refresh: ' + netErr.message };
    }

    if (res.ok && res.data && res.data.access_token) {
      const newAccess = encrypt(res.data.access_token, aadAccess(appUserId, slot));
      const newRefresh = res.data.refresh_token ? encrypt(res.data.refresh_token, aadRefresh(appUserId, slot)) : row.refresh_token_enc;
      const expiresIn = Number(res.data.expires_in) > 0 ? Number(res.data.expires_in) : 3600;
      await client.query(
        "UPDATE deriv_credentials SET access_token_enc = $3, access_expires_at = now() + ($4 || ' seconds')::interval, " +
        "refresh_token_enc = $5, status = 'valid', last_error = NULL, last_refreshed_at = now(), updated_at = now() " +
        'WHERE app_user_id = $1 AND app_slot = $2',
        [appUserId, slot, newAccess, String(expiresIn), newRefresh]);
      await client.query('COMMIT');
      return { state: 'ok', accessToken: res.data.access_token, refreshed: true };
    }

    // Definitive "no" from Deriv (bad / revoked / used refresh token): authorization is gone.
    if (res.status === 400 || res.status === 401 || res.status === 403) {
      const why = (res.data && (res.data.error_description || res.data.error)) || ('HTTP ' + res.status);
      return await markDead('Deriv refused to refresh this authorization (' + why + ').');
    }
    // Anything else (5xx, 429, malformed reply): do not judge the credentials invalid.
    await client.query('ROLLBACK');
    return { state: 'temporary', detail: 'Deriv answered the refresh with HTTP ' + res.status + '.' };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    throw err;
  } finally {
    try { await client.end(); } catch (_) {}
  }
}

// Ask Deriv itself whether this token works. 'ok' | 'invalid' | 'temporary'
async function verifyAccessToken(accessToken) {
  let res;
  try {
    res = await httpJson(derivApiBase() + '/trading/v1/options/accounts', { headers: { Authorization: 'Bearer ' + accessToken } });
  } catch (err) {
    return { result: 'temporary', detail: err.message };
  }
  if (res.ok) {
    const accounts = (res.data && res.data.data) || [];
    if (!Array.isArray(accounts) || !accounts.length) return { result: 'invalid', detail: 'No trading accounts for this authorization.' };
    return { result: 'ok', accounts: accounts };
  }
  if (res.status === 401 || res.status === 403) return { result: 'invalid', detail: 'Deriv rejected the token (HTTP ' + res.status + ').' };
  return { result: 'temporary', detail: 'Deriv answered HTTP ' + res.status + '.' };
}

// Full check of ONE slot: fresh token (refreshing if needed) + a live call to Deriv.
// Never reports 'valid' just because credentials exist.
async function checkSlot(appUserId, slot) {
  let t = await getAccessToken(appUserId, slot);
  if (t.state !== 'ok') return t;
  let v = await verifyAccessToken(t.accessToken);
  if (v.result === 'invalid') {
    // Our clock said the token was fine but Deriv disagrees (e.g. revoked). One forced refresh, then re-verify.
    t = await getAccessToken(appUserId, slot, { force: true });
    if (t.state !== 'ok') return t;
    v = await verifyAccessToken(t.accessToken);
  }
  if (v.result === 'ok') return { state: 'ok', accounts: v.accounts, accessToken: t.accessToken, refreshed: !!t.refreshed };
  if (v.result === 'invalid') {
    await markReauth(appUserId, slot, v.detail);
    return { state: 'reauth_required', detail: v.detail };
  }
  return { state: 'temporary', detail: v.detail };
}

async function markReauth(appUserId, slot, msg) {
  const client = await connectDb();
  try {
    await client.query("UPDATE deriv_credentials SET status = 'reauth_required', last_error = $3, updated_at = now() WHERE app_user_id = $1 AND app_slot = $2", [appUserId, slot, msg]);
  } finally { try { await client.end(); } catch (_) {} }
}

// Mirror a verified outcome into app_connections (the table the portal already reads).
async function recordConnectionState(client, appUserId, slot, state, detail) {
  try {
    if (state === 'ok') {
      await client.query("UPDATE app_connections SET status = 'connected', last_checked_at = now(), last_error = NULL WHERE app_user_id = $1 AND app_slot = $2", [appUserId, slot]);
      await client.query('UPDATE deriv_credentials SET last_verified_at = now(), last_error = NULL WHERE app_user_id = $1 AND app_slot = $2', [appUserId, slot]);
    } else if (state === 'reauth_required') {
      await client.query("UPDATE app_connections SET status = 'expired', last_checked_at = now(), last_error = $3 WHERE app_user_id = $1 AND app_slot = $2", [appUserId, slot, detail || null]);
    }
    // 'temporary' deliberately changes nothing: a Deriv/network blip is not a revoked authorization.
  } catch (err) {
    console.error('recordConnectionState failed:', err.message);
  }
}

module.exports = {
  MAX_SLOT, ConfigError, DbUnavailable,
  connectDb, parseCookies, cookiesOf, setCookie, clearCookie, respond,
  assertEncryptionConfigured, encrypt, decrypt, aadAccess, aadRefresh,
  httpJson, fetchWithTimeout, derivTokenUrl, derivApiBase, clientIdForSlot,
  sessionTtlSeconds, licenseTtlSeconds,
  getAppSession, getLicense, saveCredentials, getAccessToken, verifyAccessToken,
  checkSlot, markReauth, recordConnectionState
};
