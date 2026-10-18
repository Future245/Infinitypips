# Persistent Deriv authorization (8 apps) - setup and limits

## What Deriv actually allows (checked against developers.deriv.com)

- OAuth access tokens last **3600 s (1 hour)**. The only way to stay connected for days is a
  **refresh token**.
- Deriv's OAuth page documents the token response as just `access_token`, `expires_in`, `token_type`.
  Other pages say the response has an "optional refresh token" and tell you to "implement token
  refresh logic", but **no page shows how to obtain one, what scope it needs, how long it lives, or the
  refresh request itself.** The refresh request in this code is the standard OAuth2 one
  (`grant_type=refresh_token`, `client_id`, `refresh_token`) - **not confirmed by Deriv's docs.**
- So this build is written to work *if* Deriv issues refresh tokens to your 8 apps, and to say so
  plainly if it does not (see "Find out", below).
- Deriv's docs say the WebSocket is opened with a one-time URL from the OTP endpoint. That URL (not the
  access token) is all the browser receives.
- If refresh tokens are NOT issued, OAuth cannot give multi-day persistence. The alternative Deriv
  documents is PAT apps (user pastes a token; revocable from the dashboard; expiry not documented).
  That would be a different onboarding flow and is not built here.

## What changed

| File | Change |
|---|---|
| `db/persistent_auth_schema.sql` | NEW table `deriv_credentials` (encrypted tokens, one row per user + slot 1-8) |
| `netlify/lib/auth-core.js` | NEW shared code: encryption (AES-256-GCM), sessions, refresh with row lock, per-slot verification |
| `netlify/functions/session-restore.js` | NEW: on return, checks licence + session + all 8 apps independently against Deriv |
| `netlify/functions/deriv-ws-otp.js` | NEW: gives the browser a one-time WebSocket URL; the token never leaves the server |
| `netlify/functions/logout.js` | NEW: log out, optionally delete saved Deriv credentials |
| `netlify/functions/deriv-token.js` | Stores tokens encrypted; **no longer returns the access token**; timeouts; logs whether a refresh token was issued |
| `netlify/functions/portal-status.js` | Now also requires the serial key to be **still active** (before, disabling a key did not end existing sessions) |
| `portal-status`, `session-status`, `connections-status`, `verify-serial-key` | Database timeouts: a DB blip returns a retryable 503 instead of hanging |
| `index.html` | Restores the session on load; goes straight to `/Ariana.html` only if all 8 apps verify as valid, otherwise the normal start screen (nothing goes to Deriv until the user taps Access Robot); per-app recovery through the existing setup loop; temporary Deriv outages never start a login; Log out in Settings |
| `callback.html` | No longer stores tokens |
| `Ariana.html` | Connects through `deriv-ws-otp`; per-app error handling; bot forced OFF on load; connection badge shows problems. Your own target-net-profit stake engine is untouched |

Trading logic, strategy and the 8-worker pool are unchanged.

## Deploy (in this order)

1. **Generate a key** (keep it secret, back it up - losing it means everyone re-authorizes):
   `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
2. **Netlify -> Environment variables**: add `TOKEN_ENCRYPTION_KEY` = that value.
   Optional: `SESSION_TTL_DAYS` (default 30), `SERIAL_SESSION_TTL_DAYS` (default 30).
3. **Neon SQL Editor**: run `db/persistent_auth_schema.sql` (after the existing schema files; also run
   `db/app_connections_8_slots.sql` if you have not).
4. Upload the files above to GitHub and deploy.
5. Everyone must authorize their apps once more (nothing was stored server-side before).

Until steps 1-3 are done, authorizing returns `server_misconfigured` rather than storing or leaking anything.

## Find out whether Deriv issues refresh tokens (do this first, on a demo account)

1. Authorize App 1. In the browser dev tools, the `deriv-token` response shows `"refresh_available": true|false`.
2. Netlify -> Functions -> `deriv-token` logs show `Deriv token response fields: ...` (names only, never values).
3. **false?** Deriv is not issuing one for `trade account_manage`. A refresh-token flow often needs an extra
   scope; in `index.html` change `DERIV_SCOPES` to `'trade account_manage offline_access'` for one app on demo.
   (`offline_access` is the usual OAuth/Ory convention - **unverified for Deriv**, and Deriv may reject it.)
   If it is still false, tokens die after one hour and the app is flagged "needs reauthorization".
4. **true?** Wait over an hour, reopen the site: apps should show valid with no Deriv login. The refresh
   request format is then proven.

## How it behaves

- Reopen after any time: backend checks licence key (still active?), website session, then each of the 8
  apps separately (refresh if needed, then a real call to Deriv). All 8 valid -> `/Ariana.html`. Never
  starts the bot.
- One app invalid -> only that app is marked and re-authorized, on the user's tap.
- Deriv / network / database trouble -> "temporary": retried, never treated as revoked or logged out.
- Website session: 30 days, sliding renewal, httpOnly + Secure + SameSite cookies, server-side rows.
- The bot's WebSocket URLs are fetched per connection; reconnects get a fresh one.

## What is proven and what is not

Proven by `tests/` (real Postgres + real function code + real pages in jsdom, with a MOCK Deriv):
26 backend + 12 front-end tests, covering browser-closed return, multi-day expiry, refresh rotation and
concurrency, one revoked app, outages, slow Deriv, DB down, expired session, disabled licence, logout,
no secrets in any response, encryption at rest, bot stays off until the switch.

**Not proven**: anything about the real Deriv (refresh token availability, its refresh request format,
token lifetimes, OTP URL lifetime). The database schema for `app_users`, `app_sessions` and
`deriv_accounts` is not in the repo, so the tests use a schema rebuilt from your queries. Run the "Find
out" steps and a full real-account check before relying on this.

Run tests: `npm install --no-save embedded-postgres jsdom && node tests/backend.test.mjs && node tests/frontend.test.mjs`
