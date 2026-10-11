# Four-app connection setup (Phase 1 + 2)

What this adds: the Client Portal now connects your four separate Deriv apps
one after another (App 1 -> 2 -> 3 -> 4), all for the SAME Deriv account.
Each app has its own login, its own token and its own database record.
`Ariana.html` (the bot) is unchanged: it still trades through App 1 only.
The four-worker trading pool is the next phase.

## Deploy checklist (in this order)

1. **Run the SQL once** in Neon -> SQL Editor: `db/app_connections_schema.sql`
2. **Add 3 Netlify environment variables** (Site settings -> Environment variables).
   `DERIV_CLIENT_ID` stays as it is (App 1 / Ladysmith).
   - `DERIV_CLIENT_ID_2` = App ID of BotConnection2
   - `DERIV_CLIENT_ID_3` = App ID of BotConnection3
   - `DERIV_CLIENT_ID_4` = App ID of BotConnection4
3. **Check the App IDs in `index.html`** (search `DERIV_APP_IDS`). I read them from
   your Deriv dashboard screenshot, so confirm each one by pressing the copy icon
   next to it on Deriv and comparing (easy to mix up l / I / 0 / O).
   The browser IDs and the Netlify variables must be the same four IDs.
4. Deploy. Existing logins keep working even before step 1 and 2 are done.

## How it behaves

- App N only unlocks after App N-1 is connected (enforced on the server too).
- App 2-4 must be authorised with the same Deriv login as App 1, otherwise
  the server refuses it ("must be connected with the same Deriv account").
- Tokens live in the browser tab (sessionStorage), one per app. If you close the
  tab, the server remembers the apps are connected but the tokens are gone, so
  the portal shows "Session expired - reconnect" for them.
- No tokens are stored in the database or returned by the status endpoint.

## Phase 0 test to run on a DEMO account first

Connect all four, then check, and write down the answers:
1. Does connecting App 2 stop App 1's token working? (Open Ariana, see if it still trades.)
2. Open the OTP/WebSocket for each token. Do all four stay connected at the same time?
3. Rate limits: send proposals from one connection until Deriv limits it. Does a
   second app's connection still have its own full allowance, or do they share one?
   This decides whether four apps really give more trades per minute.
4. What does Deriv's token response say about expiry or refresh?
