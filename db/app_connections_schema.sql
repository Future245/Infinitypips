-- db/app_connections_schema.sql
--
-- Run this ONCE against the same Neon/Postgres database already used by
-- deriv-token.js / session-status.js (the one DATABASE_URL points to).
-- It only ADDS a table; it does not touch app_users, app_sessions,
-- deriv_accounts, serial_keys or serial_key_sessions.
--
-- How to run it: open your Neon project -> SQL Editor -> paste this file
-- -> Run. (Or `psql "$DATABASE_URL" -f db/app_connections_schema.sql`.)
--
-- One row per (user, app slot). Slots 1-4 are the four separate Deriv
-- apps. Each row records the state of THAT app's authorization only, so a
-- problem with slot 3 never changes what is stored for slots 1, 2 or 4.
--
-- No access tokens are stored here. Tokens stay in the browser exactly as
-- they do today; this table only records that a slot was authorized, by
-- which App ID, for which Deriv login, and when.

-- app_user_id must have the SAME type as app_users.id (serial int, uuid,
-- ...), which this file doesn't know. So the table is created through a
-- small block that copies the column type from app_users.
DO $$
DECLARE
  id_type text;
BEGIN
  SELECT format_type(a.atttypid, a.atttypmod)
    INTO id_type
    FROM pg_attribute a
   WHERE a.attrelid = 'app_users'::regclass
     AND a.attname = 'id'
     AND NOT a.attisdropped;

  IF id_type IS NULL THEN
    RAISE EXCEPTION 'Could not find app_users.id - is the main schema applied?';
  END IF;

  EXECUTE format($f$
    CREATE TABLE IF NOT EXISTS app_connections (
      id              serial PRIMARY KEY,
      app_user_id     %s NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
      app_slot        smallint NOT NULL CHECK (app_slot BETWEEN 1 AND 4),
      client_id       text NOT NULL,
      deriv_loginid   text NOT NULL,
      status          text NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'connected', 'expired', 'failed')),
      connected_at    timestamptz,
      last_checked_at timestamptz,
      last_error      text,
      created_at      timestamptz NOT NULL DEFAULT now(),
      UNIQUE (app_user_id, app_slot)
    )
  $f$, id_type);
END
$$;

-- Handy checks (run manually in the Neon SQL editor):
--   SELECT app_user_id, app_slot, status, deriv_loginid, connected_at
--     FROM app_connections ORDER BY app_user_id, app_slot;
--
-- Start a user's setup over (they will redo App 1 -> 4 in order):
--   DELETE FROM app_connections WHERE app_user_id = <their id>;
