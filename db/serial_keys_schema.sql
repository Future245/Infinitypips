-- db/serial_keys_schema.sql
--
-- Run this ONCE against the same Neon/Postgres database already used by
-- deriv-token.js / session-status.js (the one DATABASE_URL points to).
-- It does not touch or alter app_users, app_sessions, or deriv_accounts.
--
-- How to run it: open your Neon project -> SQL Editor -> paste this file
-- -> Run. (Or `psql "$DATABASE_URL" -f db/serial_keys_schema.sql`.)

-- Holds the serial keys you issue to clients. You add rows to this table
-- manually (e.g. via the Neon SQL editor) — nothing in the app writes to
-- it. Format enforced: exactly XXXX-XXXX-XXXX (12 digits, dash-grouped).
CREATE TABLE IF NOT EXISTS serial_keys (
  id          serial PRIMARY KEY,
  serial_key  text UNIQUE NOT NULL CHECK (serial_key ~ '^\d{4}-\d{4}-\d{4}$'),
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Tracks which browsers have successfully proven a valid serial key, so
-- returning visitors don't have to retype it every time they close the
-- site. Deliberately separate from app_sessions (Deriv OAuth) — a serial
-- key session says nothing about which Deriv account, if any, is linked.
CREATE TABLE IF NOT EXISTS serial_key_sessions (
  session_token text PRIMARY KEY,
  serial_key    text NOT NULL REFERENCES serial_keys(serial_key),
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_serial_key_sessions_expires_at
  ON serial_key_sessions (expires_at);

-- Example of adding a key manually (repeat for each key you issue):
-- INSERT INTO serial_keys (serial_key) VALUES ('4827-1936-7504');
--
-- To revoke a key without deleting it (keeps history):
-- UPDATE serial_keys SET status = 'disabled' WHERE serial_key = '4827-1936-7504';
