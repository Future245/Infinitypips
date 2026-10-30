-- db/persistent_auth_schema.sql
--
-- Run ONCE in the Neon SQL Editor (same database DATABASE_URL points to), AFTER
-- app_connections_schema.sql. It only ADDS a table.
--
-- One row per (user, app slot 1-8). Holds that slot's Deriv OAuth credentials,
-- ENCRYPTED (AES-256-GCM, key in the TOKEN_ENCRYPTION_KEY env var, never in the
-- database). The browser never receives these values.
--
--   status 'valid'           - last use / refresh worked
--   status 'reauth_required' - Deriv rejected the credentials (or no refresh token
--                              exists and the access token expired): this ONE app
--                              must be authorized again; the others are untouched.
--
-- Temporary trouble (network, Deriv 5xx, database blip) never changes status.
DO $$
DECLARE
  id_type text;
BEGIN
  SELECT format_type(a.atttypid, a.atttypmod) INTO id_type
    FROM pg_attribute a
   WHERE a.attrelid = 'app_users'::regclass AND a.attname = 'id' AND NOT a.attisdropped;
  IF id_type IS NULL THEN
    RAISE EXCEPTION 'Could not find app_users.id - is the main schema applied?';
  END IF;

  EXECUTE format($f$
    CREATE TABLE IF NOT EXISTS deriv_credentials (
      app_user_id        %s NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
      app_slot           smallint NOT NULL CHECK (app_slot BETWEEN 1 AND 8),
      client_id          text NOT NULL,
      deriv_loginid      text NOT NULL,
      access_token_enc   text NOT NULL,
      access_expires_at  timestamptz NOT NULL,
      refresh_token_enc  text,
      scope              text,
      status             text NOT NULL DEFAULT 'valid' CHECK (status IN ('valid', 'reauth_required')),
      last_error         text,
      last_verified_at   timestamptz,
      last_refreshed_at  timestamptz,
      created_at         timestamptz NOT NULL DEFAULT now(),
      updated_at         timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (app_user_id, app_slot)
    )
  $f$, id_type);
END
$$;

-- Handy checks (never selects the encrypted columns):
--   SELECT app_user_id, app_slot, status, access_expires_at, (refresh_token_enc IS NOT NULL) AS has_refresh,
--          last_verified_at, last_error FROM deriv_credentials ORDER BY app_user_id, app_slot;
