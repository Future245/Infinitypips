-- db/app_connections_8_slots.sql
--
-- OPTIONAL, run ONCE in the Neon SQL Editor. Allows app slots 5-8
-- (Nuclear Mode) to be recorded in app_connections. The robot already works
-- without it; this only lets the portal remember apps 5-8 between visits.
DO $$
DECLARE c text;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
     WHERE conrelid = 'app_connections'::regclass AND contype = 'c'
       AND pg_get_constraintdef(oid) ILIKE '%app_slot%'
  LOOP
    EXECUTE format('ALTER TABLE app_connections DROP CONSTRAINT %I', c);
  END LOOP;
  ALTER TABLE app_connections
    ADD CONSTRAINT app_connections_app_slot_check CHECK (app_slot BETWEEN 1 AND 8);
END
$$;
