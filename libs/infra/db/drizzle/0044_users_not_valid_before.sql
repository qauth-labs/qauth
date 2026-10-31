ALTER TABLE "users" ADD COLUMN "not_valid_before" bigint;--> statement-breakpoint
-- #748: users.not_valid_before is when the account was last disabled. Every
-- browser session and token of the user issued before it is refused, also
-- after the account is enabled again. It is set here, from the database's
-- clock, whenever enabled turns from true to false, however the account is
-- disabled: the db:disable-user script, or an UPDATE by hand. clock_timestamp,
-- not now: the time the row changes, not when its transaction began. It only
-- ever moves forward, so enabling the account again cannot clear it.
CREATE FUNCTION "users_not_valid_before"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD."not_valid_before" IS NOT NULL
     AND (NEW."not_valid_before" IS NULL OR NEW."not_valid_before" < OLD."not_valid_before") THEN
    RAISE EXCEPTION 'users.not_valid_before only moves forward'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'users_not_valid_before_forward_only',
            TABLE = 'users';
  END IF;
  IF OLD."enabled" AND NOT NEW."enabled" THEN
    NEW."not_valid_before" := GREATEST(
      NEW."not_valid_before",
      floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint
    );
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER "users_not_valid_before"
  BEFORE UPDATE OF "enabled", "not_valid_before" ON "users"
  FOR EACH ROW
  EXECUTE FUNCTION "users_not_valid_before"();
