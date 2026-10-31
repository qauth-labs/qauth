ALTER TABLE "users" ADD COLUMN "not_valid_before" bigint;--> statement-breakpoint
-- #748: an account already disabled when this runs was disabled at a time no
-- one recorded. Nothing is issued to a disabled account, so now is a time
-- after its disablement and before anything it can be issued again: every
-- session and token it holds stays refused once it is enabled.
UPDATE "users"
   SET "not_valid_before" = floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint
 WHERE NOT "enabled";
--> statement-breakpoint
-- #748: users.not_valid_before is when the account was last disabled. Every
-- browser session and token of the user issued before it is refused, also
-- after the account is enabled again. It is set here, from the database's
-- clock, whenever enabled turns from true to false, however the account is
-- disabled: the db:disable-user script, or an UPDATE by hand. It only ever
-- moves forward, so enabling the account again cannot clear it.
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
--> statement-breakpoint
-- #748: until the disabling transaction commits, every other transaction still
-- reads the account as enabled, and may sign it in or rotate its tokens. So
-- the time moves once more, to the end of that transaction: what was issued
-- while it was open counts as issued before the disablement. A constraint
-- trigger, deferred to the commit; its own UPDATE names no "enabled", so it
-- does not fire itself again, and users_not_valid_before checks that it only
-- moves the time forward. A later migration that disables accounts leaves its
-- trigger events pending until the commit, and the migrator applies every
-- pending migration in one transaction: nothing after it in that transaction
-- may ALTER or TRUNCATE "users" (55006).
CREATE FUNCTION "users_not_valid_before_at_commit"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  UPDATE public."users"
     SET "not_valid_before" = GREATEST(
           "not_valid_before",
           floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint
         )
   WHERE "id" = NEW."id" AND NOT "enabled";
  RETURN NULL;
END;
$$;
--> statement-breakpoint
CREATE CONSTRAINT TRIGGER "users_not_valid_before_at_commit"
  AFTER UPDATE OF "enabled" ON "users"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  WHEN (OLD."enabled" AND NOT NEW."enabled")
  EXECUTE FUNCTION "users_not_valid_before_at_commit"();
