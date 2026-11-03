ALTER TABLE "realms" ADD COLUMN "sandbox_of_realm_id" uuid;--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_sandbox_of_realm_id_realms_id_fk" FOREIGN KEY ("sandbox_of_realm_id") REFERENCES "public"."realms"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_realms_sandbox_of_realm_id" ON "realms" USING btree ("sandbox_of_realm_id");--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_sandbox_not_self" CHECK ("realms"."sandbox_of_realm_id" IS NULL OR "realms"."sandbox_of_realm_id" <> "realms"."id");--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_sandbox_not_operator" CHECK ("realms"."sandbox_of_realm_id" IS NULL OR NOT "realms"."is_operator");--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_sandbox_ceiling" CHECK ("realms"."sandbox_of_realm_id" IS NULL OR "realms"."max_environment_laxity" <> 'development');--> statement-breakpoint
-- Hand-written below this line: drizzle-kit does not model functions or
-- triggers, so `db:generate` neither writes nor drops them.
--
-- The paired sandbox realm (ADR-019 Decision 11, #554). The CHECKs above hold
-- what one row can say; this trigger holds what needs another row, whoever
-- writes it:
--
-- - The pairing is set when the sandbox is created and never changes. A
--   sandbox's settings move only into the live realm it was created for, and
--   a realm that already has users does not become a sandbox.
-- - A sandbox has no sandbox: a realm is paired only with a realm that is no
--   sandbox itself. (A new realm has no sandbox yet, and the pairing never
--   changes later, so a realm with a sandbox never becomes one.)
-- - The operator realm has no sandbox: neither a pairing with it, nor the
--   operator flag moving to a realm that has one.
--
-- - The live realm exists before its sandbox does. The foreign key alone
--   checks only at the end of the statement, so one multi-row INSERT could
--   pair a sandbox with a realm a later row of it inserts, which this trigger
--   could not read: the trigger refuses a live realm it cannot read itself.
--
-- The INSERT reads the live realm `FOR SHARE`, which waits for, and holds
-- off, any UPDATE of that row: an operator flag moving onto it commits
-- first and is seen, or waits until the sandbox is in and finds it.
CREATE FUNCTION "realms_sandbox_pairing"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  live_sandbox_of uuid;
  live_is_operator boolean;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW."sandbox_of_realm_id" IS DISTINCT FROM OLD."sandbox_of_realm_id" THEN
      RAISE EXCEPTION 'realms.sandbox_of_realm_id is set when the sandbox realm is created, and never changes'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'realms_sandbox_pairing_permanent',
              TABLE = 'realms',
              DETAIL = format('realm %s', OLD."id");
    END IF;
    IF NEW."is_operator" AND EXISTS (
      SELECT 1 FROM public."realms" s WHERE s."sandbox_of_realm_id" = NEW."id"
    ) THEN
      RAISE EXCEPTION 'the operator realm has no sandbox realm'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'realms_sandbox_of_operator',
              TABLE = 'realms',
              DETAIL = format('realm %s has a sandbox realm', NEW."id");
    END IF;
    RETURN NEW;
  END IF;

  -- A realm paired with itself: the CHECK "realms_sandbox_not_self" refuses it.
  IF NEW."sandbox_of_realm_id" = NEW."id" THEN
    RETURN NEW;
  END IF;
  SELECT l."sandbox_of_realm_id", l."is_operator"
    INTO live_sandbox_of, live_is_operator
    FROM public."realms" l
    WHERE l."id" = NEW."sandbox_of_realm_id"
    FOR SHARE;
  -- No such realm yet, a later row of this statement included: refused now,
  -- as the foreign key would refuse a realm that never comes.
  IF NOT FOUND THEN
    RAISE EXCEPTION 'the live realm of a sandbox realm exists before the sandbox realm'
      USING ERRCODE = 'foreign_key_violation',
            CONSTRAINT = 'realms_sandbox_of_realm_id_realms_id_fk',
            TABLE = 'realms',
            DETAIL = format('no realm %s', NEW."sandbox_of_realm_id");
  END IF;
  IF live_sandbox_of IS NOT NULL THEN
    RAISE EXCEPTION 'a sandbox realm has no sandbox realm'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'realms_sandbox_of_sandbox',
            TABLE = 'realms',
            DETAIL = format('realm %s is the sandbox of realm %s', NEW."sandbox_of_realm_id", live_sandbox_of);
  END IF;
  IF live_is_operator THEN
    RAISE EXCEPTION 'the operator realm has no sandbox realm'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'realms_sandbox_of_operator',
            TABLE = 'realms',
            DETAIL = format('realm %s is the operator realm', NEW."sandbox_of_realm_id");
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER "realms_sandbox_pairing_insert"
  BEFORE INSERT ON "realms"
  FOR EACH ROW
  WHEN (NEW."sandbox_of_realm_id" IS NOT NULL)
  EXECUTE FUNCTION "realms_sandbox_pairing"();
--> statement-breakpoint
CREATE TRIGGER "realms_sandbox_pairing_update"
  BEFORE UPDATE OF "sandbox_of_realm_id", "is_operator" ON "realms"
  FOR EACH ROW
  WHEN (
    NEW."sandbox_of_realm_id" IS DISTINCT FROM OLD."sandbox_of_realm_id"
    OR (NEW."is_operator" AND NOT OLD."is_operator")
  )
  EXECUTE FUNCTION "realms_sandbox_pairing"();
