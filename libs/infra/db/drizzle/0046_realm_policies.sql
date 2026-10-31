ALTER TABLE "realms" ADD COLUMN "policies" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "realms" ADD COLUMN "policy_schema_version" varchar(32);--> statement-breakpoint
ALTER TABLE "realms" ADD COLUMN "policies_version" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_policies_object" CHECK (jsonb_typeof("realms"."policies") = 'object');--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_policies_version_not_negative" CHECK ("realms"."policies_version" >= 0);--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_policy_schema_version_format" CHECK ("realms"."policy_schema_version" ~ '^[1-9][0-9]*(-rc\.(0|[1-9][0-9]*))?$');--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_policies_complete" CHECK ("realms"."policies_version" = 0 OR ("realms"."policy_schema_version" IS NOT NULL AND "realms"."access_token_lifespan" IS NOT NULL AND "realms"."refresh_token_lifespan" IS NOT NULL));--> statement-breakpoint
-- #516: realms.policies_version is the ETag of a realm's policies and the
-- If-Match a policy update compares, so it must change whenever the policies
-- do, whoever writes them. The policy store raises it itself; an UPDATE that
-- changes the document, its schema version or one of the four policy columns
-- and leaves the counter as it was (the realms repository's update, an
-- earlier release's node during a rolling upgrade, a hand-written UPDATE) has
-- it raised here. A realm without policies (0) keeps 0: the boot step fills
-- it. The counter never moves back, or an old ETag could match a new document.
CREATE FUNCTION "realms_policies_version"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW."policies_version" < OLD."policies_version" THEN
    RAISE EXCEPTION 'realms.policies_version only moves forward'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'realms_policies_version_forward_only',
            TABLE = 'realms';
  END IF;
  IF OLD."policies_version" > 0
     AND NEW."policies_version" = OLD."policies_version"
     AND (NEW."policies" IS DISTINCT FROM OLD."policies"
          OR NEW."policy_schema_version" IS DISTINCT FROM OLD."policy_schema_version"
          OR NEW."access_token_lifespan" IS DISTINCT FROM OLD."access_token_lifespan"
          OR NEW."refresh_token_lifespan" IS DISTINCT FROM OLD."refresh_token_lifespan"
          OR NEW."dynamic_registration_allowed_scopes" IS DISTINCT FROM OLD."dynamic_registration_allowed_scopes"
          OR NEW."max_environment_laxity" IS DISTINCT FROM OLD."max_environment_laxity") THEN
    NEW."policies_version" := OLD."policies_version" + 1;
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER "realms_policies_version"
  BEFORE UPDATE OF "policies", "policy_schema_version", "policies_version",
    "access_token_lifespan", "refresh_token_lifespan",
    "dynamic_registration_allowed_scopes", "max_environment_laxity" ON "realms"
  FOR EACH ROW
  EXECUTE FUNCTION "realms_policies_version"();
