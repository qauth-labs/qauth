CREATE TABLE "admin_grants" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"built_in_role" varchar(64),
	"role_id" uuid,
	"target_realm_id" uuid,
	"created_by" uuid,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"revoked_at" bigint,
	"last_security_change_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "admin_grants_one_role" CHECK (("admin_grants"."built_in_role" IS NULL) <> ("admin_grants"."role_id" IS NULL)),
	CONSTRAINT "admin_grants_built_in_role_grammar" CHECK ("admin_grants"."built_in_role" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'),
	CONSTRAINT "admin_grants_revoked_after_created" CHECK ("admin_grants"."revoked_at" IS NULL OR "admin_grants"."revoked_at" >= "admin_grants"."created_at")
);
--> statement-breakpoint
CREATE TABLE "admin_roles" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"name" varchar(64) NOT NULL,
	"permission_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"disabled_at" bigint,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "admin_roles_realm_name_unique" UNIQUE("realm_id","name"),
	CONSTRAINT "admin_roles_name_grammar" CHECK ("admin_roles"."name" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'),
	CONSTRAINT "admin_roles_permission_ids_strings" CHECK (jsonb_typeof("admin_roles"."permission_ids") = 'array' AND NOT jsonb_path_exists("admin_roles"."permission_ids", '$[*] ? (@.type() != "string")'))
);
--> statement-breakpoint
ALTER TABLE "admin_grants" ADD CONSTRAINT "admin_grants_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_grants" ADD CONSTRAINT "admin_grants_role_id_admin_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."admin_roles"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_grants" ADD CONSTRAINT "admin_grants_target_realm_id_realms_id_fk" FOREIGN KEY ("target_realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_grants" ADD CONSTRAINT "admin_grants_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_roles" ADD CONSTRAINT "admin_roles_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_admin_grants_live_unique" ON "admin_grants" USING btree ("user_id",coalesce('custom:' || "role_id"::text, 'built-in:' || "built_in_role"),coalesce("target_realm_id"::text, '*')) WHERE "admin_grants"."revoked_at" IS NULL;--> statement-breakpoint
CREATE INDEX "idx_admin_grants_user_id" ON "admin_grants" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_admin_grants_role_id" ON "admin_grants" USING btree ("role_id");--> statement-breakpoint
CREATE INDEX "idx_admin_grants_target_realm_id" ON "admin_grants" USING btree ("target_realm_id");--> statement-breakpoint
-- #510 (ADR-019 Decision 7): the realm rule of admin grants, for every writer.
-- The repository refuses the same before it writes; this holds for a row
-- written any other way.
--
-- - Only an account of the operator realm holds a grant on every realm
--   (target_realm_id NULL).
-- - An account of any other realm holds grants on its own realm only, so a
--   realm-local admin never manages another realm or the operator realm.
-- - A custom role is named only by a grant whose account lives in the role's
--   realm, or whose target is the role's realm.
--
-- Checked when a grant is written; the auth server applies the rule again on
-- every request, so a grant that stops fitting it (the operator flag moved)
-- grants nothing. A missing account or role is left to the foreign keys, which
-- refuse the row after this trigger. The function pins its search_path and
-- names its tables with their schema, so no caller can swap in its own.
CREATE FUNCTION "admin_grants_realm_rule"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  account_realm uuid;
  account_is_operator boolean;
  role_realm uuid;
BEGIN
  SELECT u."realm_id", r."is_operator"
    INTO account_realm, account_is_operator
    FROM public."users" u
    JOIN public."realms" r ON r."id" = u."realm_id"
    WHERE u."id" = NEW."user_id";
  IF account_realm IS NULL THEN
    RETURN NEW;
  END IF;
  IF NEW."target_realm_id" IS NULL AND NOT account_is_operator THEN
    RAISE EXCEPTION 'only an account of the operator realm can hold an admin grant on every realm'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'admin_grants_all_realms_operator_only',
            TABLE = 'admin_grants';
  END IF;
  IF NEW."target_realm_id" IS NOT NULL
     AND NEW."target_realm_id" <> account_realm
     AND NOT account_is_operator THEN
    RAISE EXCEPTION 'an account outside the operator realm can hold admin grants on its own realm only'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'admin_grants_target_own_realm',
            TABLE = 'admin_grants';
  END IF;
  IF NEW."role_id" IS NOT NULL THEN
    SELECT ar."realm_id" INTO role_realm
      FROM public."admin_roles" ar
      WHERE ar."id" = NEW."role_id";
    IF role_realm IS NOT NULL
       AND role_realm <> account_realm
       AND role_realm IS DISTINCT FROM NEW."target_realm_id" THEN
      RAISE EXCEPTION 'a custom admin role is granted only to an account of its realm or for its realm'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'admin_grants_role_realm',
              TABLE = 'admin_grants';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER "admin_grants_realm_rule"
  BEFORE INSERT OR UPDATE OF "user_id", "role_id", "target_realm_id" ON "admin_grants"
  FOR EACH ROW
  EXECUTE FUNCTION "admin_grants_realm_rule"();
