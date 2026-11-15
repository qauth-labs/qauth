-- #602: one-time admin enrolments (ADR-019 Decision 7). The break-glass
-- command `enrol-admin` creates an admin account with no password and no
-- credential, its admin grant, and one row here holding the SHA-256 of a
-- token it prints once in an enrolment URL. The Interaction API step that
-- registers the account's first passkey (#621) redeems the token once,
-- before `expires_at`.
--
-- The composite foreign key keeps the account in the row's realm
-- (`users_id_realm_id_unique`); one enrolment per account. Deleting the
-- account or the realm removes the row.
--
-- The trigger `admin_enrolments_use_once` lets a row change in one way only,
-- whoever writes it: an unused, unexpired token is marked used. Everything
-- else, a used token made usable again, an expiry moved, a token moved to
-- another account, is refused. "Unexpired" is read from the database's own
-- clock too, so a writer that hands an earlier `used_at` cannot redeem an
-- expired token.
--
-- A new, empty table and a trigger on it: nothing is rewritten, and a
-- release before this one never names it, so it is safe during a rolling
-- upgrade. No service role is granted anything on it: only the table owner,
-- the host's command, writes it. Forward-only.
CREATE TABLE "admin_enrolments" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"token_hash" "bytea" NOT NULL,
	"created_at" bigint NOT NULL,
	"expires_at" bigint NOT NULL,
	"used_at" bigint,
	CONSTRAINT "admin_enrolments_token_hash_unique" UNIQUE("token_hash"),
	CONSTRAINT "admin_enrolments_user_id_unique" UNIQUE("user_id"),
	CONSTRAINT "admin_enrolments_token_hash_sha256" CHECK (octet_length("admin_enrolments"."token_hash") = 32),
	CONSTRAINT "admin_enrolments_expires_after_created" CHECK ("admin_enrolments"."expires_at" > "admin_enrolments"."created_at"),
	CONSTRAINT "admin_enrolments_used_after_created" CHECK ("admin_enrolments"."used_at" IS NULL OR "admin_enrolments"."used_at" >= "admin_enrolments"."created_at")
);
--> statement-breakpoint
ALTER TABLE "admin_enrolments" ADD CONSTRAINT "admin_enrolments_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_enrolments" ADD CONSTRAINT "admin_enrolments_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;

--> statement-breakpoint
-- The one change a row takes: its redemption, once, before it expires.
CREATE FUNCTION "admin_enrolments_use_once"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD."used_at" IS NOT NULL
     OR NEW."used_at" IS NULL
     OR NEW."used_at" >= OLD."expires_at"
     OR (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint >= OLD."expires_at"
     OR NEW."id" IS DISTINCT FROM OLD."id"
     OR NEW."realm_id" IS DISTINCT FROM OLD."realm_id"
     OR NEW."user_id" IS DISTINCT FROM OLD."user_id"
     OR NEW."token_hash" IS DISTINCT FROM OLD."token_hash"
     OR NEW."created_at" IS DISTINCT FROM OLD."created_at"
     OR NEW."expires_at" IS DISTINCT FROM OLD."expires_at" THEN
    RAISE EXCEPTION 'An admin enrolment only changes when its unused, unexpired token is redeemed, once'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'admin_enrolments_use_once',
            TABLE = 'admin_enrolments';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER "admin_enrolments_use_once"
  BEFORE UPDATE ON "admin_enrolments"
  FOR EACH ROW
  EXECUTE FUNCTION "admin_enrolments_use_once"();
