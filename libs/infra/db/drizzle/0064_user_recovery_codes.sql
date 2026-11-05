-- #649 (ADR-017 Decision 8, ADR-018 §3): each account's recovery codes, one
-- row per code of its current set, 10 to a set. A row holds only the code's
-- salted hash from the password hasher, never the code, and `used_at` once the
-- one write that takes it (`UPDATE … WHERE used_at IS NULL`) has run. A new set
-- replaces the old one in one transaction. One new table, and no change to a
-- row of any other, so the previous release keeps working on the new schema
-- during a rolling upgrade: it never reads or writes the table. Forward-only:
-- nothing is rewritten.
--
-- Locks first, in the order the writers of both referenced tables take them,
-- as 0062 does: a realm's deletion takes `realms` and then cascades into
-- `users`, while a user's insert only key-shares its realm, which SHARE ROW
-- EXCLUSIVE lets through. Taking both up front keeps a realm deletion that
-- started while the migration waited from deadlocking with the foreign keys.
--
-- The user foreign key is on (user_id, realm_id), the target of
-- users_id_realm_id_unique, so the database refuses a row whose user is of
-- another realm. The CHECKs keep the hash non-empty and the times positive.
LOCK TABLE "realms" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "users" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
CREATE TABLE "user_recovery_codes" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"code_hash" text NOT NULL,
	"created_at" bigint NOT NULL,
	"used_at" bigint,
	CONSTRAINT "user_recovery_codes_code_hash_not_empty" CHECK (length("user_recovery_codes"."code_hash") > 0),
	CONSTRAINT "user_recovery_codes_created_at_positive" CHECK ("user_recovery_codes"."created_at" > 0),
	CONSTRAINT "user_recovery_codes_used_at_positive" CHECK ("user_recovery_codes"."used_at" IS NULL OR "user_recovery_codes"."used_at" > 0)
);
--> statement-breakpoint
ALTER TABLE "user_recovery_codes" ADD CONSTRAINT "user_recovery_codes_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_recovery_codes" ADD CONSTRAINT "user_recovery_codes_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_user_recovery_codes_user_realm" ON "user_recovery_codes" USING btree ("user_id","realm_id");--> statement-breakpoint
CREATE INDEX "idx_user_recovery_codes_realm_id" ON "user_recovery_codes" USING btree ("realm_id");