-- #635 (ADR-017, ADR-020 §3): the actions a user must take at the next
-- sign-in (update the password, set up a second factor or a passkey, complete
-- the profile), one row per user and action. One new table, and no change to a
-- row of any other, so the previous release keeps working on the new schema
-- during a rolling upgrade: it never reads or writes the table. Forward-only:
-- nothing is rewritten.
--
-- Locks first, in the order the writers of both referenced tables take them,
-- as 0043 and 0045 do: a realm's deletion takes `realms` and then cascades
-- into `users`, while a user's insert only key-shares its realm, which SHARE
-- ROW EXCLUSIVE lets through. The foreign keys below would take `realms`,
-- then `users`, then `realms` again; taking both up front keeps a realm
-- deletion that started while the migration waited from deadlocking with it.
-- SHARE ROW EXCLUSIVE is what ADD FOREIGN KEY takes on the referenced table:
-- reads go on, writes wait for the runner's commit.
--
-- The CHECKs hold the closed sets of `action` and `source`. The user foreign
-- key is on (user_id, realm_id), the target of users_id_realm_id_unique, so
-- the database refuses a row whose user is of another realm.
LOCK TABLE "realms" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "users" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
CREATE TABLE "user_required_actions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"action" varchar(32) NOT NULL,
	"source" varchar(16) NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "user_required_actions_action_known" CHECK ("user_required_actions"."action" in ('update_password', 'setup_mfa', 'setup_passkey', 'complete_profile')),
	CONSTRAINT "user_required_actions_source_known" CHECK ("user_required_actions"."source" in ('admin', 'user_report'))
);
--> statement-breakpoint
ALTER TABLE "user_required_actions" ADD CONSTRAINT "user_required_actions_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_required_actions" ADD CONSTRAINT "user_required_actions_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_user_required_actions_user_action_unique" ON "user_required_actions" USING btree ("user_id","action");--> statement-breakpoint
CREATE INDEX "idx_user_required_actions_realm_id" ON "user_required_actions" USING btree ("realm_id");