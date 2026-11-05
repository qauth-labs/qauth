-- #642 (ADR-017 Decision 8, ADR-019 Decision 3): each user's session epoch,
-- which the owner's password reset advances in the transaction that replaces
-- the password. A browser session created before it is absent, and a sign-in
-- transaction that began before it ends. One row per user, written at the
-- first reset; a user never reset has none. Its own table, not a `users`
-- column (ADR-002). One new table, and no change to a row of any other, so the
-- previous release keeps working on the new schema during a rolling upgrade:
-- it never reads or writes the table. Forward-only: nothing is rewritten.
--
-- Locks first, in the order the writers of both referenced tables take them,
-- as 0059 does: a realm's deletion takes `realms` and then cascades into
-- `users`, while a user's insert only key-shares its realm, which SHARE ROW
-- EXCLUSIVE lets through. The foreign keys below would take `realms`, then
-- `users`, then `realms` again; taking both up front keeps a realm deletion
-- that started while the migration waited from deadlocking with it.
--
-- The user foreign key is on (user_id, realm_id), the target of
-- users_id_realm_id_unique, so the database refuses a row whose user is of
-- another realm. The CHECKs keep the counter and its time positive.
LOCK TABLE "realms" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "users" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
CREATE TABLE "user_session_epochs" (
	"user_id" uuid PRIMARY KEY NOT NULL,
	"realm_id" uuid NOT NULL,
	"epoch" integer NOT NULL,
	"advanced_at" bigint NOT NULL,
	CONSTRAINT "user_session_epochs_epoch_positive" CHECK ("user_session_epochs"."epoch" > 0),
	CONSTRAINT "user_session_epochs_advanced_at_positive" CHECK ("user_session_epochs"."advanced_at" > 0)
);
--> statement-breakpoint
ALTER TABLE "user_session_epochs" ADD CONSTRAINT "user_session_epochs_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_session_epochs" ADD CONSTRAINT "user_session_epochs_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_user_session_epochs_realm_id" ON "user_session_epochs" USING btree ("realm_id");