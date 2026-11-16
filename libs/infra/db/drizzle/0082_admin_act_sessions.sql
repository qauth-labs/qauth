-- #523: act-chain tokens for admins acting for a user (ADR-019 Decision 7).
-- An admin who acts for a user gets an act-chain token (`sub` the user, `act`
-- the admin), minted in the transaction of the approved security operation
-- that issues it; that transaction writes one row here. The account API reads
-- the row on every call made with the token: the token works only while its
-- row is there, unexpired, and its approval is still consumed, and while the
-- admin still holds the permissions the row names. The user's account page
-- lists the rows ("an administrator acted for you").
--
-- The composite foreign key keeps the user in the row's realm
-- (`users_id_realm_id_unique`); deleting the user or the realm removes the
-- rows. The admin's account and the approval are referenced by id only, as
-- the admin audit log does, so the record outlives them. No secret: the row
-- holds the token's `jti`, never the token.
--
-- A new, empty table: nothing is rewritten, and a release before this one
-- never names it, so it is safe during a rolling upgrade. `admin` may insert
-- and read it, `api` may read it; no role updates or deletes it. Forward-only.
CREATE TABLE "admin_act_sessions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"admin_realm_id" uuid NOT NULL,
	"admin_user_id" uuid NOT NULL,
	"admin_client_id" varchar(255) NOT NULL,
	"approval_id" uuid NOT NULL,
	"operation_id" varchar(128) NOT NULL,
	"permission_ids" jsonb NOT NULL,
	"token_jti" varchar(255) NOT NULL,
	"scopes" jsonb NOT NULL,
	"created_at" bigint NOT NULL,
	"expires_at" bigint NOT NULL,
	CONSTRAINT "admin_act_sessions_realm_jti_unique" UNIQUE("realm_id","token_jti"),
	CONSTRAINT "admin_act_sessions_admin_client_id_not_empty" CHECK ("admin_act_sessions"."admin_client_id" <> ''),
	CONSTRAINT "admin_act_sessions_operation_id_not_empty" CHECK ("admin_act_sessions"."operation_id" <> ''),
	CONSTRAINT "admin_act_sessions_token_jti_not_empty" CHECK ("admin_act_sessions"."token_jti" <> ''),
	CONSTRAINT "admin_act_sessions_scopes_strings" CHECK (jsonb_typeof("admin_act_sessions"."scopes") = 'array' AND jsonb_array_length("admin_act_sessions"."scopes") > 0 AND NOT jsonb_path_exists("admin_act_sessions"."scopes", '$[*] ? (@.type() != "string")')),
	CONSTRAINT "admin_act_sessions_permission_ids_strings" CHECK (jsonb_typeof("admin_act_sessions"."permission_ids") = 'array' AND jsonb_array_length("admin_act_sessions"."permission_ids") > 0 AND NOT jsonb_path_exists("admin_act_sessions"."permission_ids", '$[*] ? (@.type() != "string")')),
	CONSTRAINT "admin_act_sessions_lifetime" CHECK ("admin_act_sessions"."expires_at" > "admin_act_sessions"."created_at" AND "admin_act_sessions"."expires_at" - "admin_act_sessions"."created_at" <= 600000)
);
--> statement-breakpoint
ALTER TABLE "admin_act_sessions" ADD CONSTRAINT "admin_act_sessions_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_act_sessions" ADD CONSTRAINT "admin_act_sessions_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_admin_act_sessions_user" ON "admin_act_sessions" USING btree ("realm_id","user_id","created_at");
