-- #522: service accounts for the admin API (ADR-019 Decision 7). A service
-- account is a `users` row with no credential, in the operator realm, and the
-- OAuth client it signs in with: `private_key_jwt`, `client_credentials` and a
-- DPoP proof. Its admin grants attach to the user row. This table binds the
-- two, names the account, and says whether it is enabled; the token endpoint
-- and the admin API read it on every request, so a disabled account gets no
-- token and makes no admin call from the next request on.
--
-- The composite foreign key keeps the account in the row's realm
-- (`users_id_realm_id_unique`); one user and one client are one service
-- account's at most. Deleting the realm, the account or the client removes
-- the row.
--
-- A new, empty table: nothing is rewritten, and a release before this one
-- never names it, so it is safe during a rolling upgrade; a node of such a
-- release knows no service account, and issues its client no admin token,
-- since that release names no account for a `client_credentials` token.
-- Forward-only.
CREATE TABLE "service_accounts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"name" varchar(64) NOT NULL,
	"user_id" uuid NOT NULL,
	"client_id" uuid NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_by" uuid,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "service_accounts_realm_name_unique" UNIQUE("realm_id","name"),
	CONSTRAINT "service_accounts_user_id_unique" UNIQUE("user_id"),
	CONSTRAINT "service_accounts_client_id_unique" UNIQUE("client_id"),
	CONSTRAINT "service_accounts_name_grammar" CHECK ("service_accounts"."name" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$')
);
--> statement-breakpoint
ALTER TABLE "service_accounts" ADD CONSTRAINT "service_accounts_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_accounts" ADD CONSTRAINT "service_accounts_client_id_oauth_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_accounts" ADD CONSTRAINT "service_accounts_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_accounts" ADD CONSTRAINT "service_accounts_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_service_accounts_created_by" ON "service_accounts" USING btree ("created_by");