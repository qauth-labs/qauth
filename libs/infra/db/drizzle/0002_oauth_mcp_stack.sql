CREATE TABLE "oauth_consents" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"oauth_client_id" uuid NOT NULL,
	"realm_id" uuid NOT NULL,
	"scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"granted_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"revoked_at" bigint
);
--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN "dynamic_registered_at" bigint;--> statement-breakpoint
ALTER TABLE "realms" ADD COLUMN "dynamic_registration_allowed_scopes" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "family_id" uuid DEFAULT uuidv7() NOT NULL;--> statement-breakpoint
ALTER TABLE "oauth_consents" ADD CONSTRAINT "oauth_consents_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "oauth_consents" ADD CONSTRAINT "oauth_consents_oauth_client_id_oauth_clients_id_fk" FOREIGN KEY ("oauth_client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "oauth_consents" ADD CONSTRAINT "oauth_consents_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_oauth_consents_user_client_active" ON "oauth_consents" USING btree ("user_id","oauth_client_id") WHERE "oauth_consents"."revoked_at" IS NULL;--> statement-breakpoint
CREATE INDEX "idx_oauth_consents_user_id" ON "oauth_consents" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_oauth_consents_client_id" ON "oauth_consents" USING btree ("oauth_client_id");--> statement-breakpoint
CREATE INDEX "idx_oauth_consents_realm_id" ON "oauth_consents" USING btree ("realm_id");--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_family_id" ON "refresh_tokens" USING btree ("family_id");