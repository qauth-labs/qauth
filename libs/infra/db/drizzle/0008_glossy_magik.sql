CREATE TABLE "api_keys" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"client_id" uuid NOT NULL,
	"developer_id" uuid,
	"name" varchar(255) NOT NULL,
	"key_hash" text NOT NULL,
	"prefix" varchar(64) NOT NULL,
	"last4" varchar(4) NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"last_used_at" bigint,
	"revoked_at" bigint
);
--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_client_id_oauth_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_developer_id_users_id_fk" FOREIGN KEY ("developer_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_api_keys_prefix_unique" ON "api_keys" USING btree ("prefix");--> statement-breakpoint
CREATE INDEX "idx_api_keys_client_id" ON "api_keys" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "idx_api_keys_developer_id" ON "api_keys" USING btree ("developer_id");--> statement-breakpoint
CREATE INDEX "idx_api_keys_realm_id" ON "api_keys" USING btree ("realm_id");--> statement-breakpoint
CREATE INDEX "idx_api_keys_active" ON "api_keys" USING btree ("client_id") WHERE "api_keys"."revoked_at" IS NULL;