CREATE TABLE "user_attributes" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"source" text NOT NULL,
	"attr_key" text NOT NULL,
	"attr_value" text NOT NULL,
	"verified" boolean DEFAULT false NOT NULL,
	"expires_at" bigint,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_credentials" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"realm_id" uuid NOT NULL,
	"provider_type" text NOT NULL,
	"external_sub" text NOT NULL,
	"credential_data" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "user_credentials_credential_data_is_object" CHECK (jsonb_typeof("user_credentials"."credential_data") = 'object')
);
--> statement-breakpoint
ALTER TABLE "user_attributes" ADD CONSTRAINT "user_attributes_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_credentials" ADD CONSTRAINT "user_credentials_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_credentials" ADD CONSTRAINT "user_credentials_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_user_attributes_user_source_key_unique" ON "user_attributes" USING btree ("user_id","source","attr_key");--> statement-breakpoint
CREATE INDEX "idx_user_attributes_user_id" ON "user_attributes" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_user_credentials_realm_provider_sub_unique" ON "user_credentials" USING btree ("realm_id","provider_type","external_sub");--> statement-breakpoint
CREATE INDEX "idx_user_credentials_user_id" ON "user_credentials" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_user_credentials_realm_id" ON "user_credentials" USING btree ("realm_id");