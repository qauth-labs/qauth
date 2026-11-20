-- #537: the webhook subscriptions of a realm. Each names an https
-- destination, the event types and categories it receives, whether it is
-- enabled and why not, the kid of its newest signing secret (the secret itself
-- is the realm's `webhook_signing` key scoped to the subscription, sealed in
-- realm_keys), when the secret a rotation replaced stops signing, the
-- sender's failure counters and the admin who created it.
--
-- A new, empty table: nothing is rewritten, and a release before this one
-- never names it, so it is safe during a rolling upgrade. Forward-only.
CREATE TABLE "webhook_subscriptions" (
	"id" uuid PRIMARY KEY NOT NULL,
	"realm_id" uuid NOT NULL,
	"url" varchar(2048) NOT NULL,
	"description" varchar(500),
	"event_types" jsonb,
	"categories" jsonb NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"disabled_reason" varchar(64),
	"secret_ref" varchar(255) NOT NULL,
	"previous_secret_expires_at" bigint,
	"consecutive_failures" integer DEFAULT 0 NOT NULL,
	"failure_count" bigint DEFAULT 0 NOT NULL,
	"last_failure_at" bigint,
	"created_by" uuid,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "webhook_subscriptions_url_https" CHECK (left("webhook_subscriptions"."url", 8) = 'https://'),
	CONSTRAINT "webhook_subscriptions_event_types_list" CHECK ("webhook_subscriptions"."event_types" IS NULL OR (jsonb_typeof("webhook_subscriptions"."event_types") = 'array' AND jsonb_array_length("webhook_subscriptions"."event_types") > 0)),
	CONSTRAINT "webhook_subscriptions_categories_list" CHECK (jsonb_typeof("webhook_subscriptions"."categories") = 'array' AND jsonb_array_length("webhook_subscriptions"."categories") > 0 AND "webhook_subscriptions"."categories" <@ '["user","admin"]'::jsonb),
	CONSTRAINT "webhook_subscriptions_disabled_reason" CHECK (("webhook_subscriptions"."enabled" AND "webhook_subscriptions"."disabled_reason" IS NULL) OR (NOT "webhook_subscriptions"."enabled" AND "webhook_subscriptions"."disabled_reason" IS NOT NULL AND "webhook_subscriptions"."disabled_reason" <> '')),
	CONSTRAINT "webhook_subscriptions_secret_ref" CHECK ("webhook_subscriptions"."secret_ref" <> ''),
	CONSTRAINT "webhook_subscriptions_failures" CHECK ("webhook_subscriptions"."consecutive_failures" >= 0 AND "webhook_subscriptions"."failure_count" >= 0),
	CONSTRAINT "webhook_subscriptions_version_positive" CHECK ("webhook_subscriptions"."version" > 0)
);
--> statement-breakpoint
ALTER TABLE "webhook_subscriptions" ADD CONSTRAINT "webhook_subscriptions_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhook_subscriptions" ADD CONSTRAINT "webhook_subscriptions_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_webhook_subscriptions_realm_created" ON "webhook_subscriptions" USING btree ("realm_id","created_at","id");--> statement-breakpoint
CREATE INDEX "idx_webhook_subscriptions_overlap" ON "webhook_subscriptions" USING btree ("previous_secret_expires_at") WHERE "webhook_subscriptions"."previous_secret_expires_at" IS NOT NULL;