CREATE TABLE "oid4vp_request_states" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"state_hash" varchar(64) NOT NULL,
	"nonce" text NOT NULL,
	"verifier_profile" text NOT NULL,
	"response_mode" text NOT NULL,
	"dcql_query" jsonb NOT NULL,
	"expires_at" bigint NOT NULL,
	"redeemed_at" bigint,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "oid4vp_request_states_state_hash_unique" UNIQUE("state_hash"),
	CONSTRAINT "oid4vp_request_states_dcql_query_object" CHECK (jsonb_typeof("oid4vp_request_states"."dcql_query") = 'object')
);
--> statement-breakpoint
ALTER TABLE "oid4vp_request_states" ADD CONSTRAINT "oid4vp_request_states_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_oid4vp_request_states_active" ON "oid4vp_request_states" USING btree ("state_hash","expires_at") WHERE "oid4vp_request_states"."redeemed_at" is null;--> statement-breakpoint
CREATE INDEX "idx_oid4vp_request_states_expires_at" ON "oid4vp_request_states" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_oid4vp_request_states_realm_id" ON "oid4vp_request_states" USING btree ("realm_id");