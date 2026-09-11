ALTER TABLE "oid4vp_request_states" ADD COLUMN "same_device" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "oid4vp_request_states" ADD COLUMN "response_code_hash" varchar(64);--> statement-breakpoint
ALTER TABLE "oid4vp_request_states" ADD COLUMN "response_code_expires_at" bigint;--> statement-breakpoint
ALTER TABLE "oid4vp_request_states" ADD COLUMN "response_code_redeemed_at" bigint;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_oid4vp_request_states_response_code" ON "oid4vp_request_states" USING btree ("response_code_hash") WHERE "oid4vp_request_states"."response_code_redeemed_at" is null;--> statement-breakpoint
ALTER TABLE "oid4vp_request_states" ADD CONSTRAINT "oid4vp_request_states_response_code_complete" CHECK (("oid4vp_request_states"."response_code_hash" is null) = ("oid4vp_request_states"."response_code_expires_at" is null));--> statement-breakpoint
ALTER TABLE "oid4vp_request_states" ADD CONSTRAINT "oid4vp_request_states_response_code_redeemed_requires_hash" CHECK ("oid4vp_request_states"."response_code_redeemed_at" is null or "oid4vp_request_states"."response_code_hash" is not null);