-- #228 (ADR-002): re-point email verification at the password credential.
-- `credential_id` is NULLABLE and `user_id` stays NOT NULL on purpose: tokens
-- minted by a pre-#228 binary (or during a rollback window) carry only
-- `user_id`, and readers fall back to the user's password credential.
-- Promotion to NOT NULL and the `user_id` drop belong to #230 — do NOT
-- tighten either here.
ALTER TABLE "email_verification_tokens" ADD COLUMN "credential_id" uuid;--> statement-breakpoint
ALTER TABLE "email_verification_tokens" ADD CONSTRAINT "email_verification_tokens_credential_id_user_credentials_id_fk" FOREIGN KEY ("credential_id") REFERENCES "public"."user_credentials"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_email_verification_tokens_credential_id" ON "email_verification_tokens" USING btree ("credential_id");--> statement-breakpoint
-- Backfill existing tokens from each user's password credential (#226
-- guarantees exactly one per user). Tokens whose user has no credential row
-- (registered after the last backfill run — the deploy runbook's
-- --refresh + --verify-only step exists to prevent this) keep NULL and are
-- served by the reader fallback.
UPDATE "email_verification_tokens" t
SET "credential_id" = uc."id"
FROM "user_credentials" uc
WHERE uc."user_id" = t."user_id"
  AND uc."provider_type" = 'password'
  AND t."credential_id" IS NULL;
