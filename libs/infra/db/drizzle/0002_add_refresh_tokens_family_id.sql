-- Adds `family_id` column + index to refresh_tokens for OAuth 2.1 §4.3.1
-- refresh-token rotation with family-wide replay detection (RFC 9700 §2.2.2).
--
-- Every rotation preserves the same family_id; when a revoked refresh token
-- is replayed, the whole family is revoked in a single UPDATE.
ALTER TABLE "refresh_tokens"
  ADD COLUMN "family_id" uuid NOT NULL DEFAULT uuidv7();
--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_family_id"
  ON "refresh_tokens" USING btree ("family_id");
