-- #627 (ADR-017 Decision 10): link each refresh-token family to the
-- authorization code whose redemption started it, so a second redemption of
-- that code can find the family and revoke it (OAuth 2.1 §4.1.3).
--
-- Forward-only and additive. The column starts NULL for every existing token:
-- a family started before this migration has no recorded code, so a replay of
-- its code is still refused but revokes nothing. The previous release, which
-- keeps serving on this schema during a rolling upgrade, never writes the
-- column; its tokens stay unlinked the same way.
--
-- Only the first token of a family carries the link, so the index is unique: a
-- code starts one family at most. It is also what the purge job's code deletes
-- read for ON DELETE SET NULL, which would otherwise scan refresh_tokens once
-- per deleted code.
ALTER TABLE "refresh_tokens" ADD COLUMN "authorization_code_id" uuid;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_authorization_code_id_authorization_codes_id_fk" FOREIGN KEY ("authorization_code_id") REFERENCES "public"."authorization_codes"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_refresh_tokens_authorization_code_id" ON "refresh_tokens" USING btree ("authorization_code_id") WHERE "refresh_tokens"."authorization_code_id" IS NOT NULL;