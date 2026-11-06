-- #655 (ADR-017 Decision 8, question 30): an account whose primary identity is
-- a passkey has no address, so when its passkey is lost a recovery code is the
-- only thing that can name it. `user_recovery_codes.lookup_digest` holds each
-- code's lookup digest for such an account's sets alone: a slow hash
-- (Argon2id) of the normalized code under a salt of the realm, the same for
-- the same code, so the sign-in's first offer can find the account by the code
-- before any first factor. The code is then checked against the row's salted
-- `code_hash`, as before. Every other set leaves it NULL, and its codes are
-- found only after a first factor named the account.
--
-- One nullable column with no default, so every existing row reads NULL: no
-- account with no address exists before this release, which is the first to
-- register one. The previous release never names the column, and its writes
-- leave it NULL, during a rolling upgrade. The partial index serves the lookup
-- of an unused code by its digest; the CHECK keeps "no digest" one value.
-- Forward-only: nothing is rewritten.
ALTER TABLE "user_recovery_codes" ADD COLUMN "lookup_digest" text;--> statement-breakpoint
CREATE INDEX "idx_user_recovery_codes_lookup" ON "user_recovery_codes" USING btree ("realm_id","lookup_digest") WHERE "user_recovery_codes"."lookup_digest" IS NOT NULL AND "user_recovery_codes"."used_at" IS NULL;--> statement-breakpoint
ALTER TABLE "user_recovery_codes" ADD CONSTRAINT "user_recovery_codes_lookup_digest_not_empty" CHECK ("user_recovery_codes"."lookup_digest" IS NULL OR length("user_recovery_codes"."lookup_digest") > 0);