-- #662 (ADR-017 Decision 10, ADR-020 §3): how and when the user signed in, on
-- the tokens of a browser sign-in. `authorization_codes.amr` holds the RFC 8176
-- methods the browser session proved, copied at mint time beside the code's
-- existing `auth_time`; `refresh_tokens.auth_time` and `refresh_tokens.amr`
-- hold the code's two values for its refresh family, and every rotation copies
-- them, so a refresh never makes a sign-in look fresher (RFC 9068 §2.2.1).
--
-- Three new nullable columns with no default, so every existing row reads
-- NULL: a code or a family from before carries no `amr`, and a family no
-- `auth_time` on its access tokens. The previous release, which never names
-- the columns, keeps working during a rolling upgrade; a token it rotates
-- meanwhile loses both values, so its family's later tokens carry neither
-- claim and an operation that asks for a fresh sign-in asks for one.
-- Forward-only: nothing is rewritten.
--
-- The CHECKs keep `amr` NULL or a non-empty list, and only beside an
-- `auth_time`, so "no method" has one representation, and an `auth_time`
-- positive. They are added NOT VALID: every row already in either table reads
-- NULL in the new columns, which each CHECK accepts, so a validating scan
-- could find nothing and would only hold both tables' locks while it read
-- them. Every row written or updated from now on is checked. Hand-written:
-- drizzle-kit models no NOT VALID, so `db:generate` neither writes nor drops
-- it.
--
-- Locks first, in the order every writer of both tables takes them, as 0041
-- does: a redemption, on either release, spends its code in
-- `authorization_codes` and then inserts into `refresh_tokens`, and a consent
-- revocation and a logout do the same. Taking `refresh_tokens` first would let
-- a redemption that spent its code while the migration waited deadlock with
-- it.
LOCK TABLE "authorization_codes" IN ACCESS EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "refresh_tokens" IN ACCESS EXCLUSIVE MODE;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD COLUMN "amr" jsonb;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "auth_time" bigint;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "amr" jsonb;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_amr_valid" CHECK ("authorization_codes"."amr" IS NULL OR ("authorization_codes"."auth_time" IS NOT NULL AND jsonb_typeof("authorization_codes"."amr") = 'array' AND "authorization_codes"."amr" <> '[]'::jsonb)) NOT VALID;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_auth_time_positive" CHECK ("refresh_tokens"."auth_time" IS NULL OR "refresh_tokens"."auth_time" > 0) NOT VALID;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_amr_valid" CHECK ("refresh_tokens"."amr" IS NULL OR ("refresh_tokens"."auth_time" IS NOT NULL AND jsonb_typeof("refresh_tokens"."amr") = 'array' AND "refresh_tokens"."amr" <> '[]'::jsonb)) NOT VALID;