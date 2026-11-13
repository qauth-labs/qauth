-- #1064 (ADR-017 Decision 8, amended 2026-11-12): a passkey or an
-- authenticator app bound after a sign-in that proved only the account's
-- password is new for the realm's `accounts.newFactorWindowDays`.
-- `user_credentials.new_until` holds when that window ends, NULL for a
-- credential that never was new; `sessions.new_credential_ids` lists the new
-- credentials a session's sign-in bound or proved, so removing one while it is
-- new ends the sessions it opened, and a sign-in that proved a factor only
-- through a new one is not fresh with the account's strongest factor.
--
-- One nullable column with no default and one column with a constant default:
-- Postgres adds both without rewriting either table. Every existing
-- credential reads NULL (none of them is new) and every existing session `[]`.
-- The previous release, which never names the columns, keeps binding factors
-- and inserting sessions during a rolling upgrade; a factor it binds is never
-- new. Forward-only: nothing is rewritten.
--
-- The CHECK keeps the list an array. It is added NOT VALID: every row already
-- in `sessions` reads `[]`, which it accepts, so a validating scan could find
-- nothing and would only hold the table's lock while it read it. Every row
-- written or updated from now on is checked. Hand-written: drizzle-kit models
-- no NOT VALID, so `db:generate` neither writes nor drops it.
ALTER TABLE "user_credentials" ADD COLUMN "new_until" bigint;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "new_credential_ids" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_new_credential_ids_is_array" CHECK (jsonb_typeof("sessions"."new_credential_ids") = 'array') NOT VALID;
