-- #1144 (ADR-017 Decisions 8 and 10, amended 2026-11-15): a registration or a
-- password reset that finishes an authorization interaction signs nobody in,
-- but its code's ID token now carries the `sid` of a logout-only session, so
-- every ending of the account's sessions sends that client a logout token
-- naming it.
--
-- `sessions.kind` says what a row is: `browser` for a browser's sign-in, and
-- `registration` or `reset` for a logout-only session, which no cookie names
-- and the session service never hands out as a browser session.
-- `refresh_tokens.family_session_id` links a family's first token to the
-- session that backed its code, so ending that one session ends the families
-- its codes started.
--
-- One column with a constant default and one nullable column with no default:
-- Postgres adds both without rewriting either table. Every existing session
-- reads `browser`, and every existing token NULL. The previous release, which
-- never names the columns, keeps inserting browser sessions (the default) and
-- refresh tokens (unlinked) during a rolling upgrade. Forward-only: nothing is
-- rewritten. No foreign key on the link: a purged session leaves an id that
-- names no row and ends nothing.
--
-- The index is partial, so it holds only linked first tokens. The CHECK is
-- added NOT VALID: every row already in `sessions` reads `browser`, which it
-- accepts, so a validating scan could find nothing and would only hold the
-- table's lock while it read it. Every row written or updated from now on is
-- checked. Hand-edited: drizzle-kit models no NOT VALID.
ALTER TABLE "sessions" ADD COLUMN "kind" text DEFAULT 'browser' NOT NULL;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "family_session_id" uuid;--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_family_session_id" ON "refresh_tokens" USING btree ("family_session_id") WHERE "refresh_tokens"."family_session_id" IS NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_kind_valid" CHECK ("sessions"."kind" IN ('browser', 'registration', 'reset')) NOT VALID;
