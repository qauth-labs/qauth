-- #549 (ADR-019 Decisions 3 and 4): record the browser session behind each
-- authorization code, so the code exchange can put the session's id in the ID
-- token's `sid` claim, as back-channel logout will name it.
--
-- Forward-only and additive. The column starts NULL for every existing code,
-- and the previous release, which keeps serving on this schema during a
-- rolling upgrade, never writes it: such a code's ID token has no `sid`, as a
-- code from the legacy Bearer path has none. Deleting a session sets the
-- column to NULL and keeps the code; the index serves that ON DELETE SET NULL.
--
-- Locks first, in the order every writer of both tables takes them: a code's
-- mint locks its session `FOR SHARE` and then inserts the code, and a
-- session's revocation updates the session and then spends its codes. ADD
-- COLUMN would take `authorization_codes` first and the foreign key `sessions`
-- second: a revocation that updated its session while the ALTER waited would
-- then wait on the ALTER while the ALTER waited on it, and PostgreSQL would
-- abort one of them as a deadlock, the migration included. SHARE ROW EXCLUSIVE
-- is what ADD FOREIGN KEY takes on the referenced table: reads and `FOR SHARE`
-- go on, writes wait for the runner's commit.
LOCK TABLE "sessions" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "authorization_codes" IN ACCESS EXCLUSIVE MODE;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD COLUMN "session_id" uuid;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_authorization_codes_session_id" ON "authorization_codes" USING btree ("session_id");