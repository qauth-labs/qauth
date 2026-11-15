-- #1144 (ADR-017 Decisions 8 and 10, amended 2026-11-15): a registration or a
-- password reset that finishes an authorization interaction signs nobody in,
-- but its code's ID token now carries the `sid` of a logout-only session, so
-- every ending of the account's sessions sends that client a logout token
-- naming it.
--
-- `sessions.kind` says what a row is: `browser` for a browser's sign-in, and
-- `registration` or `reset` for a logout-only session, which no cookie names
-- and the session service never hands out as a browser session.
-- `session_refresh_families` links a logout-only session to the refresh
-- families its codes started, so ending that one session ends them. A table of
-- its own: refresh rows name no session (#549; ADR-014 keeps a refresh-row
-- `sid` for the Authority Tree's grant id).
--
-- One column with a constant default and a new, empty table: Postgres adds
-- the column without rewriting `sessions`, every existing session reads
-- `browser`, and the previous release, which never names either, keeps
-- inserting browser sessions (the default) and refresh tokens (unlinked)
-- during a rolling upgrade. Forward-only: nothing is rewritten.
--
-- The CHECK is added NOT VALID: every row already in `sessions` reads
-- `browser`, which it accepts, so a validating scan could find nothing and
-- would only hold the table's lock while it read it. Every row written or
-- updated from now on is checked. Hand-edited: drizzle-kit models no NOT VALID.
--
-- Order: the migration runs in one transaction and holds every lock to its
-- commit, and nothing in it scans a table. `sessions` is altered first, so its
-- ACCESS EXCLUSIVE lock is taken once, up front: the foreign key's SHARE ROW
-- EXCLUSIVE lock on `sessions`, taken first, would have to be upgraded, and a
-- session revocation holding a row lock while it waits to write could then
-- deadlock with the upgrade. Every statement after it is a catalog change,
-- and the foreign key validates against an empty table.
ALTER TABLE "sessions" ADD COLUMN "kind" text DEFAULT 'browser' NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_kind_valid" CHECK ("sessions"."kind" IN ('browser', 'registration', 'reset')) NOT VALID;--> statement-breakpoint
CREATE TABLE "session_refresh_families" (
	"session_id" uuid NOT NULL,
	"family_id" uuid NOT NULL,
	CONSTRAINT "session_refresh_families_pk" PRIMARY KEY("session_id","family_id")
);
--> statement-breakpoint
ALTER TABLE "session_refresh_families" ADD CONSTRAINT "session_refresh_families_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE cascade ON UPDATE no action;
