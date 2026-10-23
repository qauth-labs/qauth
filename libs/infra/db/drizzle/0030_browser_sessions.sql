-- #468 (ADR-019 Decision 3): the unused `sessions` table becomes the store for
-- browser sessions. Each row is one account signed in on one browser, tied to
-- one realm and one user; its id is the session's `sid`. `session_clients`
-- records which clients a session served, for back-channel logout.
--
-- No code has ever read or written `sessions`: browser sessions live in Redis.
-- A row in the old shape models a token session (token hashes, one client) and
-- has no authentication time, so it cannot become a browser session. The
-- table is emptied first, which also lets `realm_id` and `auth_time` be added
-- NOT NULL without a default.
DELETE FROM "sessions";--> statement-breakpoint
ALTER TABLE "sessions" DROP CONSTRAINT "sessions_oauth_client_id_oauth_clients_id_fk";
--> statement-breakpoint
DROP INDEX "idx_sessions_active";--> statement-breakpoint
DROP INDEX "idx_sessions_access_token_hash";--> statement-breakpoint
DROP INDEX "idx_sessions_oauth_client_id";--> statement-breakpoint
ALTER TABLE "sessions" DROP COLUMN "oauth_client_id";--> statement-breakpoint
ALTER TABLE "sessions" DROP COLUMN "access_token_hash";--> statement-breakpoint
ALTER TABLE "sessions" DROP COLUMN "refresh_token_hash";--> statement-breakpoint
ALTER TABLE "sessions" DROP COLUMN "revoked";--> statement-breakpoint
ALTER TABLE "sessions" DROP COLUMN "last_activity_at";--> statement-breakpoint
CREATE TABLE "session_clients" (
	"session_id" uuid NOT NULL,
	"oauth_client_id" uuid NOT NULL,
	"first_seen_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "session_clients_pk" PRIMARY KEY("session_id","oauth_client_id")
);
--> statement-breakpoint
ALTER TABLE "sessions" DROP CONSTRAINT "sessions_user_id_users_id_fk";
--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "realm_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "auth_time" bigint NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "amr" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "assurance_level" text;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "revoked_reason" text;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "last_seen_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_id_realm_id_unique" UNIQUE("id","realm_id");--> statement-breakpoint
ALTER TABLE "session_clients" ADD CONSTRAINT "session_clients_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "session_clients" ADD CONSTRAINT "session_clients_oauth_client_id_oauth_clients_id_fk" FOREIGN KEY ("oauth_client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_session_clients_oauth_client_id" ON "session_clients" USING btree ("oauth_client_id");--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_sessions_realm_user_active" ON "sessions" USING btree ("realm_id","user_id") WHERE "sessions"."revoked_at" IS NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_amr_is_array" CHECK (jsonb_typeof("sessions"."amr") = 'array');--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_assurance_level_valid" CHECK ("sessions"."assurance_level" IS NULL OR "sessions"."assurance_level" IN ('substantial', 'high'));--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_revoked_reason_valid" CHECK ("sessions"."revoked_reason" IN ('sign_out', 'sign_out_everywhere', 'admin', 'reset', 'key_retired', 'browser_limit', 'idle', 'expired'));--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_revoked_pair" CHECK (("sessions"."revoked_at" IS NULL) = ("sessions"."revoked_reason" IS NULL));