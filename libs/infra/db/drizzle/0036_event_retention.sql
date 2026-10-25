-- Event retention (#536, ADR-020 §3, ADR-019 Decisions 7 and 10).
--
-- event_chain_anchors: where each realm's admin chain starts once the
-- retention job has deleted its oldest admin rows. The job writes it in the
-- transaction that deletes them; verifyChain starts from it.
--
-- realms gains the two retention days, a realm policy. A constant DEFAULT
-- with NOT NULL rewrites no row (Postgres 11 and later); every existing realm
-- keeps user events 90 days and admin events 365. The CHECKs hold the limits
-- of eventRetentionProblems: admin events are never kept fewer than 90 days.
--
-- idx_events_retention replaces idx_events_time, which no query used: the
-- job reads one realm's rows of one category, oldest first, and the oldest
-- row of each category takes one descent per realm. events has been in no
-- release yet, so the new index builds over few rows.
--
-- Only the retention role deletes from events (eventRetentionGrantStatements);
-- the grants are the topology area's to apply.
CREATE TABLE "event_chain_anchors" (
	"realm_id" uuid PRIMARY KEY NOT NULL,
	"seq" bigint NOT NULL,
	"hash" "bytea" NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "event_chain_anchors_seq_positive" CHECK ("event_chain_anchors"."seq" >= 1),
	CONSTRAINT "event_chain_anchors_hash_sha256" CHECK (octet_length("event_chain_anchors"."hash") = 32)
);
--> statement-breakpoint
DROP INDEX "idx_events_time";--> statement-breakpoint
ALTER TABLE "realms" ADD COLUMN "user_event_retention_days" integer DEFAULT 90 NOT NULL;--> statement-breakpoint
ALTER TABLE "realms" ADD COLUMN "admin_event_retention_days" integer DEFAULT 365 NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_events_retention" ON "events" USING btree ("realm_id","category","time");--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_user_event_retention_days_range" CHECK ("realms"."user_event_retention_days" between 1 and 36500);--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_admin_event_retention_days_range" CHECK ("realms"."admin_event_retention_days" between 90 and 36500);