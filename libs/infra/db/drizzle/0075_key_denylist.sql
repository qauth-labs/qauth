-- #551: the kid denylist of emergency key retirement (ADR-019 Decision 9).
-- A key that may be compromised is marked `compromised` in realm_keys, and its
-- `kid` gets a row here in the same transaction. Only the signer reads
-- realm_keys, and every process caches its key lists for a minute, so every
-- role reads this table instead (through a Redis copy and memory, every few
-- seconds) and refuses a token its key signed at once, whatever its key cache
-- holds; a node that cannot read it for 30 seconds refuses every token.
--
-- A new, empty table: nothing is rewritten, and a release before this one
-- never names it, so it is safe during a rolling upgrade. No row is ever
-- removed but with its realm, and no foreign key ties a row to its key row, so
-- a denied `kid` stays denied once its key is gone. Forward-only.
CREATE TABLE "realm_key_denylist" (
	"realm_id" uuid NOT NULL,
	"kid" varchar(255) NOT NULL,
	"purpose" varchar(64) NOT NULL,
	"algorithm" varchar(32) NOT NULL,
	"denied_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "realm_key_denylist_pk" PRIMARY KEY("realm_id","kid")
);
--> statement-breakpoint
ALTER TABLE "realm_key_denylist" ADD CONSTRAINT "realm_key_denylist_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;