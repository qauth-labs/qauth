ALTER TABLE "events" ADD COLUMN "prev_hash" "bytea";--> statement-breakpoint
ALTER TABLE "events" ADD COLUMN "hash" "bytea";--> statement-breakpoint
CREATE UNIQUE INDEX "idx_events_chain_link" ON "events" USING btree ("realm_id","prev_hash") WHERE "events"."prev_hash" is not null;--> statement-breakpoint
CREATE INDEX "idx_events_chain_order" ON "events" USING btree ("realm_id","seq") WHERE "events"."hash" is not null;--> statement-breakpoint
ALTER TABLE "events" ADD CONSTRAINT "events_chain_hashes_paired" CHECK (("events"."prev_hash" is null) = ("events"."hash" is null));--> statement-breakpoint
ALTER TABLE "events" ADD CONSTRAINT "events_prev_hash_sha256" CHECK ("events"."prev_hash" is null or octet_length("events"."prev_hash") = 32);--> statement-breakpoint
ALTER TABLE "events" ADD CONSTRAINT "events_hash_sha256" CHECK ("events"."hash" is null or octet_length("events"."hash") = 32);--> statement-breakpoint
ALTER TABLE "events" ADD CONSTRAINT "events_admin_chained" CHECK (("events"."category" = 'admin') = ("events"."hash" is not null)) NOT VALID;--> statement-breakpoint
-- Hand-written above and below: drizzle-kit models neither NOT VALID nor
-- functions and triggers, so `db:generate` neither writes nor drops them.
--
-- `events_admin_chained` is added NOT VALID: an admin row written before this
-- migration keeps no hash and is not checked, and every row inserted from now
-- on is. Such rows are the client suspensions and suspension lifts migration
-- 0031 copied from audit_logs; they stay outside the chain.
--
-- No row of the event store is updated (ADR-019 Decision 7, #459). The
-- trigger runs for every role whose statements fire it, the owner included,
-- and refuses the statement before it touches a row, so an UPDATE that would
-- match nothing is refused too. A table owner or a superuser can still
-- disable the trigger; the hash chain then shows what they changed in an
-- admin row. Deletes are left to the grants: only the retention job's role
-- (#536) is granted DELETE.
CREATE FUNCTION "events_no_update"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'events is append-only: UPDATE refused'
    USING ERRCODE = 'check_violation',
          CONSTRAINT = 'events_no_update',
          HINT = 'An event is never changed. Emit a new event instead.';
END;
$$;--> statement-breakpoint
CREATE TRIGGER "events_no_update"
  BEFORE UPDATE ON "events"
  FOR EACH STATEMENT
  EXECUTE FUNCTION "events_no_update"();
--> statement-breakpoint
-- An admin row joins its realm's chain only at the head (#459): its prev_hash
-- is the hash of the realm's newest admin row, or 32 zero bytes for the
-- first, and its seq comes from the identity. The writers do this already;
-- the trigger holds a role that can INSERT to it, so no inserted row can make
-- itself the head of a realm forever (a supplied seq past every other) or
-- join the chain at a hash that is not the head. A raced writer still meets
-- idx_events_chain_link. SECURITY DEFINER, because a writer holds no grant on
-- the identity's sequence. EXECUTE is revoked from PUBLIC below, so no role
-- calls the function directly; the trigger still fires for every insert.
CREATE FUNCTION "events_admin_follows_head"() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_last bigint;
  v_head bytea;
BEGIN
  SELECT s."last_value" INTO v_last FROM public."events_seq_seq" s;
  IF NEW."seq" > v_last THEN
    RAISE EXCEPTION 'admin event % sets seq % past the identity', NEW."id", NEW."seq"
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'events_seq_from_identity',
            HINT = 'seq is the identity''s; insert without it.';
  END IF;
  SELECT e."hash" INTO v_head
    FROM public."events" e
    WHERE e."realm_id" = NEW."realm_id" AND e."hash" IS NOT NULL
    ORDER BY e."seq" DESC LIMIT 1;
  IF NOT FOUND THEN
    v_head := decode(repeat('00', 32), 'hex');
  END IF;
  IF NEW."prev_hash" IS DISTINCT FROM v_head THEN
    RAISE EXCEPTION 'admin event % of realm % does not follow the chain head', NEW."id", NEW."realm_id"
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'events_admin_follows_head',
            HINT = 'Emit admin events through emit or emitAdminEvent, which take the realm''s chain lock.';
  END IF;
  RETURN NEW;
END;
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "events_admin_follows_head"() FROM PUBLIC;--> statement-breakpoint
CREATE TRIGGER "events_admin_follows_head"
  BEFORE INSERT ON "events"
  FOR EACH ROW
  WHEN (NEW."hash" IS NOT NULL)
  EXECUTE FUNCTION "events_admin_follows_head"();
