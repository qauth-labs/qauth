-- #827 (ADR-019 Decision 7): the three reads a role that writes events
-- needs, as functions, so the role holds INSERT on events and EXECUTE on
-- these three, and no SELECT. With SELECT on the table a writer could read every realm's
-- events: request IPs, user agents, and admin diffs that hold personal data.
-- And a trigger that keeps a row's xid the inserting transaction's (last).
--
-- The three read functions are SECURITY DEFINER: they read the table as its
-- owner and return only what the writer needs. Their search_path is pinned,
-- and EXECUTE is revoked from PUBLIC; `eventsWriterGrantStatements` grants it
-- to a writing role.
--
-- events_admin_chain_head: the hash of the realm's newest admin row, the
-- chain head an admin event follows, or NULL when the realm has none. The
-- writer calls it while it holds the realm's chain lock. It shows a hash and
-- nothing the hash covers.
CREATE FUNCTION "events_admin_chain_head"(p_realm_id uuid) RETURNS bytea
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT e."hash"
    FROM public."events" e
    WHERE e."realm_id" = p_realm_id AND e."hash" IS NOT NULL
    ORDER BY e."seq" DESC
    LIMIT 1
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "events_admin_chain_head"(uuid) FROM PUBLIC;--> statement-breakpoint
-- events_own_row: the row with this id, only when the calling transaction
-- wrote it, so the writer can check that the row it inserted hashes as it
-- was written. A row of any other transaction, committed or not, is not
-- returned (the trigger below keeps every row's xid its writer's); a
-- transaction that has written nothing has no id and gets none.
CREATE FUNCTION "events_own_row"(p_id uuid) RETURNS SETOF public."events"
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT e.*
    FROM public."events" e
    WHERE e."id" = p_id AND e."xid" = pg_current_xact_id_if_assigned()
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "events_own_row"(uuid) FROM PUBLIC;--> statement-breakpoint
-- events_oldest_unread_time: when the oldest event a reader cannot see yet
-- was written (epoch ms), or NULL when no committed event is held back: the
-- event store's lag, which the auth server, a writer, reports on /metrics.
-- It shows a time and nothing of the event. Postgres 18 answers it from
-- idx_events_realm_position with a skip scan, one descent per realm.
CREATE FUNCTION "events_oldest_unread_time"() RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT min(e."time")
    FROM public."events" e
    WHERE e."xid" >= pg_snapshot_xmin(pg_current_snapshot())
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "events_oldest_unread_time"() FROM PUBLIC;--> statement-breakpoint
-- events_xid_from_transaction: a row's xid is the transaction that inserts
-- it, never a value the writer supplies. Readers take rows in (xid, seq)
-- order below their snapshot's xmin, so a row inserted with an older xid
-- would land behind a reader's position and never be read, and an admin row
-- hashed over that xid would still verify. The column default sets it; the
-- trigger refuses any other value, for every role whose statements fire it.
-- pg_current_xact_id() is the top-level transaction's, in a savepoint too.
CREATE FUNCTION "events_xid_from_transaction"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW."xid" IS DISTINCT FROM pg_current_xact_id() THEN
    RAISE EXCEPTION 'event % sets xid %, not the id of the transaction that inserts it', NEW."id", NEW."xid"
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'events_xid_from_transaction',
            HINT = 'xid is the database''s; insert without it.';
  END IF;
  RETURN NEW;
END;
$$;--> statement-breakpoint
CREATE TRIGGER "events_xid_from_transaction"
  BEFORE INSERT ON "events"
  FOR EACH ROW
  EXECUTE FUNCTION "events_xid_from_transaction"();
