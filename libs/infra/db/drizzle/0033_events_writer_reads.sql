-- #827 (ADR-019 Decision 7): the two reads a role that writes events needs,
-- as functions, so the role holds INSERT on events and EXECUTE on these two,
-- and no SELECT. With SELECT on the table a writer could read every realm's
-- events: request IPs, user agents, and admin diffs that hold personal data.
--
-- Both are SECURITY DEFINER: they read the table as its owner and return only
-- what the writer needs. Their search_path is pinned, and EXECUTE is revoked
-- from PUBLIC; `eventsWriterGrantStatements` grants it to a writing role.
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
-- returned; a transaction that has written nothing has no id and gets none.
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
REVOKE ALL ON FUNCTION "events_own_row"(uuid) FROM PUBLIC;
