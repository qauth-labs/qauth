-- #498 (ADR-019 Decisions 8 and 9): the read the SSF subject sweep (#540)
-- needs from the event store, as a function, so the role that runs the sweep
-- (api) holds no SELECT on events, event_delivery_positions or
-- event_deliveries' events. With SELECT on events it could read every realm's
-- events: request IPs, user agents, and admin diffs that hold personal data.
--
-- ssf_subject_events_pending: whether an event about the user a stream's
-- subject names can still reach that stream: an event about the user that
-- the realm's SSF fan-out has not passed yet, or a delivery to the stream
-- about the user that is still pending (held, queued or retrying). The realm
-- is the stream's own. It shows a boolean and nothing of the events.
--
-- SECURITY DEFINER: it reads the tables as their owner. Its search_path is
-- pinned, and EXECUTE is revoked from PUBLIC; the per-role grants give it to
-- the api role alone. STABLE, so it reads with the snapshot of the statement
-- that calls it, as the subqueries it replaces did.
CREATE FUNCTION "ssf_subject_events_pending"(p_stream_id uuid, p_subject_id text) RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public."ssf_streams" s
      JOIN public."events" e ON e."realm_id" = s."realm_id"
      JOIN public."event_delivery_positions" p
        ON p."realm_id" = e."realm_id" AND p."destination_kind" = 'ssf'
     WHERE s."id" = p_stream_id
       AND e."subject_type" = 'user'
       AND e."subject_id" = p_subject_id
       AND (e."xid", e."seq") > (p."xid", p."seq")
  ) OR EXISTS (
    SELECT 1
      FROM public."event_deliveries" d
      JOIN public."events" e ON e."id" = d."event_id"
     WHERE d."destination_kind" = 'ssf'
       AND d."destination_id" = p_stream_id::text
       AND d."status" = 'pending'
       AND e."subject_type" = 'user'
       AND e."subject_id" = p_subject_id
  )
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "ssf_subject_events_pending"(uuid, text) FROM PUBLIC;
