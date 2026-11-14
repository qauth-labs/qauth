-- #499: the node list of the configuration digest check (ADR-019 Decision 8).
-- Every auth server node registers its row once its boot steps succeeded: its
-- service roles, its release, and its configuration digest as a SHA-256
-- digest per compared key and one over them all, never a value. It marks the
-- row seen every 30 seconds and removes it when it closes cleanly; a row
-- unseen for two minutes no longer counts, and the next registration removes
-- it. A booting node compares its digest with the live rows of its release.
--
-- No role holds anything on the table. Every role registers, marks seen,
-- removes and lists its node through the four SECURITY DEFINER functions
-- below, whose EXECUTE is revoked from PUBLIC and given to every role by the
-- grants map:
--
-- - the times are the database's clock, never a value the caller sends, so
--   no row can be dated into the future and stay live;
-- - a node is marked seen or removed only by the database user that
--   registered it (registered_by), so one role cannot remove another's node,
--   nor keep it listed;
-- - a registration removes only rows unseen for at least two minutes;
-- - every value is checked by the table's CHECKs: known role names, a
--   release version, hex digests, and at most 512 key digests named as
--   configuration keys, so another node's row carries nothing a refusal or a
--   log line could not print as it is.
--
-- Their search_path is pinned. A new, empty table: nothing is rewritten, and
-- a release before this one never names it, so it is safe during a rolling
-- upgrade; a node of such a release writes no row. Custom past the table:
-- drizzle-kit models no function. Forward-only.
-- What config_keys holds: an object of at most 512 entries, each a key name
-- and the 64-hex digest of its value. Immutable, reading nothing but its
-- argument; the table's CHECK calls it, so it exists first.
CREATE FUNCTION "deployment_nodes_config_keys_valid"(p_keys jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT jsonb_typeof(p_keys) = 'object'
     AND (SELECT count(*) FROM jsonb_each(p_keys)) <= 512
     AND NOT EXISTS (
       SELECT 1
         FROM jsonb_each(p_keys) AS e
        WHERE e.key !~ '^[A-Z][A-Z0-9_]{0,127}$'
           OR jsonb_typeof(e.value) <> 'string'
           OR (e.value #>> '{}') !~ '^[0-9a-f]{64}$'
     )
$$;--> statement-breakpoint
CREATE TABLE "deployment_nodes" (
	"node_id" uuid PRIMARY KEY NOT NULL,
	"roles" text[] NOT NULL,
	"version" varchar(64) NOT NULL,
	"config_digest" varchar(64) NOT NULL,
	"config_keys" jsonb NOT NULL,
	"started_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"last_seen_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"registered_by" text DEFAULT session_user NOT NULL,
	CONSTRAINT "deployment_nodes_roles_not_empty" CHECK (cardinality("deployment_nodes"."roles") > 0),
	CONSTRAINT "deployment_nodes_roles_known" CHECK ("deployment_nodes"."roles" <@ ARRAY['web', 'api', 'admin', 'signer', 'delivery']::text[]),
	CONSTRAINT "deployment_nodes_version_format" CHECK ("deployment_nodes"."version" ~ '^[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.]+)?$'),
	CONSTRAINT "deployment_nodes_config_digest_hex" CHECK ("deployment_nodes"."config_digest" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "deployment_nodes_config_keys_valid" CHECK (deployment_nodes_config_keys_valid("deployment_nodes"."config_keys"))
);
--> statement-breakpoint
-- The nodes seen within the last p_window_ms, oldest registration first.
CREATE FUNCTION "deployment_nodes_live"(p_window_ms bigint)
RETURNS SETOF public."deployment_nodes"
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT n.*
    FROM public."deployment_nodes" n
   WHERE n."last_seen_at" >= (EXTRACT(EPOCH FROM NOW())::bigint * 1000) - p_window_ms
   ORDER BY n."started_at", n."node_id"
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "deployment_nodes_live"(bigint) FROM PUBLIC;--> statement-breakpoint
-- Register a node, under the list's advisory lock, which the caller's
-- transaction already holds while it compares the live nodes: remove the
-- rows unseen for p_window_ms, never less than two minutes, and insert the
-- node, registered by the caller's database user at the database's time.
CREATE FUNCTION "deployment_nodes_register"(
  p_node_id uuid,
  p_roles text[],
  p_version text,
  p_config_digest text,
  p_config_keys jsonb,
  p_window_ms bigint
)
RETURNS SETOF public."deployment_nodes"
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT pg_advisory_xact_lock(hashtextextended('qauth:deployment-nodes', 0));
  DELETE FROM public."deployment_nodes"
   WHERE "last_seen_at" < (EXTRACT(EPOCH FROM NOW())::bigint * 1000) - greatest(p_window_ms, 120000);
  INSERT INTO public."deployment_nodes"
    ("node_id", "roles", "version", "config_digest", "config_keys", "registered_by")
  VALUES (p_node_id, p_roles, p_version, p_config_digest, p_config_keys, session_user)
  RETURNING *;
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "deployment_nodes_register"(uuid, text[], text, text, jsonb, bigint) FROM PUBLIC;--> statement-breakpoint
-- Mark a node seen at the database's time: 'seen' when its row was there,
-- 'restored' when it was gone and is written again, with its registration
-- time but never a later one than now, and NULL when the row is another
-- database user's, which it leaves as it is.
CREATE FUNCTION "deployment_nodes_heartbeat"(
  p_node_id uuid,
  p_roles text[],
  p_version text,
  p_config_digest text,
  p_config_keys jsonb,
  p_started_at bigint
)
RETURNS text
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  INSERT INTO public."deployment_nodes" AS n
    ("node_id", "roles", "version", "config_digest", "config_keys", "started_at", "registered_by")
  VALUES (
    p_node_id, p_roles, p_version, p_config_digest, p_config_keys,
    least(greatest(p_started_at, 0), EXTRACT(EPOCH FROM NOW())::bigint * 1000),
    session_user
  )
  ON CONFLICT ("node_id") DO UPDATE
    SET "last_seen_at" = EXTRACT(EPOCH FROM NOW())::bigint * 1000
    WHERE n."registered_by" = session_user
  -- xmax is 0 on a row the statement inserted, and set on one it updated.
  RETURNING CASE WHEN n.xmax = 0 THEN 'restored' ELSE 'seen' END
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "deployment_nodes_heartbeat"(uuid, text[], text, text, jsonb, bigint) FROM PUBLIC;--> statement-breakpoint
-- Remove a node the caller's database user registered; how many rows went.
CREATE FUNCTION "deployment_nodes_remove"(p_node_id uuid)
RETURNS integer
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  WITH removed AS (
    DELETE FROM public."deployment_nodes"
     WHERE "node_id" = p_node_id
       AND "registered_by" = session_user
    RETURNING 1
  )
  SELECT count(*)::integer FROM removed
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "deployment_nodes_remove"(uuid) FROM PUBLIC;
