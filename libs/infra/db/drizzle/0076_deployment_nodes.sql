-- #499: the node list of the configuration digest check (ADR-019 Decision 8).
-- Every auth server node writes its row once its boot steps succeeded: its
-- service roles, its release, and its configuration digest as a SHA-256
-- digest per compared key and one over them all, never a value. It marks the
-- row seen every 30 seconds and deletes it when it closes cleanly; a row
-- unseen for two minutes no longer counts, and the next booting node removes
-- it. A booting node compares its digest with the live rows of its release.
--
-- A new, empty table: nothing is rewritten, and a release before this one
-- never names it, so it is safe during a rolling upgrade; a node of such a
-- release simply writes no row. Every role's database user gets SELECT,
-- INSERT, UPDATE and DELETE on it from the grants map. Forward-only.
CREATE TABLE "deployment_nodes" (
	"node_id" uuid PRIMARY KEY NOT NULL,
	"roles" text[] NOT NULL,
	"version" varchar(64) NOT NULL,
	"config_digest" varchar(64) NOT NULL,
	"config_keys" jsonb NOT NULL,
	"started_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"last_seen_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "deployment_nodes_roles_not_empty" CHECK (cardinality("deployment_nodes"."roles") > 0),
	CONSTRAINT "deployment_nodes_config_digest_hex" CHECK ("deployment_nodes"."config_digest" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "deployment_nodes_config_keys_object" CHECK (jsonb_typeof("deployment_nodes"."config_keys") = 'object')
);
