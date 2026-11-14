import { sql } from 'drizzle-orm';
import { bigint, check, jsonb, pgTable, text, uuid, varchar } from 'drizzle-orm/pg-core';

import { EPOCH_MS_NOW } from './sql-helpers';

/**
 * The auth server nodes that run (ADR-019 Decision 8, issue #499).
 *
 * Every node writes a row once its boot steps succeeded and marks it seen
 * every 30 seconds; it removes the row when it closes cleanly. A row unseen
 * for two minutes is a node that stopped without closing: it no longer
 * counts, and the next node to boot removes it.
 *
 * A booting node compares its configuration digest with the rows of the same
 * release and refuses to start when one differs. A row holds the digest of
 * each compared key, never a value, so a refusal names the keys that differ
 * and nothing either node holds. Times are epoch ms on the database's clock,
 * so the nodes' own clocks never decide whether a node counts.
 *
 * Every role writes its own row and reads the others'. No foreign key: the
 * list belongs to the deployment, not to a realm.
 */
export const deploymentNodes = pgTable(
  'deployment_nodes',
  {
    /** A random id the node takes at each boot. */
    nodeId: uuid('node_id').primaryKey(),
    /** The service roles the node runs (`SERVICE_ROLES`), each by name. */
    roles: text('roles').array().notNull(),
    /** The QAuth release the node runs, such as `0.3.0`; `0.0.0-dev` for a build that is no release. */
    version: varchar('version', { length: 64 }).notNull(),
    /** The SHA-256 digest, in lower-case hex, over every key in `config_keys`. */
    configDigest: varchar('config_digest', { length: 64 }).notNull(),
    /** The SHA-256 digest of each compared key's value, by key name. */
    configKeys: jsonb('config_keys').$type<Record<string, string>>().notNull(),
    /** When the node registered, in epoch ms. */
    startedAt: bigint('started_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    /** When the node was last seen, in epoch ms. */
    lastSeenAt: bigint('last_seen_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    check('deployment_nodes_roles_not_empty', sql`cardinality(${t.roles}) > 0`),
    check('deployment_nodes_config_digest_hex', sql`${t.configDigest} ~ '^[0-9a-f]{64}$'`),
    check('deployment_nodes_config_keys_object', sql`jsonb_typeof(${t.configKeys}) = 'object'`),
  ]
);
