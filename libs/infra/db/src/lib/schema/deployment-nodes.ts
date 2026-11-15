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
 * No role writes the table: every role registers, marks seen, removes and
 * lists its node through the functions of migration 0077, which set the
 * times from the database's clock, check every value, and change only a row
 * the caller's own database user registered. A role's user holds `EXECUTE`
 * on them and nothing on the table, so even a compromised process can
 * neither date a row into the future nor remove another role's node. No
 * foreign key: the list belongs to the deployment, not to a realm.
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
    /**
     * The database user that registered the node: only that user marks it
     * seen or removes it.
     */
    registeredBy: text('registered_by')
      .notNull()
      .default(sql`session_user`),
  },
  (t) => [
    check('deployment_nodes_roles_not_empty', sql`cardinality(${t.roles}) > 0`),
    check(
      'deployment_nodes_roles_known',
      sql`${t.roles} <@ ARRAY['web', 'api', 'admin', 'signer', 'delivery']::text[]`
    ),
    check(
      'deployment_nodes_version_format',
      sql`${t.version} ~ '^[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.]+)?$'`
    ),
    check('deployment_nodes_config_digest_hex', sql`${t.configDigest} ~ '^[0-9a-f]{64}$'`),
    // An object of at most 512 key digests, each a key name and a 64-hex
    // digest: the function migration 0077 creates before the table.
    check(
      'deployment_nodes_config_keys_valid',
      sql`deployment_nodes_config_keys_valid(${t.configKeys})`
    ),
  ]
);
