import { sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { realms } from './core';
import { EPOCH_MS_NOW, JSONB_EMPTY_OBJECT } from './sql-helpers';

/**
 * Each realm's state of each installed AuthMethod plugin (ADR-019 Decisions
 * 10 and 12, issue #600): whether the realm has it on, and its config. One
 * row per realm and plugin, written by the admin API; a plugin a realm never
 * configured has no row, and is off there.
 *
 * - `plugin_id` is the plugin's AuthMethod `id`, the stable name of its
 *   implementation, not the package it came from: a new version of the
 *   package keeps the row.
 * - `config` holds the config's plain members, never a secret one.
 * - `secrets` maps the path of each secret member that holds a value
 *   (`clientSecret`, `mtls.keyPassword`) to its ciphertext, encrypted with
 *   the realm's `data_at_rest` key (`v1.<kid>.<iv>.<ciphertext>`), never in
 *   the clear. A cleared secret has no entry.
 * - `version` rises by one with every write: the admin API's entity tag, so
 *   two admins cannot overwrite each other's change unseen.
 *
 * Deleting the realm deletes its rows. A plugin removed from the deployment
 * keeps its rows, which nothing reads until it is installed again.
 */
export const realmAuthMethodPlugins = pgTable(
  'realm_auth_method_plugins',
  {
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The plugin's AuthMethod `id`. */
    pluginId: varchar('plugin_id', { length: 63 }).notNull(),
    /** Whether the realm offers the plugin. */
    enabled: boolean('enabled').notNull().default(false),
    /** The config's plain members, as the plugin's schema takes them. */
    config: jsonb('config').$type<Record<string, unknown>>().notNull().default(JSONB_EMPTY_OBJECT),
    /** The ciphertext of each secret member that holds a value, by its path. */
    secrets: jsonb('secrets').$type<Record<string, string>>().notNull().default(JSONB_EMPTY_OBJECT),
    /** Raised by one with every write. */
    version: integer('version').notNull().default(1),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    primaryKey({ columns: [t.realmId, t.pluginId], name: 'realm_auth_method_plugins_pkey' }),
    // The AuthMethod id rule of the contract (`AUTH_METHOD_ID_PATTERN`).
    check(
      'realm_auth_method_plugins_plugin_id_form',
      sql`${t.pluginId} ~ '^[a-z][a-z0-9_-]{0,62}$'`
    ),
    check('realm_auth_method_plugins_config_object', sql`jsonb_typeof(${t.config}) = 'object'`),
    check('realm_auth_method_plugins_secrets_object', sql`jsonb_typeof(${t.secrets}) = 'object'`),
    // Every secret is a data-at-rest ciphertext, `v1.<kid>.<iv>.<ciphertext>`:
    // a value of any other form would be one stored in the clear.
    check(
      'realm_auth_method_plugins_secrets_ciphertext',
      sql`NOT jsonb_path_exists(${t.secrets}, 'strict $.* ? (@.type() != "string" || !(@ like_regex "^v1[.][^.]+[.][^.]+[.][^.]+$"))')`
    ),
    check('realm_auth_method_plugins_version_positive', sql`${t.version} > 0`),
  ]
);
