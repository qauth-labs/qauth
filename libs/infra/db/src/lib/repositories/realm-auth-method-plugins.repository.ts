import { and, asc, eq, sql } from 'drizzle-orm';

import type { DbClient } from '../../types';
import { realmAuthMethodPlugins } from '../schema/auth-method-plugins';
import { EPOCH_MS_NOW } from '../schema/sql-helpers';

/**
 * Each realm's state of each installed AuthMethod plugin (ADR-019 Decisions
 * 10 and 12, issue #600): `realm_auth_method_plugins`. The admin API writes
 * it; the plugin runtime reads it to tell whether a realm has a plugin on and
 * to build the plugin's context from its config.
 *
 * Secrets are stored as the caller hands them: ciphertexts the signer made
 * with the realm's `data_at_rest` key. The table refuses any other form, so
 * a plaintext value fails the write.
 */

/** One realm's state of one plugin. */
export interface RealmAuthMethodPlugin {
  readonly realmId: string;
  readonly pluginId: string;
  readonly enabled: boolean;
  /** The config's plain members. */
  readonly config: Record<string, unknown>;
  /** The ciphertext of each secret member that holds a value, by path. */
  readonly secrets: Record<string, string>;
  /** Raised by one with every write. */
  readonly version: number;
  readonly createdAt: number;
  readonly updatedAt: number;
}

/** What a write sets: the whole state. */
export interface RealmAuthMethodPluginState {
  readonly enabled: boolean;
  readonly config: Readonly<Record<string, unknown>>;
  readonly secrets: Readonly<Record<string, string>>;
}

/**
 * The version a write expects to replace: the row's `version`, or `null` for
 * a plugin the realm has no row for yet.
 */
export type RealmAuthMethodPluginExpectedVersion = number | null;

/** The realm plugin repository (#600). */
export interface RealmAuthMethodPluginsRepository {
  /** Every row of the realm, by plugin id. `[]` for an id that is not a UUID. */
  listByRealm(realmId: string, tx?: DbClient): Promise<RealmAuthMethodPlugin[]>;
  /** The realm's row for the plugin, or `undefined`. */
  find(
    realmId: string,
    pluginId: string,
    tx?: DbClient
  ): Promise<RealmAuthMethodPlugin | undefined>;
  /**
   * Write the realm's state of the plugin, when its row is still at
   * `expectedVersion`: a new row at version 1 for `null` (when none exists
   * yet), otherwise the row at that version, raised by one. Answers the
   * written row, or `undefined` when the row is at another version or (for
   * `null`) already exists: the caller answers 412.
   */
  save(
    realmId: string,
    pluginId: string,
    state: RealmAuthMethodPluginState,
    expectedVersion: RealmAuthMethodPluginExpectedVersion,
    tx?: DbClient
  ): Promise<RealmAuthMethodPlugin | undefined>;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The AuthMethod id rule (`AUTH_METHOD_ID_PATTERN`), which the table's CHECK holds too. */
const PLUGIN_ID_PATTERN = /^[a-z][a-z0-9_-]{0,62}$/;

/** Refuse a key Postgres would refuse with an error (22P02) before it reaches it. */
const isKey = (realmId: string, pluginId: string) =>
  typeof realmId === 'string' &&
  UUID_PATTERN.test(realmId) &&
  typeof pluginId === 'string' &&
  PLUGIN_ID_PATTERN.test(pluginId);

/** A plain copy of a state's objects, so the caller's are never stored by reference. */
const plain = <T>(value: T): T => structuredClone(value);

/**
 * Factory for the realm plugin repository (#600).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createRealmAuthMethodPluginsRepository(
  defaultDb: DbClient
): RealmAuthMethodPluginsRepository {
  return {
    async listByRealm(realmId, tx) {
      if (typeof realmId !== 'string' || !UUID_PATTERN.test(realmId)) return [];
      return (tx ?? defaultDb)
        .select()
        .from(realmAuthMethodPlugins)
        .where(eq(realmAuthMethodPlugins.realmId, realmId))
        .orderBy(asc(realmAuthMethodPlugins.pluginId));
    },

    async find(realmId, pluginId, tx) {
      if (!isKey(realmId, pluginId)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .select()
        .from(realmAuthMethodPlugins)
        .where(
          and(
            eq(realmAuthMethodPlugins.realmId, realmId),
            eq(realmAuthMethodPlugins.pluginId, pluginId)
          )
        )
        .limit(1);
      return row;
    },

    async save(realmId, pluginId, state, expectedVersion, tx) {
      if (!isKey(realmId, pluginId)) return undefined;
      const invoker = tx ?? defaultDb;
      const values = {
        enabled: state.enabled === true,
        config: plain({ ...state.config }),
        secrets: plain({ ...state.secrets }),
      };
      if (expectedVersion === null) {
        const [created] = await invoker
          .insert(realmAuthMethodPlugins)
          .values({ realmId, pluginId, ...values })
          .onConflictDoNothing()
          .returning();
        return created;
      }
      if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) return undefined;
      const [updated] = await invoker
        .update(realmAuthMethodPlugins)
        .set({
          ...values,
          version: sql`${realmAuthMethodPlugins.version} + 1`,
          updatedAt: EPOCH_MS_NOW,
        })
        .where(
          and(
            eq(realmAuthMethodPlugins.realmId, realmId),
            eq(realmAuthMethodPlugins.pluginId, pluginId),
            eq(realmAuthMethodPlugins.version, expectedVersion)
          )
        )
        .returning();
      return updated;
    },
  };
}
