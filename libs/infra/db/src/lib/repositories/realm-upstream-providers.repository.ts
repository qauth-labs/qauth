import {
  extractConstraintName,
  isUniqueConstraintError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { and, asc, eq, type InferInsertModel, type InferSelectModel } from 'drizzle-orm';

import type { DbClient } from '../../types';
import { EPOCH_MS_NOW } from '../schema/sql-helpers';
import { realmUpstreamProviders } from '../schema/upstream-providers';

/**
 * The generic upstream OpenID Connect providers of each realm
 * (`realm_upstream_providers`, ADR-020, issue #639). The admin API writes
 * them (#714); the sign-in pages and the upstream callback read them.
 *
 * The repository stores what it is given: the config's client secret is
 * sealed by the caller with the realm's `data_at_rest` key, and its shape is
 * the upstream OIDC package's to check. The table's CHECKs refuse a type, a
 * display name or a config of the wrong form.
 */

/** One provider of a realm. */
export type RealmUpstreamProvider = InferSelectModel<typeof realmUpstreamProviders>;

/** What {@link RealmUpstreamProvidersRepository.create} writes. */
export type NewRealmUpstreamProvider = InferInsertModel<typeof realmUpstreamProviders>;

/** What {@link RealmUpstreamProvidersRepository.update} may change: all but the key. */
export type RealmUpstreamProviderChanges = Partial<
  Pick<
    NewRealmUpstreamProvider,
    'displayName' | 'displayOrder' | 'hidden' | 'enabled' | 'marksVerified' | 'config'
  >
>;

/** The upstream provider repository (#639). */
export interface RealmUpstreamProvidersRepository {
  /** Every provider of the realm, by display order, then type. `[]` for an id that is not a UUID. */
  listByRealm(realmId: string, tx?: DbClient): Promise<RealmUpstreamProvider[]>;
  /** The realm's provider of the type, or `undefined`. */
  find(realmId: string, type: string, tx?: DbClient): Promise<RealmUpstreamProvider | undefined>;
  /**
   * Add a provider to its realm.
   *
   * @throws UniqueConstraintError when the realm already has a provider of
   *   the type.
   */
  create(data: NewRealmUpstreamProvider, tx?: DbClient): Promise<RealmUpstreamProvider>;
  /**
   * Change the realm's provider of the type and stamp `updated_at`.
   *
   * @returns the row as written, or `undefined` when the realm has none.
   */
  update(
    realmId: string,
    type: string,
    changes: RealmUpstreamProviderChanges,
    tx?: DbClient
  ): Promise<RealmUpstreamProvider | undefined>;
  /**
   * Delete the realm's provider of the type.
   *
   * @returns whether a row was deleted.
   */
  delete(realmId: string, type: string, tx?: DbClient): Promise<boolean>;
  /**
   * Whose client the signer signs the realm's provider's client assertions
   * for (#1073): the client id and the algorithm its config names when it
   * authenticates with `private_key_jwt`, read from the realm id, the type,
   * the switch and the config alone, the only columns of the table the
   * signer's database user may read. `undefined` when the realm has no such
   * provider, it is off, or it authenticates with a client secret.
   */
  findAssertionClient(
    realmId: string,
    type: string,
    tx?: DbClient
  ): Promise<UpstreamProviderAssertionClient | undefined>;
}

/** The client a generic provider's client assertions are signed for (#1073). */
export interface UpstreamProviderAssertionClient {
  readonly clientId: string;
  /** The algorithm of the key registered with the provider. */
  readonly algorithm: string;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Refuse a realm id Postgres would refuse with an error (22P02) before it reaches it. */
const isRealmId = (realmId: string) => typeof realmId === 'string' && UUID_PATTERN.test(realmId);

/**
 * Factory for the upstream provider repository (#639).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createRealmUpstreamProvidersRepository(
  defaultDb: DbClient
): RealmUpstreamProvidersRepository {
  const inRealm = (realmId: string, type: string) =>
    and(eq(realmUpstreamProviders.realmId, realmId), eq(realmUpstreamProviders.type, type));

  return {
    async listByRealm(realmId, tx) {
      if (!isRealmId(realmId)) return [];
      return (tx ?? defaultDb)
        .select()
        .from(realmUpstreamProviders)
        .where(eq(realmUpstreamProviders.realmId, realmId))
        .orderBy(asc(realmUpstreamProviders.displayOrder), asc(realmUpstreamProviders.type));
    },

    async findAssertionClient(realmId, type, tx) {
      if (!isRealmId(realmId) || typeof type !== 'string') return undefined;
      const [row] = await (tx ?? defaultDb)
        .select({ config: realmUpstreamProviders.config })
        .from(realmUpstreamProviders)
        .where(and(inRealm(realmId, type), eq(realmUpstreamProviders.enabled, true)))
        .limit(1);
      const config: unknown = row?.config;
      if (typeof config !== 'object' || config === null) return undefined;
      const { clientId, clientAuthentication } = config as Record<string, unknown>;
      if (typeof clientAuthentication !== 'object' || clientAuthentication === null) {
        return undefined;
      }
      const { method, signingAlgorithm } = clientAuthentication as Record<string, unknown>;
      if (
        method !== 'private_key_jwt' ||
        typeof clientId !== 'string' ||
        clientId === '' ||
        typeof signingAlgorithm !== 'string'
      ) {
        return undefined;
      }
      return { clientId, algorithm: signingAlgorithm };
    },

    async find(realmId, type, tx) {
      if (!isRealmId(realmId)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .select()
        .from(realmUpstreamProviders)
        .where(inRealm(realmId, type))
        .limit(1);
      return row;
    },

    async create(data, tx) {
      try {
        const [row] = await (tx ?? defaultDb)
          .insert(realmUpstreamProviders)
          .values(data)
          .returning();
        return row;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint =
            extractConstraintName(error) || 'idx_realm_upstream_providers_realm_type_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    async update(realmId, type, changes, tx) {
      if (!isRealmId(realmId)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .update(realmUpstreamProviders)
        .set({ ...changes, updatedAt: EPOCH_MS_NOW })
        .where(inRealm(realmId, type))
        .returning();
      return row;
    },

    async delete(realmId, type, tx) {
      if (!isRealmId(realmId)) return false;
      const deleted = await (tx ?? defaultDb)
        .delete(realmUpstreamProviders)
        .where(inRealm(realmId, type))
        .returning({ id: realmUpstreamProviders.id });
      return deleted.length > 0;
    },
  };
}
