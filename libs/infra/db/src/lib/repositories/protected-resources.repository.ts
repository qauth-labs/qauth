import { and, asc, desc, eq, lt, or, sql } from 'drizzle-orm';

import type { DbClient } from '../../types';
import type { KeysetPage } from '../../types/repository';
import { protectedResources, type ProtectedResourceScope } from '../schema/protected-resources';
import { EPOCH_MS_NOW } from '../schema/sql-helpers';

/**
 * The protected resources of a realm (#1087): `protected_resources`. The
 * admin API and the seed manifest write them; every path that grants a
 * user's scopes reads the realm's list, the authorization endpoint, the
 * consent step and the token endpoint's code and refresh grants.
 *
 * The repository stores what it is given: the writers check the resource
 * indicator, the scopes and their texts before they call it. The table's
 * CHECKs hold the shapes besides.
 */

/** One protected resource of a realm. */
export interface ProtectedResource {
  readonly id: string;
  readonly realmId: string;
  /** The RFC 8707 resource indicator, matched exactly. */
  readonly resource: string;
  readonly scopes: readonly ProtectedResourceScope[];
  /** Whether every client of the realm may ask for the scopes. */
  readonly anyClient: boolean;
  /** The `client_id`s that may, when {@link anyClient} is false. */
  readonly clientIds: readonly string[];
  /** Raised by one with every write. */
  readonly version: number;
  readonly createdAt: number;
  readonly updatedAt: number;
}

/** What a write sets: everything but the resource indicator, which never changes. */
export interface ProtectedResourceSettings {
  readonly scopes: readonly ProtectedResourceScope[];
  readonly anyClient: boolean;
  /** Empty when {@link anyClient} is true. */
  readonly clientIds: readonly string[];
}

/** The protected resource repository (#1087). Every method takes the realm first. */
export interface ProtectedResourcesRepository {
  /** Every protected resource of the realm, by resource indicator. `[]` for an id that is not a UUID. */
  listByRealm(realmId: string, tx?: DbClient): Promise<ProtectedResource[]>;
  /** One page of the realm's protected resources, newest first by `created_at` and then `id`. */
  pageByRealm(realmId: string, page: KeysetPage, tx?: DbClient): Promise<ProtectedResource[]>;
  /** The protected resource `id` of the realm, or `undefined`. */
  findById(realmId: string, id: string, tx?: DbClient): Promise<ProtectedResource | undefined>;
  /**
   * The protected resource `id` of the realm, locked `FOR NO KEY UPDATE` in
   * `tx` until it commits, or `undefined`.
   */
  findByIdForUpdate(
    realmId: string,
    id: string,
    tx: DbClient
  ): Promise<ProtectedResource | undefined>;
  /** The realm's protected resource with this resource indicator, or `undefined`. */
  findByResource(
    realmId: string,
    resource: string,
    tx?: DbClient
  ): Promise<ProtectedResource | undefined>;
  /**
   * Register `resource` in the realm at version 1. Answers the new row, or
   * `undefined` when the realm already registered the resource.
   */
  create(
    realmId: string,
    resource: string,
    settings: ProtectedResourceSettings,
    tx?: DbClient
  ): Promise<ProtectedResource | undefined>;
  /**
   * Replace the settings of the protected resource `id` while it is at
   * `expectedVersion`, raising its version by one. Answers the written row,
   * or `undefined` when it is gone or at another version.
   */
  update(
    realmId: string,
    id: string,
    settings: ProtectedResourceSettings,
    expectedVersion: number,
    tx?: DbClient
  ): Promise<ProtectedResource | undefined>;
  /**
   * Remove the protected resource `id` while it is at `expectedVersion`.
   * Answers whether a row was removed.
   */
  delete(realmId: string, id: string, expectedVersion: number, tx?: DbClient): Promise<boolean>;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Refuse an id Postgres would refuse with an error (22P02) before it reaches it. */
const isUuid = (value: unknown): value is string =>
  typeof value === 'string' && UUID_PATTERN.test(value);

const isVersion = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 1;

/** The stored columns of `settings`: plain copies, so the caller's objects are never stored by reference. */
function columnsOf(settings: ProtectedResourceSettings) {
  return {
    scopes: settings.scopes.map((entry) => ({
      scope: entry.scope,
      text: { ...entry.text },
      sensitive: entry.sensitive === true,
    })),
    anyClient: settings.anyClient === true,
    clientIds: settings.anyClient === true ? [] : [...settings.clientIds],
  };
}

/**
 * Factory for the protected resource repository (#1087).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createProtectedResourcesRepository(
  defaultDb: DbClient
): ProtectedResourcesRepository {
  const ofRealm = (realmId: string, id: string) =>
    and(eq(protectedResources.realmId, realmId), eq(protectedResources.id, id));

  return {
    async listByRealm(realmId, tx) {
      if (!isUuid(realmId)) return [];
      return (tx ?? defaultDb)
        .select()
        .from(protectedResources)
        .where(eq(protectedResources.realmId, realmId))
        .orderBy(asc(protectedResources.resource));
    },

    async pageByRealm(realmId, page, tx) {
      if (!isUuid(realmId)) return [];
      const after = page.after;
      return (tx ?? defaultDb)
        .select()
        .from(protectedResources)
        .where(
          and(
            eq(protectedResources.realmId, realmId),
            after === undefined
              ? undefined
              : or(
                  lt(protectedResources.createdAt, after.at),
                  and(
                    eq(protectedResources.createdAt, after.at),
                    lt(protectedResources.id, after.id)
                  )
                )
          )
        )
        .orderBy(desc(protectedResources.createdAt), desc(protectedResources.id))
        .limit(page.limit);
    },

    async findById(realmId, id, tx) {
      if (!isUuid(realmId) || !isUuid(id)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .select()
        .from(protectedResources)
        .where(ofRealm(realmId, id))
        .limit(1);
      return row;
    },

    async findByIdForUpdate(realmId, id, tx) {
      if (!isUuid(realmId) || !isUuid(id)) return undefined;
      const [row] = await tx
        .select()
        .from(protectedResources)
        .where(ofRealm(realmId, id))
        .limit(1)
        .for('no key update');
      return row;
    },

    async findByResource(realmId, resource, tx) {
      if (!isUuid(realmId) || typeof resource !== 'string') return undefined;
      const [row] = await (tx ?? defaultDb)
        .select()
        .from(protectedResources)
        .where(
          and(eq(protectedResources.realmId, realmId), eq(protectedResources.resource, resource))
        )
        .limit(1);
      return row;
    },

    async create(realmId, resource, settings, tx) {
      if (!isUuid(realmId)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .insert(protectedResources)
        .values({ realmId, resource, ...columnsOf(settings) })
        .onConflictDoNothing({ target: [protectedResources.realmId, protectedResources.resource] })
        .returning();
      return row;
    },

    async update(realmId, id, settings, expectedVersion, tx) {
      if (!isUuid(realmId) || !isUuid(id) || !isVersion(expectedVersion)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .update(protectedResources)
        .set({
          ...columnsOf(settings),
          version: sql`${protectedResources.version} + 1`,
          updatedAt: EPOCH_MS_NOW,
        })
        .where(and(ofRealm(realmId, id), eq(protectedResources.version, expectedVersion)))
        .returning();
      return row;
    },

    async delete(realmId, id, expectedVersion, tx) {
      if (!isUuid(realmId) || !isUuid(id) || !isVersion(expectedVersion)) return false;
      const removed = await (tx ?? defaultDb)
        .delete(protectedResources)
        .where(and(ofRealm(realmId, id), eq(protectedResources.version, expectedVersion)))
        .returning({ id: protectedResources.id });
      return removed.length > 0;
    },
  };
}
