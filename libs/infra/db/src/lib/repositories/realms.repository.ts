import {
  BadRequestError,
  extractConstraintName,
  isUniqueConstraintError,
  NotFoundError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { InvalidRealmHostError, normaliseRealmHost } from '@qauth-labs/shared-validation';
import { and, eq, InferInsertModel, InferSelectModel } from 'drizzle-orm';

import { DbClient } from '../db';
import { realmHosts, realms } from '../schema/core';
import { BaseRepository } from './base.repository';

export type Realm = InferSelectModel<typeof realms>;
export type NewRealm = InferInsertModel<typeof realms>;
export type UpdateRealm = Partial<Omit<NewRealm, 'id' | 'createdAt'>> & {
  updatedAt?: number;
};

/** A `realm_hosts` row (ADR-019 Decision 1, issue #470). */
export type RealmHost = InferSelectModel<typeof realmHosts>;

/** A realm together with the host row that named it. */
export interface RealmWithHost {
  realm: Realm;
  host: RealmHost;
}

/** Input of {@link RealmsRepository.createWithPrimaryHost}: a new realm that has its issuer. */
export type NewRealmWithIssuer = NewRealm & { issuer: string };

/** Constraint behind a duplicate host: `host` is the primary key of `realm_hosts`. */
const REALM_HOSTS_PKEY = 'realm_hosts_pkey';

/**
 * Realms repository interface extending BaseRepository with additional methods
 */
export interface RealmsRepository extends BaseRepository<Realm, NewRealm, UpdateRealm> {
  /**
   * Find a realm by name
   */
  findByName(name: string, tx?: DbClient): Promise<Realm | undefined>;

  /**
   * Find the realm a host belongs to, as a primary or an endpoint host.
   *
   * The host is normalised with `normaliseRealmHost()` first, so any spelling
   * of a stored host matches it: case, a port, a trailing dot, the Unicode form
   * of a punycode name. A value that cannot be a host matches nothing. The
   * realm comes back as stored: a disabled realm, or one whose issuer is still
   * NULL, is the caller's to refuse.
   */
  findByHost(host: string, tx?: DbClient): Promise<RealmWithHost | undefined>;

  /**
   * Create a realm and its primary host in one transaction.
   *
   * The host is normalised as a primary host, so an IP literal is refused. The
   * issuer is required, has no trailing slash, query or fragment, and its host
   * must be the primary host: the two are the realm's permanent identity.
   *
   * @throws InvalidRealmHostError if the host cannot be a primary host
   * @throws BadRequestError if the issuer is not a URL on the primary host
   * @throws UniqueConstraintError if the host, name or issuer is taken
   */
  createWithPrimaryHost(
    data: NewRealmWithIssuer,
    primaryHost: string,
    tx?: DbClient
  ): Promise<RealmWithHost>;

  /**
   * Add an endpoint host to a realm. An IP literal is allowed.
   *
   * @throws InvalidRealmHostError if the host cannot be a realm host
   * @throws UniqueConstraintError if any realm already has the host, of either kind
   */
  addEndpointHost(realmId: string, host: string, tx?: DbClient): Promise<RealmHost>;

  /**
   * Remove an endpoint host from a realm. A primary host is never removed.
   *
   * @returns true if the realm had the host as an endpoint host
   */
  removeEndpointHost(realmId: string, host: string, tx?: DbClient): Promise<boolean>;
}

/**
 * Normalise a host for a lookup or a removal, where a value that cannot be a
 * host simply matches no row.
 */
function normaliseForMatch(host: string, kind?: 'endpoint'): string | undefined {
  try {
    return normaliseRealmHost(host, kind);
  } catch (error) {
    if (error instanceof InvalidRealmHostError) return undefined;
    throw error;
  }
}

/**
 * Check that an issuer can sit on `primaryHost`: a URL with no trailing slash,
 * query or fragment (RFC 8414 §2), whose host normalises to the primary host.
 * The scheme is the configuration's to check; a development issuer may be
 * `http://localhost:3000`.
 */
function assertIssuerOnPrimaryHost(issuer: string, primaryHost: string): void {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new BadRequestError('Realm issuer is not a URL');
  }
  if (issuer.endsWith('/')) {
    throw new BadRequestError('Realm issuer must not end with a slash');
  }
  if (issuer.includes('?') || issuer.includes('#')) {
    throw new BadRequestError('Realm issuer must not have a query or fragment');
  }
  if (normaliseForMatch(url.host) !== primaryHost) {
    throw new BadRequestError("Realm issuer's host is not the realm's primary host");
  }
}

/** Map a duplicate key to {@link UniqueConstraintError}; rethrow anything else. */
function rethrowUnique(error: unknown, fallbackConstraint: string): never {
  if (isUniqueConstraintError(error)) {
    throw new UniqueConstraintError(extractConstraintName(error) || fallbackConstraint, error);
  }
  throw error;
}

/**
 * Factory function that creates a realms repository with CRUD operations
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository object with CRUD methods implementing BaseRepository
 */
export function createRealmsRepository(defaultDb: DbClient): RealmsRepository {
  return {
    /**
     * Create a new realm
     *
     * @param data - Realm data to create
     * @param tx - Optional transaction client
     * @returns Created realm
     * @throws UniqueConstraintError if realm name already exists
     */
    async create(data: NewRealm, tx?: DbClient): Promise<Realm> {
      const invoker = tx ?? defaultDb;
      try {
        const [realm] = await invoker.insert(realms).values(data).returning();
        return realm;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint = extractConstraintName(error) || 'realms_name_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    /**
     * Find a realm by ID
     *
     * @param id - Realm ID
     * @param tx - Optional transaction client
     * @returns Realm if found, undefined otherwise
     */
    async findById(id: string, tx?: DbClient): Promise<Realm | undefined> {
      const invoker = tx ?? defaultDb;
      const [realm] = await invoker.select().from(realms).where(eq(realms.id, id)).limit(1);
      return realm;
    },

    /**
     * Find a realm by ID, throwing an error if not found
     *
     * @param id - Realm ID
     * @param tx - Optional transaction client
     * @returns Realm
     * @throws NotFoundError if realm is not found
     */
    async findByIdOrThrow(id: string, tx?: DbClient): Promise<Realm> {
      const realm = await this.findById(id, tx);
      if (!realm) {
        throw new NotFoundError('Realm', id);
      }
      return realm;
    },

    /**
     * Find a realm by name
     *
     * @param name - Realm name
     * @param tx - Optional transaction client
     * @returns Realm if found, undefined otherwise
     */
    async findByName(name: string, tx?: DbClient): Promise<Realm | undefined> {
      const invoker = tx ?? defaultDb;
      const [realm] = await invoker.select().from(realms).where(eq(realms.name, name)).limit(1);
      return realm;
    },

    async findByHost(host: string, tx?: DbClient): Promise<RealmWithHost | undefined> {
      const normalised = normaliseForMatch(host);
      if (normalised === undefined) return undefined;
      const invoker = tx ?? defaultDb;
      const [row] = await invoker
        .select({ realm: realms, host: realmHosts })
        .from(realmHosts)
        .innerJoin(realms, eq(realmHosts.realmId, realms.id))
        .where(eq(realmHosts.host, normalised))
        .limit(1);
      return row;
    },

    async createWithPrimaryHost(
      data: NewRealmWithIssuer,
      primaryHost: string,
      tx?: DbClient
    ): Promise<RealmWithHost> {
      const host = normaliseRealmHost(primaryHost, 'primary');
      assertIssuerOnPrimaryHost(data.issuer, host);
      const invoker = tx ?? defaultDb;
      try {
        // A savepoint inside an outer transaction, so a realm is never left
        // without its primary host when the caller catches the error and goes on.
        return await invoker.transaction(async (innerTx) => {
          const [realm] = await innerTx.insert(realms).values(data).returning();
          const [realmHost] = await innerTx
            .insert(realmHosts)
            .values({ host, realmId: realm.id, kind: 'primary' })
            .returning();
          return { realm, host: realmHost };
        });
      } catch (error) {
        rethrowUnique(error, REALM_HOSTS_PKEY);
      }
    },

    async addEndpointHost(realmId: string, host: string, tx?: DbClient): Promise<RealmHost> {
      const normalised = normaliseRealmHost(host, 'endpoint');
      const invoker = tx ?? defaultDb;
      try {
        const [realmHost] = await invoker
          .insert(realmHosts)
          .values({ host: normalised, realmId, kind: 'endpoint' })
          .returning();
        return realmHost;
      } catch (error) {
        rethrowUnique(error, REALM_HOSTS_PKEY);
      }
    },

    async removeEndpointHost(realmId: string, host: string, tx?: DbClient): Promise<boolean> {
      const normalised = normaliseForMatch(host, 'endpoint');
      if (normalised === undefined) return false;
      const invoker = tx ?? defaultDb;
      const [removed] = await invoker
        .delete(realmHosts)
        .where(
          and(
            eq(realmHosts.host, normalised),
            eq(realmHosts.realmId, realmId),
            eq(realmHosts.kind, 'endpoint')
          )
        )
        .returning({ host: realmHosts.host });
      return !!removed;
    },

    /**
     * Update a realm by ID
     *
     * @param id - Realm ID
     * @param data - Fields to update
     * @param tx - Optional transaction client
     * @returns Updated realm
     * @throws NotFoundError if realm is not found
     * @throws UniqueConstraintError if realm name or issuer would violate uniqueness
     *
     * `issuer` may be set where it is NULL. Changing a set issuer fails in the
     * database (trigger `realms_issuer_permanent`, SQLSTATE 23514), and so
     * does a second realm with `isOperator: true` (`idx_realms_one_operator`,
     * a {@link UniqueConstraintError}).
     */
    async update(id: string, data: UpdateRealm, tx?: DbClient): Promise<Realm> {
      const invoker = tx ?? defaultDb;
      const updateData = {
        ...data,
        updatedAt: data.updatedAt ?? Date.now(),
      };

      try {
        const [realm] = await invoker
          .update(realms)
          .set(updateData)
          .where(eq(realms.id, id))
          .returning();

        if (!realm) {
          throw new NotFoundError('Realm', id);
        }

        return realm;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint = extractConstraintName(error) || 'realms_name_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    /**
     * Delete a realm by ID
     *
     * @param id - Realm ID
     * @param tx - Optional transaction client
     * @returns True if deleted, false if not found
     */
    async delete(id: string, tx?: DbClient): Promise<boolean> {
      const invoker = tx ?? defaultDb;
      const [realm] = await invoker.delete(realms).where(eq(realms.id, id)).returning();
      return !!realm;
    },
  };
}
