import {
  BadRequestError,
  extractConstraintName,
  isUniqueConstraintError,
  NotFoundError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import {
  InvalidRealmHostError,
  normaliseRealmHost,
  resolveRpId,
  rpIdCoversHost,
} from '@qauth-labs/shared-validation';
import { and, eq, InferInsertModel, InferSelectModel, isNull, sql } from 'drizzle-orm';

import type { DbTransaction } from '../../types';
import { DbClient } from '../db';
import { realmHosts, realms } from '../schema/core';
import { BaseRepository } from './base.repository';

export type Realm = InferSelectModel<typeof realms>;
export type NewRealm = InferInsertModel<typeof realms>;
/**
 * Fields a realm update may change. The passkey RP ID columns are left out on
 * purpose (#467, #553): `setWebAuthnRpId` writes the RP ID, refusing it once
 * the realm is locked, and only `lockRpIdForEnrolment` writes the lock.
 */
export type UpdateRealm = Partial<
  Omit<NewRealm, 'id' | 'createdAt' | 'webauthnRpId' | 'webauthnRpIdLockedAt'>
> & {
  updatedAt?: number;
};

/** What {@link RealmsRepository.lockRpIdForEnrolment} hands the enrolment (#553). */
export interface RpIdEnrolmentLock {
  /** The RP ID to store the passkey under: `resolveRpId` of the locked realm. */
  readonly rpId: string;
  /** When the realm's first enrolment locked the RP ID, in epoch ms. */
  readonly lockedAt: number;
  /** Whether this call took the lock, which only the realm's first enrolment does. */
  readonly lockedNow: boolean;
}

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
 * The advisory lock key text of {@link RealmsRepository.lockProvisioning},
 * hashed to a `bigint` by Postgres. The `qauth:` prefix keeps it apart from
 * the admin audit chain locks and from keys other software on the database
 * might choose.
 */
const PROVISIONING_LOCK = 'qauth:realm-provisioning';

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
   * issuer is required and is an `https` URL (plain `http` on `localhost`
   * only) with no white space, control character, backslash, userinfo,
   * trailing slash, query or fragment. Its host must be the primary host: the
   * two are the realm's permanent identity.
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
   * Give a realm its issuer and its primary host, in one transaction (#484).
   *
   * Each is written only where the realm has none yet, so a second call with
   * the same values changes nothing. This is how a realm created before
   * migration 0025, whose issuer is NULL, gets its identity. The issuer and
   * host rules are those of {@link createWithPrimaryHost}.
   *
   * @throws InvalidRealmHostError if the host cannot be a primary host
   * @throws BadRequestError if the issuer is not a URL on the primary host, or
   * the realm already has a different issuer or primary host (both permanent)
   * @throws NotFoundError if the realm does not exist
   * @throws UniqueConstraintError if another realm has the host or the issuer
   */
  assignIssuer(
    realmId: string,
    issuer: string,
    primaryHost: string,
    tx?: DbClient
  ): Promise<RealmWithHost>;

  /**
   * Find the operator realm (ADR-019 Decisions 1 and 7), if one is marked.
   */
  findOperator(tx?: DbClient): Promise<Realm | undefined>;

  /**
   * Set the realm's passkey RP ID (ADR-019 Decision 2, issue #553): a parent
   * domain of its primary host, or `null` for the primary host itself. Allowed
   * only while no passkey has locked it; a value that names the RP ID the
   * realm is locked to changes nothing.
   *
   * The caller checks the value with the RP ID rules of the WebAuthn provider
   * first (`resolveRelyingPartyId`: the `allowParentDomainRpId` opt-in, the
   * label boundary, the Public Suffix List). This method refuses only what no
   * caller may store: a value that is not a host name, an IP literal, and a
   * name that is not the primary host or a parent domain of it.
   *
   * @throws InvalidRealmHostError if `rpId` cannot be an RP ID (an IP literal,
   * a URL, a wildcard)
   * @throws BadRequestError if the realm is locked to another RP ID, or `rpId`
   * is neither the primary host nor a parent domain of it
   * @throws NotFoundError if the realm does not exist
   */
  setWebAuthnRpId(realmId: string, rpId: string | null, tx?: DbClient): Promise<Realm>;

  /**
   * Lock the realm's passkey RP ID for an enrolment, and return the RP ID to
   * store the passkey under (ADR-019 Decision 2, issue #553).
   *
   * Sets `webauthn_rp_id_locked_at` where it is empty; a realm already locked
   * keeps its lock time. The enrolment calls this in the transaction that
   * stores the passkey, so a realm's first passkey and its lock commit
   * together, or neither does. The first call holds the realm row until `tx`
   * ends: a concurrent first enrolment waits, then finds the lock set and gets
   * the same RP ID. From the lock on, the trigger `realms_webauthn_rp_id_locked`
   * refuses every change of the RP ID, whoever writes it.
   *
   * @throws NotFoundError if the realm does not exist
   * @throws RealmWithoutIssuerError if the RP ID is the primary host and the
   * realm has no issuer yet
   */
  lockRpIdForEnrolment(tx: DbTransaction, realmId: string): Promise<RpIdEnrolmentLock>;

  /**
   * Take the realm provisioning lock until `tx` ends: a transaction-scoped
   * Postgres advisory lock. The auth server's boot step holds it while it
   * creates or completes the default realm, so nodes that start together
   * provision it one at a time and the later ones find the first one's work.
   */
  lockProvisioning(tx: DbTransaction): Promise<void>;

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
 * White space, C0 controls, DEL and `\`. The WHATWG URL parser drops the
 * first three and reads `\` as `/`, so it would accept an issuer that is not
 * the string it parsed.
 */
// eslint-disable-next-line no-control-regex -- matching control characters is the entire purpose of this pattern
const UNPARSED_ISSUER_CHARACTERS = /[\s\u0000-\u001f\u007f\\]/u;

/** `localhost` or a name under it (RFC 6761 §6.3), where plain http may serve development. */
const isLocalhost = (hostname: string): boolean =>
  hostname === 'localhost' || hostname.endsWith('.localhost');

/**
 * Check that an issuer can sit on `primaryHost`: an `https` URL with no white
 * space, control character, backslash, userinfo, trailing slash, query or
 * fragment (RFC 8414 §2), whose host normalises to the primary host. Plain
 * `http` is accepted on `localhost` only, for development
 * (`http://localhost:3000`).
 *
 * The scheme and character rules are CHECKs on `realms.issuer` too, because
 * `update` may set an issuer that is still NULL. The issuer is permanent, so
 * a value refused here could never be corrected later.
 */
function assertIssuerOnPrimaryHost(issuer: string, primaryHost: string): void {
  if (UNPARSED_ISSUER_CHARACTERS.test(issuer)) {
    throw new BadRequestError(
      'Realm issuer must not contain white space, control characters or a backslash'
    );
  }
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
  if (url.username !== '' || url.password !== '') {
    throw new BadRequestError('Realm issuer must not carry a user name or password');
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocalhost(url.hostname))) {
    throw new BadRequestError('Realm issuer must use https; plain http is for localhost only');
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

    async assignIssuer(
      realmId: string,
      issuer: string,
      primaryHost: string,
      tx?: DbClient
    ): Promise<RealmWithHost> {
      const host = normaliseRealmHost(primaryHost, 'primary');
      assertIssuerOnPrimaryHost(issuer, host);
      const invoker = tx ?? defaultDb;
      try {
        // A savepoint inside an outer transaction, as in createWithPrimaryHost.
        return await invoker.transaction(async (innerTx) => {
          const [current] = await innerTx
            .select()
            .from(realms)
            .where(eq(realms.id, realmId))
            .limit(1)
            .for('update');
          if (!current) {
            throw new NotFoundError('Realm', realmId);
          }

          let realm = current;
          if (current.issuer === null) {
            [realm] = await innerTx
              .update(realms)
              .set({ issuer, updatedAt: Date.now() })
              .where(eq(realms.id, realmId))
              .returning();
          } else if (current.issuer !== issuer) {
            throw new BadRequestError(
              'Realm already has a different issuer; an issuer is permanent'
            );
          }

          const [primary] = await innerTx
            .select()
            .from(realmHosts)
            .where(and(eq(realmHosts.realmId, realmId), eq(realmHosts.kind, 'primary')))
            .limit(1);
          if (primary) {
            if (primary.host !== host) {
              throw new BadRequestError(
                'Realm already has a different primary host; a primary host is permanent'
              );
            }
            return { realm, host: primary };
          }

          const [realmHost] = await innerTx
            .insert(realmHosts)
            .values({ host, realmId, kind: 'primary' })
            .returning();
          return { realm, host: realmHost };
        });
      } catch (error) {
        rethrowUnique(error, REALM_HOSTS_PKEY);
      }
    },

    async findOperator(tx?: DbClient): Promise<Realm | undefined> {
      const invoker = tx ?? defaultDb;
      const [realm] = await invoker
        .select()
        .from(realms)
        .where(eq(realms.isOperator, true))
        .limit(1);
      return realm;
    },

    async setWebAuthnRpId(realmId: string, rpId: string | null, tx?: DbClient): Promise<Realm> {
      const normalised = rpId === null ? null : normaliseRealmHost(rpId, 'primary');
      const invoker = tx ?? defaultDb;
      // A savepoint inside an outer transaction, as in assignIssuer. The row
      // lock orders this against a first enrolment's lock: whichever comes
      // second sees the other's write.
      return invoker.transaction(async (innerTx) => {
        const [current] = await innerTx
          .select()
          .from(realms)
          .where(eq(realms.id, realmId))
          .limit(1)
          .for('update');
        if (!current) {
          throw new NotFoundError('Realm', realmId);
        }
        if (current.webauthnRpId === normalised) return current;

        const primaryHost = resolveRpId({ issuer: current.issuer, webauthnRpId: null });
        if (normalised !== null && !rpIdCoversHost(normalised, primaryHost)) {
          throw new BadRequestError(
            "Realm's passkey RP ID must be its primary host or a parent domain of it"
          );
        }
        if (current.webauthnRpIdLockedAt !== null) {
          // NULL and the primary host spelled out are the same RP ID.
          if (resolveRpId({ ...current, webauthnRpId: normalised }) === resolveRpId(current)) {
            return current;
          }
          throw new BadRequestError(
            "Realm's passkey RP ID is locked by its first passkey enrolment; another RP ID would orphan every enrolled passkey"
          );
        }
        const [updated] = await innerTx
          .update(realms)
          .set({ webauthnRpId: normalised, updatedAt: Date.now() })
          .where(eq(realms.id, realmId))
          .returning();
        return updated;
      });
    },

    async lockRpIdForEnrolment(tx: DbTransaction, realmId: string): Promise<RpIdEnrolmentLock> {
      // The first enrolment's UPDATE holds the row until `tx` ends. A
      // concurrent first enrolment waits on it, then re-reads the committed row
      // (READ COMMITTED), matches nothing, and reads the lock below. A realm
      // already locked matches nothing at once and takes no row lock, so later
      // enrolments do not queue on the realm row.
      const now = Date.now();
      const [locked] = await tx
        .update(realms)
        .set({ webauthnRpIdLockedAt: now, updatedAt: now })
        .where(and(eq(realms.id, realmId), isNull(realms.webauthnRpIdLockedAt)))
        .returning();
      if (locked) {
        return { rpId: resolveRpId(locked), lockedAt: now, lockedNow: true };
      }

      const [current] = await tx.select().from(realms).where(eq(realms.id, realmId)).limit(1);
      if (!current) {
        throw new NotFoundError('Realm', realmId);
      }
      if (current.webauthnRpIdLockedAt === null) {
        // Only a snapshot older than the other enrolment's commit gets here,
        // which READ COMMITTED does not take.
        throw new Error('Realm passkey RP ID lock was not visible after a lost race');
      }
      return {
        rpId: resolveRpId(current),
        lockedAt: current.webauthnRpIdLockedAt,
        lockedNow: false,
      };
    },

    async lockProvisioning(tx: DbTransaction): Promise<void> {
      await tx.execute(
        sql`select pg_advisory_xact_lock(hashtextextended(${PROVISIONING_LOCK}, 0))`
      );
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
