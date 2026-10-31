import {
  BadRequestError,
  extractConstraintName,
  isUniqueConstraintError,
  NotFoundError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import {
  type EventRetentionPolicy,
  eventRetentionProblems,
  InvalidRealmHostError,
  normaliseRealmHost,
  reservedQauthScopesIn,
  resolveRpId,
  rpIdCoversHost,
} from '@qauth-labs/shared-validation';
import { and, eq, inArray, InferInsertModel, InferSelectModel, isNull, ne, sql } from 'drizzle-orm';

import type { DbTransaction } from '../../types';
import { DbClient } from '../db';
import { realmHosts, realms } from '../schema/core';
import { BaseRepository } from './base.repository';
import {
  type RealmPolicyRecord,
  realmPolicyRecord,
  splitRealmPolicies,
} from './realm-policy-record';

export type Realm = InferSelectModel<typeof realms>;
/**
 * A new realm. Its policy document, schema version and counter are left out
 * (#516): a new realm stores the repository's policy seed, and only
 * `writePolicies` writes them afterwards, so nothing the policy store did not
 * parse reaches `realms.policies`.
 */
export type NewRealm = Omit<
  InferInsertModel<typeof realms>,
  'policies' | 'policySchemaVersion' | 'policiesVersion'
>;
/**
 * Fields a realm update may change. The passkey RP ID columns are left out on
 * purpose (#467, #553): `setWebAuthnRpId` writes the RP ID, refusing it once
 * the realm is locked, and only `lockRpIdForEnrolment` writes the lock. The
 * operator flag is left out too (#510): the realm rule of admin grants rests
 * on it, and only `setOperator` writes it. So are the policy document, its
 * schema version and its counter (#516): only `writePolicies` writes them,
 * comparing the counter. The four policy columns are still writable here,
 * for the callers that wrote them before the policies existed; the trigger
 * `realms_policies_version` raises the counter when such a write changes one.
 */
export type UpdateRealm = Partial<
  Omit<NewRealm, 'id' | 'createdAt' | 'webauthnRpId' | 'webauthnRpIdLockedAt' | 'isOperator'>
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

/**
 * The policy document a new realm gets (#516): `defaultsFromEnv` of the
 * environment the server runs with, and the schema version it follows.
 */
export interface RealmPolicyDocumentSeed {
  /** A whole policy document of the realm policy schema, with no secret field. */
  readonly document: Record<string, unknown>;
  /** The policy schema version, `REALM_POLICY_SCHEMA_VERSION`. */
  readonly schemaVersion: string;
}

/**
 * The realm policies the environment seeds into a new realm (ADR-019
 * Decision 10): the values a realm gets for the policies its creator leaves
 * out. The realm row owns them from then on; a later change of a seed leaves
 * existing realms as they are.
 */
export type RealmPolicySeeds = Partial<EventRetentionPolicy> & {
  /**
   * The policy document (#516), which every new realm stores; a
   * column-backed field its creator sets keeps the creator's value. Without
   * it a new realm has no policies (counter 0) until the boot step fills
   * them.
   */
  readonly policies?: RealmPolicyDocumentSeed;
};

/** What {@link RealmsRepository.writePolicies} writes. */
export interface RealmPoliciesWrite {
  /** The whole policy document, parsed by the policy store; no secret field. */
  readonly document: Record<string, unknown>;
  /** The policy schema version the document follows. */
  readonly schemaVersion: string;
  /** The counter the realm must still have; the write sets it one higher. */
  readonly expectedVersion: number;
}

/** The policy columns of a realm row, which only the repository's seed and `writePolicies` set. */
type RealmPolicyColumnsOfRow = Pick<
  InferInsertModel<typeof realms>,
  'policies' | 'policySchemaVersion' | 'policiesVersion'
>;

/** Options of {@link createRealmsRepository}. */
export interface RealmsRepositoryOptions {
  /**
   * The seeds every new realm gets, whichever call creates it. A policy left
   * out of the seeds takes the column default.
   */
  readonly seeds?: RealmPolicySeeds;
}

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
   * Find the realm whose issuer is exactly `issuer` (#510): the realm a
   * token's `iss` names. Exact match: issuers are stored without a trailing
   * slash, so `https://auth.example.com/` names no realm. The realm comes back
   * as stored: a disabled realm is the caller's to refuse.
   */
  findByIssuer(issuer: string, tx?: DbClient): Promise<Realm | undefined>;

  /**
   * Whether one of `values` is the issuer of a realm other than `realmId`:
   * an access token whose `aud` names one may have been minted in that realm
   * (#410). Exact match: issuers are stored without a trailing slash.
   */
  anotherRealmHasIssuer(
    realmId: string,
    values: readonly string[],
    tx?: DbClient
  ): Promise<boolean>;

  /**
   * Create a realm and its primary host in one transaction.
   *
   * The host is normalised as a primary host, so an IP literal is refused. The
   * issuer is required and is an `https` URL (plain `http` on `localhost`
   * only) with no white space, control character, backslash, userinfo,
   * trailing slash, query or fragment. Its host must be the primary host: the
   * two are the realm's permanent identity.
   *
   * The realm gets the repository's seeds for the policies `data` leaves out.
   *
   * @throws InvalidRealmHostError if the host cannot be a primary host
   * @throws BadRequestError if the issuer is not a URL on the primary host, or
   *   the event retention is out of range
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
   * Set or clear the realm's operator flag (ADR-019 Decision 7, #510): the
   * only writer of `is_operator` after a realm's creation, since the realm
   * rule of admin grants rests on it. The default realm's boot step marks the
   * operator realm when there is none; moving the flag clears it on one realm
   * and sets it on another, in one transaction.
   *
   * @throws NotFoundError if the realm does not exist
   * @throws UniqueConstraintError if another realm is the operator realm
   *   (`idx_realms_one_operator`)
   */
  setOperator(realmId: string, isOperator: boolean, tx?: DbClient): Promise<Realm>;

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
   * Write a realm's policies (#516): the four column-backed fields to their
   * columns, every other field to `realms.policies`, the schema version, and
   * the counter one higher than `expectedVersion`, in one `UPDATE ... WHERE
   * policies_version = expectedVersion`. So of two writers that read the
   * same counter one wins and the other changes nothing: a boot filling a
   * realm with no policies (counter 0) races another node's boot, an update
   * a concurrent one.
   *
   * The policy store is the only caller: it parses the document with the
   * policy schema and keeps every secret out of it.
   *
   * @returns the realm as written, or `undefined` when the realm is gone or
   *   its counter is no longer `expectedVersion`
   * @throws BadRequestError if the allowlist holds a `qauth:` scope
   * @throws TypeError if the document lacks a column-backed field
   */
  writePolicies(
    realmId: string,
    write: RealmPoliciesWrite,
    tx?: DbClient
  ): Promise<Realm | undefined>;

  /**
   * Every realm's policies, as the boot step reads them to fill a realm that
   * has none and to complete one a later release added fields to (#516).
   */
  listPolicyRecords(tx?: DbClient): Promise<RealmPolicyRecord[]>;

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

/**
 * Refuse event retention outside its limits (#536): user events 1 to 36500
 * days, admin events 90 to 36500. The row's CHECK constraints refuse the same.
 */
function assertEventRetention(data: Partial<EventRetentionPolicy>): void {
  const problems = eventRetentionProblems({
    userEventRetentionDays: data.userEventRetentionDays,
    adminEventRetentionDays: data.adminEventRetentionDays,
  });
  if (problems.length > 0) {
    throw new BadRequestError(`Realm event retention is out of range: ${problems.join('; ')}`);
  }
}

/**
 * Refuse a session limit of zero or less (#552). A maximum session length of
 * zero would end every session and every refresh-token family at its start; an
 * idle timeout of zero would end every session at its first request after
 * sign-in. NULL means no limit. The CHECKs `realms_sso_max_lifespan_positive`
 * and `realms_sso_idle_timeout_positive` refuse the same.
 */
function assertSsoLimits(data: {
  ssoMaxLifespan?: number | null;
  ssoIdleTimeout?: number | null;
}): void {
  for (const [column, value] of [
    ['sso_max_lifespan', data.ssoMaxLifespan],
    ['sso_idle_timeout', data.ssoIdleTimeout],
  ] as const) {
    if (value === undefined || value === null) continue;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new BadRequestError(
        `Realm ${column} must be a positive whole number of seconds, or null for no limit`
      );
    }
  }
}

/**
 * Refuse a dynamic registration allowlist that holds a scope in the reserved
 * `qauth:` namespace, in any case (#507, ADR-019 Decision 7): QAuth's own
 * scopes, the admin API's among them, are never obtained through dynamic
 * registration. The CHECK `realms_dynamic_registration_scopes_not_qauth`
 * refuses the same.
 */
function assertDynamicRegistrationScopes(data: {
  dynamicRegistrationAllowedScopes?: readonly string[];
}): void {
  const scopes = data.dynamicRegistrationAllowedScopes;
  if (scopes === undefined) return;
  const reserved = reservedQauthScopesIn(scopes.filter((scope) => typeof scope === 'string'));
  if (reserved.length > 0) {
    throw new BadRequestError(
      `Realm dynamic_registration_allowed_scopes must not hold a scope in the "qauth:" namespace, which is reserved for QAuth's own scopes: ${reserved.join(', ')}`
    );
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
 * Every realm it creates gets `options.seeds` for the policies its creator
 * leaves out, and every create and update refuses event retention outside
 * its limits, an `sso_max_lifespan` of zero or less and a dynamic
 * registration allowlist with a scope in the reserved `qauth:` namespace
 * ({@link BadRequestError}).
 *
 * @param defaultDb - Database client to use for queries
 * @param options - The realm policy seeds (ADR-019 Decision 10)
 * @returns Repository object with CRUD methods implementing BaseRepository
 * @throws TypeError when a seed is out of range, so a bad environment fails
 *   the boot rather than the first realm's creation
 */
export function createRealmsRepository(
  defaultDb: DbClient,
  options: RealmsRepositoryOptions = {}
): RealmsRepository {
  const { policies: policySeed, ...retentionSeeds } = { ...options.seeds };
  const seedProblems = eventRetentionProblems(retentionSeeds);
  if (seedProblems.length > 0) {
    throw new TypeError(`createRealmsRepository: ${seedProblems.join('; ')}`);
  }
  // Split once, so a seed without a column-backed field fails the boot rather
  // than the first realm's creation.
  const policyColumnsSeed =
    policySeed === undefined ? undefined : splitRealmPolicies(policySeed.document);

  /**
   * A new realm's row: the seeds, overridden by what the creator set. The
   * policy document, its schema version and its counter come from the seed
   * alone, whatever the creator passed.
   */
  function seeded<T extends NewRealm>(data: T): T & RealmPolicyColumnsOfRow {
    const row: T & Partial<RealmPolicyColumnsOfRow> = { ...data };
    delete row.policies;
    delete row.policySchemaVersion;
    delete row.policiesVersion;
    for (const [key, value] of Object.entries(retentionSeeds) as [
      keyof EventRetentionPolicy,
      number,
    ][]) {
      if (row[key] === undefined) row[key] = value;
    }
    if (policySeed !== undefined && policyColumnsSeed !== undefined) {
      const { columns, members } = structuredClone(policyColumnsSeed);
      for (const [column, value] of Object.entries(columns) as [keyof typeof columns, never][]) {
        if (row[column] === undefined) row[column] = value;
      }
      row.policies = members;
      row.policySchemaVersion = policySeed.schemaVersion;
      row.policiesVersion = 1;
    }
    assertEventRetention(row);
    assertSsoLimits(row);
    assertDynamicRegistrationScopes(row);
    return row as T & RealmPolicyColumnsOfRow;
  }

  return {
    /**
     * Create a new realm
     *
     * @param data - Realm data to create
     * @param tx - Optional transaction client
     * @returns Created realm, with the seeds for the policies `data` leaves out
     * @throws BadRequestError if its event retention is out of range
     * @throws UniqueConstraintError if realm name already exists
     */
    async create(data: NewRealm, tx?: DbClient): Promise<Realm> {
      const row = seeded(data);
      const invoker = tx ?? defaultDb;
      try {
        const [realm] = await invoker.insert(realms).values(row).returning();
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

    async findByIssuer(issuer: string, tx?: DbClient): Promise<Realm | undefined> {
      if (typeof issuer !== 'string' || issuer.length === 0) return undefined;
      const invoker = tx ?? defaultDb;
      const [realm] = await invoker.select().from(realms).where(eq(realms.issuer, issuer)).limit(1);
      return realm;
    },

    async anotherRealmHasIssuer(
      realmId: string,
      values: readonly string[],
      tx?: DbClient
    ): Promise<boolean> {
      if (values.length === 0) return false;
      const invoker = tx ?? defaultDb;
      const [row] = await invoker
        .select({ id: realms.id })
        .from(realms)
        .where(and(inArray(realms.issuer, [...values]), ne(realms.id, realmId)))
        .limit(1);
      return row !== undefined;
    },

    async createWithPrimaryHost(
      data: NewRealmWithIssuer,
      primaryHost: string,
      tx?: DbClient
    ): Promise<RealmWithHost> {
      const host = normaliseRealmHost(primaryHost, 'primary');
      assertIssuerOnPrimaryHost(data.issuer, host);
      const row = seeded(data);
      const invoker = tx ?? defaultDb;
      try {
        // A savepoint inside an outer transaction, so a realm is never left
        // without its primary host when the caller catches the error and goes on.
        return await invoker.transaction(async (innerTx) => {
          const [realm] = await innerTx.insert(realms).values(row).returning();
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

    async setOperator(realmId: string, isOperator: boolean, tx?: DbClient): Promise<Realm> {
      try {
        const [realm] = await (tx ?? defaultDb)
          .update(realms)
          .set({ isOperator, updatedAt: Date.now() })
          .where(eq(realms.id, realmId))
          .returning();
        if (!realm) {
          throw new NotFoundError('Realm', realmId);
        }
        return realm;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          throw new UniqueConstraintError(
            extractConstraintName(error) || 'idx_realms_one_operator',
            error
          );
        }
        throw error;
      }
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

    async writePolicies(
      realmId: string,
      write: RealmPoliciesWrite,
      tx?: DbClient
    ): Promise<Realm | undefined> {
      if (!Number.isSafeInteger(write.expectedVersion) || write.expectedVersion < 0) {
        throw new TypeError('writePolicies: expectedVersion is a whole number, 0 or more');
      }
      const { columns, members } = splitRealmPolicies(write.document);
      assertDynamicRegistrationScopes(columns);
      const [realm] = await (tx ?? defaultDb)
        .update(realms)
        .set({
          ...columns,
          policies: members,
          policySchemaVersion: write.schemaVersion,
          policiesVersion: write.expectedVersion + 1,
          updatedAt: Date.now(),
        })
        .where(and(eq(realms.id, realmId), eq(realms.policiesVersion, write.expectedVersion)))
        .returning();
      return realm;
    },

    async listPolicyRecords(tx?: DbClient): Promise<RealmPolicyRecord[]> {
      const rows = await (tx ?? defaultDb)
        .select()
        .from(realms)
        .orderBy(realms.createdAt, realms.id);
      return rows.map(realmPolicyRecord);
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
     * @throws BadRequestError if a new event retention is out of range
     *   (admin events fewer than 90 days, for one)
     * @throws UniqueConstraintError if realm name or issuer would violate uniqueness
     *
     * `issuer` may be set where it is NULL. Changing a set issuer fails in the
     * database (trigger `realms_issuer_permanent`, SQLSTATE 23514). The
     * operator flag is `setOperator`'s to write.
     */
    async update(id: string, data: UpdateRealm, tx?: DbClient): Promise<Realm> {
      assertEventRetention(data);
      assertSsoLimits(data);
      assertDynamicRegistrationScopes(data);
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
