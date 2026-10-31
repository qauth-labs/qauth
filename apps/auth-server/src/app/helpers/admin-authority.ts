/**
 * Admin authority: what an admin token may do to which realm (ADR-019
 * Decision 7, issue #510).
 *
 * Who administers what:
 *
 * - An admin of the operator realm manages any realm, by grant.
 * - Any other admin is realm-local: it manages only its own realm, and its
 *   token's `iss` must be that realm's issuer. It never manages the operator
 *   realm.
 *
 * Roles are read from the database on every request (`admin_grants`,
 * `admin_roles`), never from token claims, so a disabled account, a revoked
 * grant or a disabled role counts from the next request on, with the same
 * token. The token's scopes only narrow what the grants give
 * (`effectivePermissions`).
 *
 * Two seams bind a token to its realm, now that every realm signs its tokens
 * with its own keys under its own issuer (#491):
 *
 * - {@link RealmIssuerDirectory} maps a token's `iss` to its realm. The
 *   default, {@link deploymentRealmIssuerDirectory}, finds the realm whose
 *   stored issuer the `iss` is.
 * - {@link IssuerKeyResolver} verifies a token with the keys of the realm its
 *   `iss` names. The default, {@link deploymentIssuerKeyResolver}, verifies
 *   with that realm's published keys and pins its issuer, so a token signed
 *   by another realm's key never passes as this realm's.
 */
import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import { JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { accessTokenIssuedAt, accountCredentialRefusal } from './account-validity';
import { PERMISSION_REGISTRY, type PermissionRegistry } from './admin-permissions';
import {
  BUILT_IN_ROLE_NAMES,
  BUILT_IN_ROLES,
  type BuiltInRoleName,
  effectivePermissions,
} from './admin-roles';
import { ADMIN_SCOPE_LIST } from './admin-scopes';
import type { IssuerResolver } from './family-token';
import { tokenRealm } from './realm-url';
import type { RealmRow } from './request-realm';
import { inactiveSubjectError } from './token-subject';

/** A realm as the issuer directory returns it: the realm row. */
export type IssuerRealm = RealmRow;

/** The live grants of an account, as the grants repository lists them. */
type LiveAdminGrants = Awaited<
  ReturnType<FastifyInstance['repositories']['adminGrants']['listLive']>
>;

/** One live grant. */
export type LiveAdminGrant = LiveAdminGrants[number];

/**
 * Maps an issuer to its realm (ADR-019 Decision 1): the realm whose issuer a
 * token's `iss` names.
 */
export interface RealmIssuerDirectory {
  /** The realm `issuer` names, or `undefined` for an issuer of no realm here. */
  realmForIssuer(issuer: string): Promise<IssuerRealm | undefined>;
}

/**
 * Verifies a token with the keys of the realm its issuer names (ADR-019
 * Decisions 1 and 9, #491).
 */
export interface IssuerKeyResolver {
  /**
   * Verify `token`'s signature with the keys of `realm`, its expiry, and that
   * its `iss` is that realm's.
   *
   * @throws JWTInvalidError when no key of the realm verifies the token, or
   *   its `iss` is not the realm's
   */
  verifyAccessToken(realm: IssuerRealm, token: string): Promise<JWTPayload>;
}

/**
 * The default {@link RealmIssuerDirectory}: an issuer names the realm whose
 * stored issuer it is, exactly as the realm's tokens carry it (#491; issuers
 * are stored without a trailing slash). Any other issuer names no realm.
 */
export function deploymentRealmIssuerDirectory(fastify: FastifyInstance): RealmIssuerDirectory {
  return {
    async realmForIssuer(issuer) {
      const realm = await fastify.repositories.realms.findByIssuer(issuer);
      return realm !== undefined && realm.issuer === issuer ? realm : undefined;
    },
  };
}

/**
 * The default {@link IssuerKeyResolver}: the realm's own keys, as the signer
 * lists them, verify its tokens, with its issuer pinned (#491). A realm
 * without an issuer has no tokens, and none verifies.
 */
export function deploymentIssuerKeyResolver(fastify: FastifyInstance): IssuerKeyResolver {
  return {
    async verifyAccessToken(realm, token) {
      if (realm.issuer === null) {
        throw new JWTInvalidError('The realm the access token names has no issuer');
      }
      return fastify.jwtUtils.verifyAccessToken(tokenRealm(realm), token);
    },
  };
}

/** The seams {@link resolveAdminAuthority} and {@link adminIssuerResolver} read. */
export interface AdminAuthorityOptions {
  /** Default: {@link deploymentRealmIssuerDirectory}. */
  readonly directory?: RealmIssuerDirectory;
  /** Default: {@link deploymentIssuerKeyResolver}. */
  readonly keys?: IssuerKeyResolver;
  /** Default: the auth server's permission catalog. */
  readonly registry?: PermissionRegistry;
}

/**
 * The issuer rule of the admin family's token guard (`requireFamilyToken`,
 * #509): the token's `iss` must name an enabled realm in the directory, and
 * the token must verify with that realm's keys. The guard has verified the
 * signature with the request realm's keys before; this is the check that binds
 * a token's issuer to its own realm's keys (#491), so an issuer rule that
 * accepts another realm's issuer never accepts a token that realm's keys did
 * not sign.
 */
export function adminIssuerResolver(options: AdminAuthorityOptions = {}): IssuerResolver {
  return async (issuer, request) => {
    const fastify = request.server;
    const directory = options.directory ?? deploymentRealmIssuerDirectory(fastify);
    const realm = await directory.realmForIssuer(issuer);
    if (realm === undefined || !realm.enabled) return false;
    const credential = fastify.jwtUtils.extractCredentialFromHeader(request.headers.authorization);
    if (credential === null) return false;
    const keys = options.keys ?? deploymentIssuerKeyResolver(fastify);
    try {
      const claims = await keys.verifyAccessToken(realm, credential.token);
      return claims.iss === issuer;
    } catch {
      return false;
    }
  };
}

/** The input of {@link resolveAdminAuthority}: a verified admin token and the realm it acts on. */
export interface AdminAuthorityRequest {
  /** The token's `iss`. */
  readonly iss: string;
  /** The token's `sub`: the account. */
  readonly sub: string;
  /**
   * The token's `iat`, in seconds. A token with none, or one issued before the
   * account was last disabled, names no active account (#748).
   */
  readonly iat?: number;
  /** The token's `scope` claim, space-delimited, or its scopes as a list. */
  readonly scopes: string | Iterable<string> | undefined;
  /** The realm the request acts on, as the request names it. */
  readonly targetRealmId: string;
}

/**
 * Why {@link resolveAdminAuthority} refused:
 *
 * - `issuer_unknown`: the token's `iss` names no enabled realm here;
 * - `account_inactive`: the subject is not an enabled account of that realm,
 *   or the token was issued before the account was last disabled (#748);
 * - `realm_not_found`: the requested realm is outside the caller's grants, or
 *   does not exist. The two are one answer, so it never confirms a realm
 *   exists to someone who may not manage it.
 */
export type AdminAuthorityRefusal = 'issuer_unknown' | 'account_inactive' | 'realm_not_found';

/** What {@link resolveAdminAuthority} found. */
export type AdminAuthority =
  | {
      readonly allowed: true;
      /** The realm whose issuer issued the token: the operator realm or the admin's own. */
      readonly issuerRealm: IssuerRealm;
      /** Whether the caller is an operator-realm admin. */
      readonly operator: boolean;
      /** The realm the request acts on. It may be disabled: an admin manages a disabled realm. */
      readonly targetRealm: RealmRow;
      /** The account. */
      readonly userId: string;
      /**
       * The permission ids the request may use: those the matching grants'
       * roles hold, intersected with the token's scopes. May be empty; the
       * operation's own permission check answers 403 then.
       */
      readonly permissions: ReadonlySet<string>;
      /**
       * The permission ids the matching grants' roles hold, before the
       * token's scopes narrow them: what a token with every admin scope would
       * use. A permission here and not in {@link permissions} is one the
       * token's scopes withhold, so a wider token would reach it (#511).
       */
      readonly rolePermissions: ReadonlySet<string>;
      /** The grants that matched, in the order they were created. */
      readonly grantIds: readonly string[];
    }
  | { readonly allowed: false; readonly refusal: AdminAuthorityRefusal };

const uuidSchema = z.uuid();

/** The permission ids a live grant's role holds now. */
export function grantedPermissionIds(live: LiveAdminGrant): readonly string[] {
  if (live.grant.builtInRole !== null) {
    const name = live.grant.builtInRole;
    return (BUILT_IN_ROLE_NAMES as readonly string[]).includes(name)
      ? BUILT_IN_ROLES[name as BuiltInRoleName].permissionIds
      : [];
  }
  return live.role?.permissionIds ?? [];
}

/**
 * Whether a live grant still fits the realm rule for an account of
 * `accountRealm` (`admin_grants_realm_rule` holds it when the grant is
 * written; the operator flag may have moved since):
 *
 * - a grant on every realm only for an account of the operator realm;
 * - a grant on another realm than the account's own only for an account of
 *   the operator realm;
 * - a custom role of the account's realm or of the grant's target realm.
 */
export function grantFitsRealmRule(
  live: LiveAdminGrant,
  accountRealm: Pick<RealmRow, 'id' | 'isOperator'>
): boolean {
  const { targetRealmId } = live.grant;
  if (!accountRealm.isOperator && targetRealmId !== accountRealm.id) return false;
  if (live.grant.roleId !== null) {
    const role = live.role;
    if (role === null || role.disabledAt !== null) return false;
    if (role.realmId !== accountRealm.id && role.realmId !== targetRealmId) return false;
  }
  return true;
}

/**
 * Decide what an admin token may do to a realm (ADR-019 Decision 7, #510).
 * The token was verified by the admin family's guard; this reads the
 * database, every time:
 *
 * 1. Find the realm whose issuer is the token's `iss`. No enabled realm:
 *    `issuer_unknown`.
 * 2. The subject must be an enabled account of that realm:
 *    `account_inactive` otherwise.
 * 3. An operator-realm token needs a live grant whose target is the requested
 *    realm or every realm.
 * 4. Any other token is realm-local: the requested realm must be the issuer's
 *    own, with a live grant on it. The operator realm is never its target.
 * 5. The permissions of the matching grants, intersected with the token's
 *    scopes, are the effective permissions.
 *
 * A realm outside the grants, and a realm that does not exist, are both
 * `realm_not_found` (404, never 403): the answer does not confirm the realm
 * exists. Grants are matched before the realm is read, so a caller with no
 * grant learns nothing from the realm table.
 */
export async function resolveAdminAuthority(
  fastify: FastifyInstance,
  request: AdminAuthorityRequest,
  options: AdminAuthorityOptions = {}
): Promise<AdminAuthority> {
  const directory = options.directory ?? deploymentRealmIssuerDirectory(fastify);
  const issuerRealm = await directory.realmForIssuer(request.iss);
  if (issuerRealm === undefined || !issuerRealm.enabled) {
    return { allowed: false, refusal: 'issuer_unknown' };
  }

  if (!uuidSchema.safeParse(request.sub).success) {
    return { allowed: false, refusal: 'account_inactive' };
  }
  // Read in the issuer's realm (#489): an account of another realm is not
  // found, as an unknown one is not.
  const user = await fastify.repositories.users.findById(issuerRealm.id, request.sub);
  if (
    !user ||
    accountCredentialRefusal(user, accessTokenIssuedAt(request)) !== null ||
    user.realmId !== issuerRealm.id
  ) {
    return { allowed: false, refusal: 'account_inactive' };
  }

  if (!uuidSchema.safeParse(request.targetRealmId).success) {
    return { allowed: false, refusal: 'realm_not_found' };
  }
  // Ids are compared as strings below; Postgres prints a uuid in lower case.
  const target = request.targetRealmId.toLowerCase();
  const operator = issuerRealm.isOperator;
  // Rule 4: a realm-local admin acts on its own realm, never on another.
  if (!operator && target !== issuerRealm.id) {
    return { allowed: false, refusal: 'realm_not_found' };
  }

  const live = await fastify.repositories.adminGrants.listLive(issuerRealm.id, user.id);
  const matching = live.filter(
    (grant) =>
      grantFitsRealmRule(grant, issuerRealm) &&
      (grant.grant.targetRealmId === target || (operator && grant.grant.targetRealmId === null))
  );
  if (matching.length === 0) {
    return { allowed: false, refusal: 'realm_not_found' };
  }

  const targetRealm = await fastify.repositories.realms.findById(target);
  // Rule 4 again for a realm-local caller: the operator realm is never its
  // target. Its own realm is not the operator realm, so only a moved flag
  // reaches this.
  if (targetRealm === undefined || (!operator && targetRealm.isOperator)) {
    return { allowed: false, refusal: 'realm_not_found' };
  }

  const granted = matching.flatMap((grant) => grantedPermissionIds(grant));
  const registry = options.registry ?? PERMISSION_REGISTRY;
  return {
    allowed: true,
    issuerRealm,
    operator,
    targetRealm,
    userId: user.id,
    permissions: effectivePermissions(granted, request.scopes ?? [], registry),
    rolePermissions: effectivePermissions(granted, ADMIN_SCOPE_LIST, registry),
    grantIds: matching.map((grant) => grant.grant.id),
  };
}

/**
 * The error a refusal answers with:
 *
 * - `issuer_unknown` and `account_inactive`: 401, the RFC 6750
 *   `invalid_token` challenge, as the family guard answers a token it refuses;
 * - `realm_not_found`: 404 `not_found`, naming the realm id the request gave,
 *   which is the same whether the realm exists or not.
 */
export function adminAuthorityError(refusal: AdminAuthorityRefusal, targetRealmId: string): Error {
  switch (refusal) {
    case 'issuer_unknown':
      return new JWTInvalidError('Access token issuer is not accepted here');
    case 'account_inactive':
      return inactiveSubjectError();
    case 'realm_not_found':
      return new NotFoundError('Realm', targetRealmId);
  }
}
