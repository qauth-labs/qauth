/**
 * What a scope of the reserved `qauth:` namespace or the admin audience takes
 * to reach a token (ADR-019 Decision 7, issues #510 and #933). The token
 * endpoint applies it on every grant that mints an access token or an
 * assertion: authorization_code, refresh_token, client_credentials, token
 * exchange (both outcomes) and the jwt-bearer grant.
 *
 * - An admin scope (`qauth:admin:read`, `:write`, `:security`) is issued only
 *   when the client lists the admin API's audience and the account holds a
 *   live admin grant whose role has a permission of that scope's class.
 * - A scope of the account or developer API (`API_FAMILY_SCOPES`:
 *   `qauth:account:read`, `qauth:developer:write`, ...) is issued only when
 *   the client lists that family's audience, which only an operator sets, and
 *   the token names an account (#933). No grant or role is read: the family's
 *   operations act on the token's own user, and its guard refuses any other
 *   subject. It needs no DPoP proof.
 * - Any other scope of the reserved `qauth:` namespace is never issued.
 *
 *   A scope that fails is WITHHELD: the token is issued without it, and the response's
 *   `scope` says so (RFC 6749 §3.3). When nothing else is left to issue, the
 *   token route refuses the request, `invalid_scope`, rather than answer with
 *   no `scope`, which would read as the scope asked for.
 * - The admin audience is issued only to an account whose live admin grants
 *   give a permission. Otherwise the request is refused, `invalid_target`
 *   (RFC 8707 §2), as for an audience the client does not list.
 *
 * - An admin token is always bound to a DPoP key (#520, ADR-019 Decision 7).
 *   A request that carries no valid DPoP proof gets no admin scope, and is
 *   told so (`proofMissing`) when it would otherwise get one, or the admin
 *   audience: the token route then refuses it, or withholds the scopes. A
 *   request whose account holds no grant is answered as before, so the
 *   answer to it does not depend on the proof.
 *
 * Grants are read when the token is issued, so a refresh after a revocation
 * no longer carries what the grant gave. A request decided for no account
 * (`userId: null`) never gets an admin scope or the admin audience: a
 * `client_credentials` token, which names none, the two ID-JAG grants, whose
 * authority comes from another identity provider or goes to another
 * authorization server, and a delegated token of token exchange, since an
 * admin acts as itself, never through an agent. The account and its grants
 * are read in the request's realm only (#489).
 *
 * A family scope follows `namesUser` instead: withheld from a
 * `client_credentials` token and from both ID-JAG grants, but kept on a
 * delegated token of token exchange when its subject token carried it and the
 * agent's own client lists the family's audience. The account API takes an
 * act-chain token where its contract says so (ADR-019 Decision 7), and the
 * developer API's guard refuses one.
 *
 * Nothing is read from the database unless the request asks for an admin
 * scope or the admin audience.
 */
import { isReservedQauthScope } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';

import { API_FAMILY_AUDIENCES, familyScopeOf } from '../api-conventions/families';
import { grantedPermissionIds, grantFitsRealmRule } from './admin-authority';
import { PERMISSION_REGISTRY, type PermissionRegistry } from './admin-permissions';
import { isAdminScope, type PermissionClass, permissionClassOfScope } from './admin-scopes';
import { type OAuthClientLike, unlistedReservedAudiences } from './client-auth';

/** What {@link adminIssuance} decides about one token. */
export interface AdminIssuanceRequest {
  /** The client the token is issued to. */
  readonly client: Pick<OAuthClientLike, 'audience' | 'metadata' | 'dynamicRegisteredAt'>;
  /**
   * The request's realm (#489): the account is read, and its grants found, in
   * this realm only.
   */
  readonly realmId: string;
  /** The account the token is for; `null` when it names none (`client_credentials`). */
  readonly userId: string | null;
  /**
   * Whether the token names a user (its `sub`), for the family scopes
   * (#933); by default, whether `userId` names one. A delegated token of
   * token exchange is decided for no account by the admin rule, but names its
   * user: it passes `true`.
   */
  readonly namesUser?: boolean;
  /** The scopes the grant would issue. */
  readonly scopes: readonly string[];
  /** The `aud` the token would carry. */
  readonly aud: string | readonly string[];
  /**
   * Whether the request carried a valid DPoP proof, so the access token is
   * bound to its key (`cnf.jkt`, RFC 9449 §6.1). Without one, no admin scope
   * is issued (#520).
   */
  readonly dpopBound: boolean;
}

/** The outcome of {@link adminIssuance}. */
export interface AdminIssuance {
  /** The scopes to issue: the requested ones without the withheld ones, in order. */
  readonly scopes: string[];
  /** The `qauth:` scopes left out. */
  readonly withheld: string[];
  /** Whether `aud` names the admin audience for an account that may not have it. */
  readonly audienceRefused: boolean;
  /**
   * Whether the request would get an admin scope, or the admin audience, its
   * account's grants allow, but carries no DPoP proof (#520): an admin token
   * is bound to a key, so `scopes` holds none of them, and the audience must
   * be refused.
   */
  readonly proofMissing: boolean;
}

/**
 * The permission classes an account's live grants give, for issuance: every
 * live grant that fits the realm rule, whatever its target, since the token is
 * not yet bound to a realm to act on. A grant whose role gives no grantable
 * permission adds nothing.
 */
async function heldPermissionClasses(
  fastify: FastifyInstance,
  realmId: string,
  userId: string | null,
  registry: PermissionRegistry
): Promise<ReadonlySet<PermissionClass>> {
  const none = new Set<PermissionClass>();
  if (userId === null) return none;
  const user = await fastify.repositories.users.findById(realmId, userId);
  if (!user || !user.enabled) return none;
  const accountRealm = await fastify.repositories.realms.findById(realmId);
  if (accountRealm === undefined) return none;
  const live = await fastify.repositories.adminGrants.listLive(realmId, user.id);
  const fitting = live.filter((grant) => grantFitsRealmRule(grant, accountRealm));
  const classes = new Set<PermissionClass>();
  for (const grant of fitting) {
    for (const id of grantedPermissionIds(grant)) {
      const permission = registry.isGrantable(id) ? registry.get(id) : undefined;
      if (permission !== undefined) classes.add(permission.class);
    }
  }
  return classes;
}

/**
 * Decide which `qauth:` scopes a token may carry and whether it may name the
 * admin audience. See the module comment for the rules.
 */
export async function adminIssuance(
  fastify: FastifyInstance,
  request: AdminIssuanceRequest,
  registry: PermissionRegistry = PERMISSION_REGISTRY
): Promise<AdminIssuance> {
  const reserved = request.scopes.filter((scope) => isReservedQauthScope(scope));
  const namesAdminAudience = [request.aud].flat().includes(API_FAMILY_AUDIENCES.admin);
  if (reserved.length === 0 && !namesAdminAudience) {
    return {
      scopes: [...request.scopes],
      withheld: [],
      audienceRefused: false,
      proofMissing: false,
    };
  }

  // The grants are read only for what they decide: an admin scope or the
  // admin audience. A family scope needs none.
  const held =
    namesAdminAudience || reserved.some(isAdminScope)
      ? await heldPermissionClasses(fastify, request.realmId, request.userId, registry)
      : new Set<PermissionClass>();
  const clientListsAdmin =
    unlistedReservedAudiences(request.client, API_FAMILY_AUDIENCES.admin).length === 0;
  const allowedByGrants = (scope: string): boolean => {
    if (!isReservedQauthScope(scope)) return true;
    const familyScope = familyScopeOf(scope);
    if (familyScope !== undefined) {
      return (
        (request.namesUser ?? request.userId !== null) &&
        unlistedReservedAudiences(request.client, API_FAMILY_AUDIENCES[familyScope.family])
          .length === 0
      );
    }
    const permissionClass = permissionClassOfScope(scope);
    return clientListsAdmin && permissionClass !== undefined && held.has(permissionClass);
  };
  const audienceRefused = namesAdminAudience && held.size === 0;
  // An admin scope the grants allow still needs a key to bind the token to;
  // a family scope does not.
  const unbound = (scope: string): boolean =>
    !request.dpopBound && isAdminScope(scope) && allowedByGrants(scope);
  const issuable = (scope: string): boolean => allowedByGrants(scope) && !unbound(scope);
  return {
    scopes: request.scopes.filter(issuable),
    withheld: request.scopes.filter((scope) => !issuable(scope)),
    audienceRefused,
    proofMissing:
      !request.dpopBound &&
      ((namesAdminAudience && !audienceRefused) || request.scopes.some(unbound)),
  };
}
