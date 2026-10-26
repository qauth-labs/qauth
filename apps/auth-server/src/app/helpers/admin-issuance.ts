/**
 * What an admin scope or the admin audience takes to reach a token (ADR-019
 * Decision 7, issue #510). The token endpoint applies it on every grant that
 * mints an access token or an assertion: authorization_code, refresh_token,
 * client_credentials, token exchange (both outcomes) and the jwt-bearer grant.
 *
 * - An admin scope (`qauth:admin:read`, `:write`, `:security`) is issued only
 *   when the client lists the admin API's audience and the account holds a
 *   live admin grant whose role has a permission of that scope's class. Any
 *   other scope of the reserved `qauth:` namespace is never issued. A scope
 *   that fails is WITHHELD: the token is issued without it, and the response's
 *   `scope` says so (RFC 6749 §3.3).
 * - The admin audience is issued only to an account that holds a live admin
 *   grant. Otherwise the request is refused, `invalid_target` (RFC 8707 §2),
 *   as for an audience the client does not list.
 *
 * Grants are read when the token is issued, so a refresh after a revocation
 * no longer carries what the grant gave. A token that names no account, a
 * `client_credentials` token, never gets either: grants belong to accounts.
 *
 * Nothing is read from the database unless the request asks for a `qauth:`
 * scope or the admin audience.
 */
import { isReservedQauthScope } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';

import { API_FAMILY_AUDIENCES } from '../api-conventions/families';
import { grantedPermissionIds, grantFitsRealmRule } from './admin-authority';
import { PERMISSION_REGISTRY, type PermissionRegistry } from './admin-permissions';
import { type PermissionClass, permissionClassOfScope } from './admin-scopes';
import { type OAuthClientLike, unlistedReservedAudiences } from './client-auth';

/** What {@link adminIssuance} decides about one token. */
export interface AdminIssuanceRequest {
  /** The client the token is issued to. */
  readonly client: Pick<OAuthClientLike, 'audience' | 'metadata' | 'dynamicRegisteredAt'>;
  /** The account the token is for; `null` when it names none (`client_credentials`). */
  readonly userId: string | null;
  /** The scopes the grant would issue. */
  readonly scopes: readonly string[];
  /** The `aud` the token would carry. */
  readonly aud: string | readonly string[];
}

/** The outcome of {@link adminIssuance}. */
export interface AdminIssuance {
  /** The scopes to issue: the requested ones without the withheld ones, in order. */
  readonly scopes: string[];
  /** The `qauth:` scopes left out. */
  readonly withheld: string[];
  /** Whether `aud` names the admin audience for an account that may not have it. */
  readonly audienceRefused: boolean;
}

/**
 * The permission classes, and whether any live grant at all, an account holds
 * for issuance: every live grant that fits the realm rule, whatever its
 * target, since the token is not yet bound to a realm to act on.
 */
async function heldAdminGrants(
  fastify: FastifyInstance,
  userId: string | null,
  registry: PermissionRegistry
): Promise<{ any: boolean; classes: ReadonlySet<PermissionClass> }> {
  const none = { any: false, classes: new Set<PermissionClass>() };
  if (userId === null) return none;
  const user = await fastify.repositories.users.findById(userId);
  if (!user || !user.enabled) return none;
  const accountRealm = await fastify.repositories.realms.findById(user.realmId);
  if (accountRealm === undefined) return none;
  const fitting = (await fastify.repositories.adminGrants.listLive(user.id)).filter((grant) =>
    grantFitsRealmRule(grant, accountRealm)
  );
  const classes = new Set<PermissionClass>();
  for (const grant of fitting) {
    for (const id of grantedPermissionIds(grant)) {
      const permission = registry.isGrantable(id) ? registry.get(id) : undefined;
      if (permission !== undefined) classes.add(permission.class);
    }
  }
  return { any: fitting.length > 0, classes };
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
    return { scopes: [...request.scopes], withheld: [], audienceRefused: false };
  }

  const held = await heldAdminGrants(fastify, request.userId, registry);
  const clientListsAdmin =
    unlistedReservedAudiences(request.client, API_FAMILY_AUDIENCES.admin).length === 0;
  const issuable = (scope: string): boolean => {
    if (!isReservedQauthScope(scope)) return true;
    const permissionClass = permissionClassOfScope(scope);
    return clientListsAdmin && permissionClass !== undefined && held.classes.has(permissionClass);
  };
  return {
    scopes: request.scopes.filter(issuable),
    withheld: request.scopes.filter((scope) => !issuable(scope)),
    audienceRefused: namesAdminAudience && !held.any,
  };
}
