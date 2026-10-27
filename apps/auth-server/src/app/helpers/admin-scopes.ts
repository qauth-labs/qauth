/**
 * Admin scopes (ADR-019 Decision 7, issue #507).
 *
 * The admin API has three scopes, one per permission class:
 *
 *   - `qauth:admin:read`     → `read` permissions
 *   - `qauth:admin:write`    → `write` permissions
 *   - `qauth:admin:security` → `security` permissions
 *
 * The scopes are coarse and INDEPENDENT. No scope implies another:
 * `qauth:admin:write` does not satisfy a read permission, and
 * `qauth:admin:security` satisfies neither a read nor a write permission. A
 * request that needs a write permission and a security permission needs both
 * scopes. Scopes are matched exactly and case-sensitively (RFC 6749 §3.3), as
 * `resource-guard` matches every other scope.
 *
 * A scope alone grants nothing: it is intersected with the caller's admin
 * roles (`effectivePermissions` in `admin-roles.ts`). A role grants
 * permissions; the token's scopes decide which classes of them this token may
 * use.
 *
 * RESERVED NAMESPACE: every scope in the `qauth:` namespace is QAuth's
 * (`@qauth-labs/shared-validation`'s `isReservedQauthScope`, case
 * insensitive). A realm's dynamic registration allowlist cannot hold one, so
 * dynamic registration drops one and the developer API refuses one; a Client
 * ID Metadata Document's `scope` is never stored; discovery never lists one.
 * Other servers' `admin:*` scopes are ordinary scopes, and the reserved
 * `agent:*` scope modes (`scope-modes.ts`) do not collide with the namespace.
 */
import {
  isReservedQauthScope,
  QAUTH_SCOPE_NAMESPACE,
  reservedQauthScopesIn,
} from '@qauth-labs/shared-validation';

import { API_FAMILY_AUDIENCES } from '../api-conventions/families';

export { isReservedQauthScope, QAUTH_SCOPE_NAMESPACE, reservedQauthScopesIn };

/**
 * The classes of admin permission, from the least to the most sensitive. Each
 * permission has exactly one (`admin-permissions.ts`), and each class has
 * exactly one scope.
 */
export const PERMISSION_CLASSES = Object.freeze(['read', 'write', 'security'] as const);

export type PermissionClass = (typeof PERMISSION_CLASSES)[number];

/** The scope that allows each permission class. */
export const ADMIN_SCOPES = Object.freeze({
  read: 'qauth:admin:read',
  write: 'qauth:admin:write',
  security: 'qauth:admin:security',
} as const satisfies Record<PermissionClass, string>);

export type AdminScope = (typeof ADMIN_SCOPES)[PermissionClass];

/** The three admin scopes, in class order. */
export const ADMIN_SCOPE_LIST: readonly AdminScope[] = Object.freeze(
  PERMISSION_CLASSES.map((permissionClass) => ADMIN_SCOPES[permissionClass])
);

const CLASS_OF_SCOPE: ReadonlyMap<string, PermissionClass> = new Map(
  PERMISSION_CLASSES.map((permissionClass) => [ADMIN_SCOPES[permissionClass], permissionClass])
);

/**
 * The permission class an admin scope allows, or `undefined` for any other
 * string. Exact match only: `QAuth:admin:read`, `qauth:admin:read ` and
 * `admin:read` allow nothing.
 */
export function permissionClassOfScope(scope: string): PermissionClass | undefined {
  return CLASS_OF_SCOPE.get(scope);
}

/**
 * A token's scopes as a set. Takes the space-delimited `scope` claim
 * (RFC 6749 §3.3, RFC 9068 §2.2.3) or a list that was already split. A string
 * is never read as a list of characters.
 *
 * The claim is split on the space character only, as RFC 6749 §3.3 delimits
 * it (`resource-guard` splits on any white space). A tab or a line break never
 * appears in a claim QAuth issues, and kept inside a scope it only makes that
 * scope match nothing.
 */
export function tokenScopeSet(scopes: string | Iterable<string>): ReadonlySet<string> {
  if (typeof scopes === 'string') {
    return new Set(scopes.split(' ').filter((scope) => scope.length > 0));
  }
  return new Set(scopes);
}

/** The permission classes a token's scopes allow. */
export function allowedPermissionClasses(
  scopes: string | Iterable<string>
): ReadonlySet<PermissionClass> {
  const allowed = new Set<PermissionClass>();
  for (const scope of tokenScopeSet(scopes)) {
    const permissionClass = permissionClassOfScope(scope);
    if (permissionClass !== undefined) allowed.add(permissionClass);
  }
  return allowed;
}

/**
 * `aud` without the admin API's audience, for a token minted where no admin
 * grant is checked: `/auth/login`, from the system client's stored audience
 * (#510). The client id when nothing else is left, as for a client with no
 * audience. Here, away from the grant checks of `admin-issuance.ts`, so the
 * route reaches no admin grant (#495's route manifest).
 */
export function withoutAdminAudience(
  aud: string | readonly string[],
  clientId: string
): string | string[] {
  const rest = [aud].flat().filter((value) => value !== API_FAMILY_AUDIENCES.admin);
  if (rest.length === 0) return clientId;
  return rest.length === 1 ? rest[0] : rest;
}
