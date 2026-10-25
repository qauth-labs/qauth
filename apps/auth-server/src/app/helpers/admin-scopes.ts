/**
 * Admin scopes (ADR-019 Decision 7, issue #507).
 *
 * The admin API has three scopes, one per permission class:
 *
 *   - `admin:read`     → `read` permissions
 *   - `admin:write`    → `write` permissions
 *   - `admin:security` → `security` permissions
 *
 * The scopes are coarse and INDEPENDENT. No scope implies another:
 * `admin:write` does not satisfy a read permission, and `admin:security`
 * satisfies neither a read nor a write permission. A request that needs a
 * write permission and a security permission needs both scopes. Scopes are matched
 * exactly and case-sensitively (RFC 6749 §3.3), as `resource-guard` matches
 * every other scope.
 *
 * A scope alone grants nothing: it is intersected with the caller's admin
 * roles (`effectivePermissions` in `admin-roles.ts`). A role grants
 * permissions; the token's scopes decide which classes of them this token may
 * use.
 *
 * RESERVED PREFIX: every scope that starts with `admin:` belongs to the admin
 * API (`@qauth-labs/shared-validation`'s `isReservedAdminScope`, case
 * insensitive). Dynamic registration and Client ID Metadata Documents refuse
 * one, a realm's dynamic registration allowlist cannot hold one, and discovery
 * never lists one. The reserved `agent:*` scope modes (`scope-modes.ts`) do
 * not collide with it.
 */
import {
  isReservedAdminScope,
  RESERVED_ADMIN_SCOPE_PREFIX,
  reservedAdminScopesIn,
} from '@qauth-labs/shared-validation';

export { isReservedAdminScope, reservedAdminScopesIn };

/**
 * The classes of admin permission, from the least to the most sensitive. Each
 * permission has exactly one (`admin-permissions.ts`), and each class has
 * exactly one scope.
 */
export const PERMISSION_CLASSES = ['read', 'write', 'security'] as const;

export type PermissionClass = (typeof PERMISSION_CLASSES)[number];

/** The prefix every admin scope starts with, reserved for the admin API. */
export const ADMIN_SCOPE_PREFIX = RESERVED_ADMIN_SCOPE_PREFIX;

/** The scope that allows each permission class. */
export const ADMIN_SCOPES = Object.freeze({
  read: 'admin:read',
  write: 'admin:write',
  security: 'admin:security',
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
 * string. Exact match only: `Admin:read` and `admin:read ` allow nothing.
 */
export function permissionClassOfScope(scope: string): PermissionClass | undefined {
  return CLASS_OF_SCOPE.get(scope);
}

/**
 * A token's scopes as a set. Takes the space-delimited `scope` claim
 * (RFC 6749 §3.3, RFC 9068 §2.2.3) or a list that was already split. A string
 * is never read as a list of characters.
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
