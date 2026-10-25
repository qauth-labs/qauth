/**
 * Admin roles (ADR-019 Decision 7, ADR-020 §3, issue #507).
 *
 * A role is a set of permission ids from the catalog (`admin-permissions.ts`).
 * What a request may do is the intersection of two things:
 *
 *   - the permissions the caller's roles grant, and
 *   - the classes the token's scopes allow (`admin-scopes.ts`).
 *
 * {@link effectivePermissions} computes it. A permission is effective only
 * when its class's scope is in the token, so a token with only `admin:write`
 * never uses a security permission, whatever role the caller holds.
 *
 * BUILT-IN ROLES are defined here, in code, by class: `viewer` holds every
 * read permission, `editor` every read and write permission, and
 * `security-admin` every permission. They follow the catalog, so a permission
 * added to it joins them, and they cannot be edited: the objects are frozen,
 * and no table holds them. CUSTOM ROLES are stored per realm by the admin
 * grants work (#510) and checked with {@link validateCustomRole}.
 *
 * Admin roles are not the `roles` table (`libs/infra/db/src/lib/schema/roles.ts`):
 * that table holds application roles, which reach tokens as claims (ADR-020
 * fork D).
 */
import { PERMISSION_REGISTRY, type PermissionRegistry } from './admin-permissions';
import { allowedPermissionClasses, type PermissionClass } from './admin-scopes';

/** The names of the built-in roles, from the least to the most privileged. */
export const BUILT_IN_ROLE_NAMES = Object.freeze(['viewer', 'editor', 'security-admin'] as const);

export type BuiltInRoleName = (typeof BUILT_IN_ROLE_NAMES)[number];

/** A built-in role: every grantable permission of its classes. */
export interface BuiltInRole {
  readonly name: BuiltInRoleName;
  /** One sentence for the docs page and the admin console. */
  readonly description: string;
  /** The permission classes whose every permission the role holds. */
  readonly classes: readonly PermissionClass[];
  /** The ids of those permissions, in catalog order. */
  readonly permissionIds: readonly string[];
}

const BUILT_IN_ROLE_CLASSES: Readonly<
  Record<BuiltInRoleName, { classes: readonly PermissionClass[]; description: string }>
> = {
  viewer: { classes: ['read'], description: 'Reads everything an admin can read.' },
  editor: {
    classes: ['read', 'write'],
    description: 'Reads, and makes every change that is not a security operation.',
  },
  'security-admin': {
    classes: ['read', 'write', 'security'],
    description: 'Reads, makes every change, and performs security operations.',
  },
};

/** The built-in roles over `registry`, frozen. */
export function builtInRolesOf(
  registry: PermissionRegistry
): Readonly<Record<BuiltInRoleName, BuiltInRole>> {
  const roles = {} as Record<BuiltInRoleName, BuiltInRole>;
  for (const name of BUILT_IN_ROLE_NAMES) {
    const { classes, description } = BUILT_IN_ROLE_CLASSES[name];
    roles[name] = Object.freeze({
      name,
      description,
      classes: Object.freeze([...classes]),
      permissionIds: Object.freeze(
        registry.active
          .filter((permission) => classes.includes(permission.class))
          .map((permission) => permission.id)
      ),
    });
  }
  return Object.freeze(roles);
}

/** The built-in roles over the auth server's catalog. */
export const BUILT_IN_ROLES: Readonly<Record<BuiltInRoleName, BuiltInRole>> =
  builtInRolesOf(PERMISSION_REGISTRY);

/** Whether `name` is the name of a built-in role, which a custom role may not take. */
export function isBuiltInRoleName(name: string): name is BuiltInRoleName {
  return (BUILT_IN_ROLE_NAMES as readonly string[]).includes(name);
}

/** The outcome of {@link validateCustomRole}. */
export type CustomRoleValidation =
  | {
      readonly valid: true;
      /** The role's permission ids, each once, in catalog order. */
      readonly permissionIds: readonly string[];
    }
  | {
      readonly valid: false;
      /** Ids no catalog entry has, in the order given. */
      readonly unknownIds: readonly string[];
      /** Ids of retired permissions, which no role may list any more, in the order given. */
      readonly retiredIds: readonly string[];
    };

/**
 * Check the permission ids of a custom role. Refuses an id the catalog does
 * not know and the id of a retired permission; accepts any set of grantable
 * permissions, security permissions included, since a token still needs
 * `admin:security` to use one.
 */
export function validateCustomRole(
  permissionIds: readonly string[],
  registry: PermissionRegistry = PERMISSION_REGISTRY
): CustomRoleValidation {
  const unknownIds: string[] = [];
  const retiredIds: string[] = [];
  const listed = new Set<string>();
  for (const id of permissionIds) {
    const permission = typeof id === 'string' ? registry.get(id) : undefined;
    if (permission === undefined) unknownIds.push(String(id));
    else if (permission.retiredIn !== undefined) retiredIds.push(id);
    else listed.add(id);
  }
  if (unknownIds.length > 0 || retiredIds.length > 0) {
    return { valid: false, unknownIds, retiredIds };
  }
  return {
    valid: true,
    permissionIds: registry.active
      .filter((permission) => listed.has(permission.id))
      .map((permission) => permission.id),
  };
}

/**
 * The permissions a request may use: those of `rolePermissions` whose class's
 * scope is in `tokenScopes`.
 *
 * - `rolePermissions` is the union of the caller's roles' permission ids.
 * - `tokenScopes` is the token's `scope` claim, space-delimited, or the list
 *   of its scopes.
 *
 * Fails closed: an id the catalog does not know, or a retired one, is never
 * effective, and only the three admin scopes, matched exactly, allow a class.
 * No scope implies another.
 */
export function effectivePermissions(
  rolePermissions: Iterable<string>,
  tokenScopes: string | Iterable<string>,
  registry: PermissionRegistry = PERMISSION_REGISTRY
): ReadonlySet<string> {
  if (typeof rolePermissions === 'string') {
    throw new TypeError('effectivePermissions: rolePermissions is a list of permission ids');
  }
  const allowed = allowedPermissionClasses(tokenScopes);
  const effective = new Set<string>();
  for (const id of rolePermissions) {
    if (!registry.isGrantable(id)) continue;
    const permission = registry.get(id);
    if (permission !== undefined && allowed.has(permission.class)) effective.add(id);
  }
  return effective;
}
