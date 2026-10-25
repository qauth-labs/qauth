/**
 * The admin permission catalog (ADR-019 Decision 7, ADR-018 §5, issue #507).
 *
 * A permission is what an admin role grants and what an admin operation
 * needs: `realms.read`, `realms.policies.write`. Each permission has exactly
 * one class, `read`, `write` or `security`, and a token may use it only when
 * it carries that class's scope (`admin-scopes.ts`, `effectivePermissions` in
 * `admin-roles.ts`).
 *
 * STABLE CONTRACT. The ids are published on the docs site's
 * `reference/admin-permissions.md`, which is generated from this registry
 * (`admin-permissions-page.ts`), and custom roles store them. An id, once
 * published, is never renamed and never reused for another meaning. A
 * permission that is no longer needed is RETIRED, not removed: its entry stays
 * with `retiredIn`, so its id stays taken, no role grants it any more and the
 * page lists it as retired.
 *
 * SECURITY PERMISSIONS. An operation that ADR-019 Decision 7 defines as a
 * security operation ("defined by effect") needs a permission of class
 * `security`, with an id of its own. A security permission never shares an id
 * with a write permission, so no custom role reaches a security operation
 * through `admin:write`. An operation whose request decides whether it is a
 * security operation, such as a policy patch, names a write permission and a
 * security permission (`realms.policies.write`, `realms.policies.security`),
 * and a request that touches both needs both, and so both scopes.
 *
 * A new permission is a new {@link definePermission} entry in
 * {@link ADMIN_PERMISSIONS}, added in the pull request of the operation that
 * needs it.
 */
import { PERMISSION_CLASSES, type PermissionClass } from './admin-scopes';

/** A release tag, as the release that retires a permission is named: `v0.3.0`. */
export type ReleaseTag = `v${number}.${number}.${number}`;

const RELEASE_TAG = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

/**
 * A permission id: lower camelCase segments joined by dots, at least two,
 * such as `realms.read` or `realms.policies.security`. The same shape as an
 * operation id (`api-conventions/openapi-conventions.ts`).
 */
export const PERMISSION_ID_PATTERN = /^[a-z][a-zA-Z0-9]*(?:\.[a-z][a-zA-Z0-9]*)+$/;

/** A resource: one or more lower camelCase segments, such as `realms` or `realms.policies`. */
const RESOURCE_PATTERN = /^[a-z][a-zA-Z0-9]*(?:\.[a-z][a-zA-Z0-9]*)*$/;

/** One entry of the catalog. */
export interface AdminPermission {
  /** The published id, `<resource>.<action>`: `realms.policies.write`. */
  readonly id: string;
  /** The one class of the permission; it names the scope a token needs to use it. */
  readonly class: PermissionClass;
  /** What the permission acts on: the leading segments of the id, such as `realms.policies`. */
  readonly resource: string;
  /** One sentence for the docs page and the role editor. */
  readonly description: string;
  /**
   * The release that retired the permission. A retired permission keeps its
   * id, so the id is never reused, but it grants nothing and no role may list
   * it any more.
   */
  readonly retiredIn?: ReleaseTag;
}

/** A catalog entry refused by {@link definePermission} or {@link createPermissionRegistry}. */
export class PermissionDefinitionError extends Error {
  override readonly name = 'PermissionDefinitionError';
}

/** Throws {@link PermissionDefinitionError} when `permission` is not well formed. */
function assertPermission(permission: AdminPermission): void {
  const { id, resource, description, retiredIn } = permission;
  const where = `permission ${JSON.stringify(id)}`;
  if (typeof id !== 'string' || !PERMISSION_ID_PATTERN.test(id)) {
    throw new PermissionDefinitionError(
      `${where}: an id is lower camelCase segments joined by dots, such as realms.read`
    );
  }
  if (!PERMISSION_CLASSES.includes(permission.class)) {
    throw new PermissionDefinitionError(
      `${where}: the class must be one of ${PERMISSION_CLASSES.join(', ')}`
    );
  }
  if (
    typeof resource !== 'string' ||
    !RESOURCE_PATTERN.test(resource) ||
    !id.startsWith(`${resource}.`)
  ) {
    throw new PermissionDefinitionError(
      `${where}: the resource must be the leading segments of the id, such as realms for realms.read`
    );
  }
  // An id that ends in a class name says that class. `realms.policies.security`
  // declared as `write` would read as a security permission on the page and in
  // the role editor while `admin:write` reached it.
  const action = id.slice(id.lastIndexOf('.') + 1);
  if ((PERMISSION_CLASSES as readonly string[]).includes(action) && action !== permission.class) {
    throw new PermissionDefinitionError(
      `${where}: an id that ends in .${action} must have the class ${action}`
    );
  }
  if (
    typeof description !== 'string' ||
    description.length === 0 ||
    description.trim() !== description ||
    /[\r\n]/.test(description)
  ) {
    throw new PermissionDefinitionError(`${where}: the description is one line of text`);
  }
  if (retiredIn !== undefined && !RELEASE_TAG.test(retiredIn)) {
    throw new PermissionDefinitionError(
      `${where}: retiredIn is the tag of the release that retired it, such as v0.3.0`
    );
  }
}

/**
 * Define one permission of the catalog.
 *
 * @throws {PermissionDefinitionError} when the id, class, resource,
 *   description or retiring release is not well formed
 */
export function definePermission(permission: AdminPermission): AdminPermission {
  assertPermission(permission);
  return Object.freeze({ ...permission });
}

/** A catalog: every permission once, looked up by id. */
export interface PermissionRegistry {
  /** Every permission, retired ones included, in definition order. */
  readonly all: readonly AdminPermission[];
  /** The permissions a role can grant: every one that is not retired. */
  readonly active: readonly AdminPermission[];
  /** The permission with this exact id, retired or not; `undefined` for an unknown id. */
  get(id: string): AdminPermission | undefined;
  /** Whether `id` names a permission a role can grant now: known and not retired. */
  isGrantable(id: string): boolean;
  /** The grantable permissions of one class, in definition order. */
  ofClass(permissionClass: PermissionClass): readonly AdminPermission[];
}

/**
 * Build a catalog from its definitions.
 *
 * @throws {PermissionDefinitionError} when two permissions have the same id,
 *   or ids that differ only in case, or when an entry is not well formed
 */
export function createPermissionRegistry(
  permissions: readonly AdminPermission[]
): PermissionRegistry {
  const byId = new Map<string, AdminPermission>();
  const byFoldedId = new Map<string, string>();
  for (const permission of permissions) {
    assertPermission(permission);
    const folded = permission.id.toLowerCase();
    const taken = byFoldedId.get(folded);
    if (taken !== undefined) {
      throw new PermissionDefinitionError(
        taken === permission.id
          ? `permission ${JSON.stringify(permission.id)} is defined twice; an id names one permission`
          : `permissions ${JSON.stringify(taken)} and ${JSON.stringify(permission.id)} differ only in case`
      );
    }
    byFoldedId.set(folded, permission.id);
    byId.set(permission.id, Object.freeze({ ...permission }));
  }

  const all = Object.freeze([...byId.values()]);
  const active = Object.freeze(all.filter((permission) => permission.retiredIn === undefined));
  const byClass = new Map<PermissionClass, readonly AdminPermission[]>(
    PERMISSION_CLASSES.map((permissionClass) => [
      permissionClass,
      Object.freeze(active.filter((permission) => permission.class === permissionClass)),
    ])
  );

  return Object.freeze({
    all,
    active,
    get: (id: string) => byId.get(id),
    isGrantable: (id: string) => {
      const permission = byId.get(id);
      return permission !== undefined && permission.retiredIn === undefined;
    },
    ofClass: (permissionClass: PermissionClass) => byClass.get(permissionClass) ?? [],
  });
}

/**
 * Every admin permission. The first operations of the admin API need these:
 * reading a realm and patching its policies (#517), exporting it (#530),
 * planning a realm-file import (#518), and the approval requests of security
 * operations (#512).
 */
export const ADMIN_PERMISSIONS: readonly AdminPermission[] = Object.freeze([
  definePermission({
    id: 'realms.read',
    class: 'read',
    resource: 'realms',
    description: "Read a realm's representation, with its settings and policies.",
  }),
  definePermission({
    id: 'realms.export',
    class: 'read',
    resource: 'realms',
    description: "Export a realm's configuration as a realm file, which holds no secret value.",
  }),
  definePermission({
    id: 'realms.import.plan',
    class: 'read',
    resource: 'realms',
    description:
      'Compute the dry-run plan of a realm-file import: every change it would make and the permissions each needs. It applies nothing.',
  }),
  definePermission({
    id: 'realms.policies.write',
    class: 'write',
    resource: 'realms.policies',
    description:
      'Change a realm policy whose change is not a security operation, such as a token lifespan.',
  }),
  definePermission({
    id: 'realms.policies.security',
    class: 'security',
    resource: 'realms.policies',
    description:
      'Change a realm policy whose change is a security operation, such as loosening the sign-in methods or the password policy.',
  }),
  definePermission({
    id: 'approvals.read',
    class: 'read',
    resource: 'approvals',
    description: 'Read the approval requests of security operations and where each one stands.',
  }),
  definePermission({
    id: 'approvals.approve',
    class: 'security',
    resource: 'approvals',
    description: "Approve another admin's security operation, with a fresh passkey.",
  }),
]);

/** The catalog the auth server authorizes against. */
export const PERMISSION_REGISTRY: PermissionRegistry = createPermissionRegistry(ADMIN_PERMISSIONS);
