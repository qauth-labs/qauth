import {
  BadRequestError,
  extractConstraintName,
  isUniqueConstraintError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { and, asc, eq, type InferSelectModel, isNull, sql } from 'drizzle-orm';

import type { DbClient } from '../../types';
import {
  ADMIN_ROLE_NAME_MAX_LENGTH,
  ADMIN_ROLE_NAME_PATTERN,
  adminGrants,
  adminRoles,
} from '../schema/admin-grants';
import { EPOCH_MS_NOW } from '../schema/sql-helpers';

/** A stored custom admin role (issue #510). */
export type AdminRole = InferSelectModel<typeof adminRoles>;

/** What the auth server's permission catalog says about a list of permission ids. */
export type AdminRolePermissionCheck =
  | {
      readonly valid: true;
      /** The ids, each once, in catalog order: what is stored. */
      readonly permissionIds: readonly string[];
    }
  | {
      readonly valid: false;
      /** Ids no catalog entry has. */
      readonly unknownIds: readonly string[];
      /** Ids of retired permissions, which no role may list any more. */
      readonly retiredIds: readonly string[];
    };

/**
 * The admin role catalog the repositories check against (issue #510). The
 * auth server owns the permission catalog and the built-in roles
 * (`admin-permissions.ts`, `admin-roles.ts`), so it supplies this through the
 * database plugin; this library cannot import them.
 */
export interface AdminRoleCatalog {
  /** The built-in roles' names. A grant names one of them exactly. */
  readonly builtInRoleNames: readonly string[];
  /**
   * Whether `name` reads as a built-in role's name, compared the way a reader
   * compares names (`isBuiltInRoleName`). A custom role may not take one.
   */
  isBuiltInRoleName(name: string): boolean;
  /** Check a custom role's permission ids (`validateCustomRole`, #507). */
  validatePermissionIds(permissionIds: readonly string[]): AdminRolePermissionCheck;
}

/** Options of {@link createAdminRolesRepository} and `createAdminGrantsRepository`. */
export interface AdminRolesRepositoryOptions {
  /**
   * The catalog. Without one, no custom role is created or changed and no
   * grant names a built-in role: nothing can say which ids or names are valid.
   */
  readonly catalog?: AdminRoleCatalog;
}

/** A new custom role. */
export interface NewAdminRole {
  /** The realm it is defined in. */
  readonly realmId: string;
  /** {@link ADMIN_ROLE_NAME_PATTERN}, at most 64 characters, never a built-in role's name. */
  readonly name: string;
  /** Permission catalog ids; stored once each, in catalog order. */
  readonly permissionIds: readonly string[];
}

/** What {@link AdminRolesRepository.update} changes; a member left out stays. */
export interface AdminRoleChanges {
  readonly permissionIds?: readonly string[];
  /** `true` disables the role, `false` enables it again. */
  readonly disabled?: boolean;
}

/**
 * Custom admin roles (ADR-019 Decision 7, issue #510). Built-in roles are not
 * stored; see `admin_roles` in the schema.
 */
export interface AdminRolesRepository {
  /**
   * Create a custom role in a realm.
   *
   * @throws BadRequestError when the name is not in the grammar, reads as a
   *   built-in role's name, or a permission id is unknown or retired, or when
   *   the repository has no catalog
   * @throws UniqueConstraintError when the realm has a role of that name
   */
  create(role: NewAdminRole, tx?: DbClient): Promise<AdminRole>;

  /** The realm's role with this id; `undefined` for an id of another realm. */
  findById(realmId: string, roleId: string, tx?: DbClient): Promise<AdminRole | undefined>;

  /** The realm's roles, disabled ones included, by name. */
  listByRealm(realmId: string, tx?: DbClient): Promise<AdminRole[]>;

  /**
   * Change a role's permissions or disable or enable it. Every grant that
   * names the role gets a new `last_security_change_at` in the same
   * transaction when what the role gives changes: its permission set, or
   * whether it is disabled. Takes effect on the next request.
   *
   * @returns the role as stored, or `undefined` when the realm has no role
   *   with this id
   * @throws BadRequestError when a permission id is unknown or retired, or
   *   when the repository has no catalog
   */
  update(
    realmId: string,
    roleId: string,
    changes: AdminRoleChanges,
    tx?: DbClient
  ): Promise<AdminRole | undefined>;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Refuse an id that is not a UUID before it reaches Postgres (22P02 → 500). */
export function isAdminRecordId(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

/** The catalog, or a refusal: nothing can say which ids or names are valid without it. */
export function requireAdminRoleCatalog(catalog: AdminRoleCatalog | undefined): AdminRoleCatalog {
  if (catalog === undefined) {
    throw new BadRequestError(
      'No admin role catalog was configured: admin roles and grants cannot be written'
    );
  }
  return catalog;
}

/** Whether `name` fits the admin role name grammar. */
export function isAdminRoleName(name: unknown): name is string {
  return (
    typeof name === 'string' &&
    name.length <= ADMIN_ROLE_NAME_MAX_LENGTH &&
    ADMIN_ROLE_NAME_PATTERN.test(name)
  );
}

/** The catalog-normalised permission ids, or a refusal naming the bad ones. */
function checkedPermissionIds(
  catalog: AdminRoleCatalog,
  permissionIds: readonly string[]
): readonly string[] {
  if (!Array.isArray(permissionIds)) {
    throw new BadRequestError('An admin role holds a list of permission ids');
  }
  const check = catalog.validatePermissionIds(permissionIds);
  if (check.valid) return check.permissionIds;
  const parts = [
    ...(check.unknownIds.length > 0 ? [`unknown: ${check.unknownIds.join(', ')}`] : []),
    ...(check.retiredIds.length > 0 ? [`retired: ${check.retiredIds.join(', ')}`] : []),
  ];
  throw new BadRequestError(`An admin role lists permissions it cannot hold (${parts.join('; ')})`);
}

function sameIds(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((id, index) => id === b[index]);
}

/**
 * Factory for custom admin roles (issue #510). See
 * {@link AdminRolesRepository} for the guarantees.
 *
 * @param defaultDb - the server's database
 * @param options - the auth server's admin role catalog
 */
export function createAdminRolesRepository(
  defaultDb: DbClient,
  options: AdminRolesRepositoryOptions = {}
): AdminRolesRepository {
  return {
    async create(role, tx) {
      const catalog = requireAdminRoleCatalog(options.catalog);
      if (!isAdminRecordId(role.realmId)) {
        throw new BadRequestError('An admin role needs the id of its realm');
      }
      if (!isAdminRoleName(role.name)) {
        throw new BadRequestError(
          'An admin role name is lower-case ASCII letters and digits in words joined by single hyphens, starting with a letter, at most 64 characters'
        );
      }
      if (catalog.isBuiltInRoleName(role.name)) {
        throw new BadRequestError(`"${role.name}" is the name of a built-in admin role`);
      }
      const permissionIds = checkedPermissionIds(catalog, role.permissionIds);
      try {
        const [row] = await (tx ?? defaultDb)
          .insert(adminRoles)
          .values({ realmId: role.realmId, name: role.name, permissionIds: [...permissionIds] })
          .returning();
        return row;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          throw new UniqueConstraintError(
            extractConstraintName(error) || 'admin_roles_realm_name_unique',
            error
          );
        }
        throw error;
      }
    },

    async findById(realmId, roleId, tx) {
      if (!isAdminRecordId(realmId) || !isAdminRecordId(roleId)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .select()
        .from(adminRoles)
        .where(and(eq(adminRoles.id, roleId), eq(adminRoles.realmId, realmId)));
      return row;
    },

    async listByRealm(realmId, tx) {
      if (!isAdminRecordId(realmId)) return [];
      return (tx ?? defaultDb)
        .select()
        .from(adminRoles)
        .where(eq(adminRoles.realmId, realmId))
        .orderBy(asc(adminRoles.name));
    },

    async update(realmId, roleId, changes, tx) {
      const catalog = requireAdminRoleCatalog(options.catalog);
      if (!isAdminRecordId(realmId) || !isAdminRecordId(roleId)) return undefined;
      const permissionIds =
        changes.permissionIds === undefined
          ? undefined
          : checkedPermissionIds(catalog, changes.permissionIds);

      return (tx ?? defaultDb).transaction(async (inner) => {
        const [current] = await inner
          .select()
          .from(adminRoles)
          .where(and(eq(adminRoles.id, roleId), eq(adminRoles.realmId, realmId)))
          .for('update');
        if (current === undefined) return undefined;

        const permissionsChange =
          permissionIds !== undefined && !sameIds(permissionIds, current.permissionIds);
        const disabledChange =
          changes.disabled !== undefined && changes.disabled !== (current.disabledAt !== null);
        if (!permissionsChange && !disabledChange) return current;

        const [row] = await inner
          .update(adminRoles)
          .set({
            ...(permissionsChange ? { permissionIds: [...(permissionIds ?? [])] } : {}),
            ...(disabledChange ? { disabledAt: changes.disabled ? EPOCH_MS_NOW : null } : {}),
            updatedAt: EPOCH_MS_NOW,
          })
          .where(eq(adminRoles.id, roleId))
          .returning();
        // What every grant of the role gives changed with it (the two-admin
        // rule reads this, ADR-019 Decision 7). Revoked grants give nothing,
        // so they keep the time of their revocation.
        await inner
          .update(adminGrants)
          .set({
            lastSecurityChangeAt: sql`greatest(${EPOCH_MS_NOW}, ${adminGrants.lastSecurityChangeAt})`,
          })
          .where(and(eq(adminGrants.roleId, roleId), isNull(adminGrants.revokedAt)));
        return row;
      });
    },
  };
}
