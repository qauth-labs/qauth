import {
  BadRequestError,
  extractConstraintName,
  isUniqueConstraintError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { and, asc, eq, getTableColumns, type InferSelectModel, isNull, or, sql } from 'drizzle-orm';

import type { Database, DbClient } from '../../types';
import { adminGrants, adminRoles } from '../schema/admin-grants';
import { realms, users } from '../schema/core';
import { EPOCH_MS_NOW } from '../schema/sql-helpers';
import {
  type AdminRole,
  type AdminRolesRepositoryOptions,
  isAdminRecordId,
  requireAdminRoleCatalog,
} from './admin-roles.repository';

/** A stored admin grant (issue #510). */
export type AdminGrant = InferSelectModel<typeof adminGrants>;

/** The role a grant names: a built-in role by name, or a custom role by id. */
export type AdminGrantRole =
  | { readonly kind: 'built-in'; readonly name: string }
  | { readonly kind: 'custom'; readonly roleId: string };

/** A new grant. */
export interface NewAdminGrant {
  /** The account the grant is for. */
  readonly userId: string;
  readonly role: AdminGrantRole;
  /** The realm the grant covers, or `null` for every realm (operator-realm accounts only). */
  readonly targetRealmId: string | null;
  /** The admin who creates it; `null` for the operator CLI or QAuth itself. */
  readonly createdBy: string | null;
}

/** A grant that gives its role's permissions now, with the custom role it names. */
export interface LiveAdminGrant {
  readonly grant: AdminGrant;
  /** The custom role, enabled; `null` when the grant names a built-in role. */
  readonly role: AdminRole | null;
}

/**
 * Admin grants (ADR-019 Decision 7, issue #510). A grant is created and
 * revoked, never changed. Every refusal of the realm rule below is also made
 * by the trigger `admin_grants_realm_rule` for a row written any other way.
 */
export interface AdminGrantsRepository {
  /**
   * Grant an account a role on one realm or on every realm.
   *
   * - Only an account of the operator realm gets a grant on every realm.
   * - An account of any other realm gets grants on its own realm only.
   * - A built-in role is named exactly as the catalog names it. A custom role
   *   must be enabled, and be defined in the account's realm or in the target
   *   realm.
   *
   * @throws BadRequestError when the account, the target realm or the role
   *   does not exist, when the grant breaks the realm rule, when the custom
   *   role is disabled, or when a built-in role is named and the repository
   *   has no catalog
   * @throws UniqueConstraintError when the account already holds a live grant
   *   of that role on that target
   */
  create(grant: NewAdminGrant, tx?: DbClient): Promise<AdminGrant>;

  /** The grant with this id, live or revoked. */
  findById(grantId: string, tx?: DbClient): Promise<AdminGrant | undefined>;

  /** Every grant of the account, revoked ones included, oldest first. */
  listByUser(userId: string, tx?: DbClient): Promise<AdminGrant[]>;

  /**
   * The account's grants that give their role's permissions now: not revoked,
   * and naming a built-in role or an enabled custom role. Read on every admin
   * request, so a revocation or a disabled role counts from the next one. The
   * account's own state and the realm rule are the caller's to check
   * (`resolveAdminAuthority`).
   */
  listLive(userId: string, tx?: DbClient): Promise<LiveAdminGrant[]>;

  /**
   * Revoke a live grant. Its `revoked_at` and `last_security_change_at` are
   * set to now.
   *
   * @returns the revoked grant, or `undefined` when no live grant has this id
   */
  revoke(grantId: string, tx?: DbClient): Promise<AdminGrant | undefined>;
}

/**
 * Factory for admin grants (issue #510). See {@link AdminGrantsRepository}
 * for the guarantees.
 *
 * @param defaultDb - the server's database
 * @param options - the auth server's admin role catalog, for built-in roles
 */
export function createAdminGrantsRepository(
  defaultDb: Database,
  options: AdminRolesRepositoryOptions = {}
): AdminGrantsRepository {
  return {
    async create(grant, tx) {
      const db = tx ?? defaultDb;
      if (!isAdminRecordId(grant.userId)) {
        throw new BadRequestError('An admin grant needs the id of an account');
      }
      if (grant.targetRealmId !== null && !isAdminRecordId(grant.targetRealmId)) {
        throw new BadRequestError('An admin grant targets a realm id, or null for every realm');
      }
      if (grant.createdBy !== null && !isAdminRecordId(grant.createdBy)) {
        throw new BadRequestError('An admin grant is created by an account id, or null');
      }

      const [account] = await db
        .select({ realmId: users.realmId, isOperator: realms.isOperator })
        .from(users)
        .innerJoin(realms, eq(realms.id, users.realmId))
        .where(eq(users.id, grant.userId));
      if (account === undefined) {
        throw new BadRequestError('An admin grant is for an account that exists');
      }
      if (grant.targetRealmId === null) {
        if (!account.isOperator) {
          throw new BadRequestError(
            'Only an account of the operator realm can hold an admin grant on every realm'
          );
        }
      } else {
        if (grant.targetRealmId !== account.realmId && !account.isOperator) {
          throw new BadRequestError(
            'An account outside the operator realm can hold admin grants on its own realm only'
          );
        }
        const [target] = await db
          .select({ id: realms.id })
          .from(realms)
          .where(eq(realms.id, grant.targetRealmId));
        if (target === undefined) {
          throw new BadRequestError('An admin grant targets a realm that exists');
        }
      }

      let role: { builtInRole: string; roleId: null } | { builtInRole: null; roleId: string };
      if (grant.role.kind === 'built-in') {
        const catalog = requireAdminRoleCatalog(options.catalog);
        if (!catalog.builtInRoleNames.includes(grant.role.name)) {
          throw new BadRequestError(`"${String(grant.role.name)}" is not a built-in admin role`);
        }
        role = { builtInRole: grant.role.name, roleId: null };
      } else {
        const roleId = grant.role.roleId;
        const [custom] = isAdminRecordId(roleId)
          ? await db
              .select({ realmId: adminRoles.realmId, disabledAt: adminRoles.disabledAt })
              .from(adminRoles)
              .where(eq(adminRoles.id, roleId))
          : [];
        if (custom === undefined) {
          throw new BadRequestError('An admin grant names a custom role that exists');
        }
        if (custom.realmId !== account.realmId && custom.realmId !== grant.targetRealmId) {
          throw new BadRequestError(
            'A custom admin role is granted only to an account of its realm or for its realm'
          );
        }
        if (custom.disabledAt !== null) {
          throw new BadRequestError('A disabled admin role cannot be granted');
        }
        role = { builtInRole: null, roleId };
      }

      try {
        const [row] = await db
          .insert(adminGrants)
          .values({
            userId: grant.userId,
            ...role,
            targetRealmId: grant.targetRealmId,
            createdBy: grant.createdBy,
          })
          .returning();
        return row;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          throw new UniqueConstraintError(
            extractConstraintName(error) || 'idx_admin_grants_live_unique',
            error
          );
        }
        throw error;
      }
    },

    async findById(grantId, tx) {
      if (!isAdminRecordId(grantId)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .select()
        .from(adminGrants)
        .where(eq(adminGrants.id, grantId));
      return row;
    },

    async listByUser(userId, tx) {
      if (!isAdminRecordId(userId)) return [];
      return (tx ?? defaultDb)
        .select()
        .from(adminGrants)
        .where(eq(adminGrants.userId, userId))
        .orderBy(asc(adminGrants.createdAt), asc(adminGrants.id));
    },

    async listLive(userId, tx) {
      if (!isAdminRecordId(userId)) return [];
      const rows = await (tx ?? defaultDb)
        .select({ grant: getTableColumns(adminGrants), role: getTableColumns(adminRoles) })
        .from(adminGrants)
        .leftJoin(adminRoles, eq(adminRoles.id, adminGrants.roleId))
        .where(
          and(
            eq(adminGrants.userId, userId),
            isNull(adminGrants.revokedAt),
            or(isNull(adminGrants.roleId), isNull(adminRoles.disabledAt))
          )
        )
        .orderBy(asc(adminGrants.createdAt), asc(adminGrants.id));
      return rows.map((row) => ({
        grant: row.grant,
        role: row.grant.roleId === null ? null : row.role,
      }));
    },

    async revoke(grantId, tx) {
      if (!isAdminRecordId(grantId)) return undefined;
      // `greatest` keeps both times at or after the last change, which is at
      // or after the creation time; the epoch-ms default rounds to the second,
      // and the trigger `admin_grants_revoke_only` refuses a time that moves
      // back.
      const now = sql`greatest(${EPOCH_MS_NOW}, ${adminGrants.lastSecurityChangeAt})`;
      const [row] = await (tx ?? defaultDb)
        .update(adminGrants)
        .set({ revokedAt: now, lastSecurityChangeAt: now })
        .where(and(eq(adminGrants.id, grantId), isNull(adminGrants.revokedAt)))
        .returning();
      return row;
    },
  };
}
