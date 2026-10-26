import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  index,
  jsonb,
  pgTable,
  unique,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { realms, users } from './core';
import { EPOCH_MS_NOW, JSONB_EMPTY_ARRAY } from './sql-helpers';

/** The longest name a custom admin role, or a built-in role a grant names, may have. */
export const ADMIN_ROLE_NAME_MAX_LENGTH = 64;

/**
 * The grammar of an admin role name (issue #510): lower-case ASCII letters and
 * digits in words joined by single hyphens, starting with a letter, such as
 * `support` or `realm-auditor`. Every built-in role name (`viewer`, `editor`,
 * `security-admin`) fits it, and a name in it cannot hide a look-alike letter,
 * an invisible character or a second spelling of another name, so names
 * compare byte for byte. The CHECKs below hold the same rule.
 */
export const ADMIN_ROLE_NAME_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

/** {@link ADMIN_ROLE_NAME_PATTERN} as a POSIX regular expression for the CHECKs. */
const ADMIN_ROLE_NAME_SQL = '^[a-z][a-z0-9]*(-[a-z0-9]+)*$';

/**
 * Custom admin roles (ADR-019 Decision 7, ADR-020 §3, issue #510).
 *
 * A custom role is a named set of permission ids from the auth server's
 * permission catalog (`admin-permissions.ts`), defined in one realm. The
 * built-in roles (`viewer`, `editor`, `security-admin`) are not rows: they are
 * defined in code and follow the catalog, so a grant names one by its name
 * instead (`admin_grants.built_in_role`).
 *
 * These are not the application roles of `roles` and `user_roles`, which
 * reach tokens as claims (ADR-020 fork D). An admin role never reaches a
 * token: the admin API reads it from here on every request.
 *
 * - `permission_ids` is validated against the catalog by the repository
 *   (`validateCustomRole`, #507) and stored in catalog order, each id once.
 *   A permission the catalog retires later stays listed and grants nothing.
 * - A role is never deleted while a grant names it, revoked grants included
 *   (the foreign key from `admin_grants` refuses it): it is disabled instead.
 *   A disabled role grants nothing from the next request on. Deleting the
 *   realm removes its roles together with every grant that names them; the
 *   key is checked at the end of the statement, so that cascade passes.
 * - Which grants may name a role: those whose account lives in the role's
 *   realm, or whose target realm is the role's realm. The trigger
 *   `admin_grants_realm_rule` checks it on every grant.
 */
export const adminRoles = pgTable(
  'admin_roles',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** The realm the role is defined in. */
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** Unique in its realm; never a built-in role's name (the repository refuses one). */
    name: varchar('name', { length: ADMIN_ROLE_NAME_MAX_LENGTH }).notNull(),
    /** Permission catalog ids, in catalog order. */
    permissionIds: jsonb('permission_ids').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    /** When the role was disabled, in epoch ms; NULL while it grants its permissions. */
    disabledAt: bigint('disabled_at', { mode: 'number' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    unique('admin_roles_realm_name_unique').on(t.realmId, t.name),
    check('admin_roles_name_grammar', sql`${t.name} ~ ${sql.raw(`'${ADMIN_ROLE_NAME_SQL}'`)}`),
    check(
      'admin_roles_permission_ids_strings',
      sql`jsonb_typeof(${t.permissionIds}) = 'array' AND NOT jsonb_path_exists(${t.permissionIds}, '$[*] ? (@.type() != "string")')`
    ),
  ]
);

/**
 * Admin grants (ADR-019 Decision 7, issue #510): which account may administer
 * which realm, through which role.
 *
 * A grant names exactly one role: a built-in role by name, or a custom role
 * of `admin_roles`. Its target is one realm, or every realm (`target_realm_id`
 * NULL).
 *
 * The realm rule, held by the repository and by the trigger
 * `admin_grants_realm_rule` for every writer:
 *
 * - Only an account of the operator realm holds a grant on every realm
 *   (`admin_grants_all_realms_operator_only`).
 * - An account of any other realm holds grants on its own realm only
 *   (`admin_grants_target_own_realm`): a realm-local admin never manages
 *   another realm, nor the operator realm.
 * - A custom role is named only by a grant whose account lives in the role's
 *   realm or whose target is the role's realm (`admin_grants_role_realm`).
 *
 * The rule is checked when the grant is written. If the operator flag moves to
 * another realm later, `resolveAdminAuthority` in the auth server applies the
 * rule again on every request, so a grant that no longer fits it grants
 * nothing.
 *
 * A grant is never changed, only revoked. Its account, role and target are
 * fixed; a different grant is a new row. Revocation takes effect on the next
 * request, because the admin API reads grants on every request and never from
 * a token.
 *
 * `last_security_change_at` is the last time what the grant gives changed: its
 * creation, its revocation, and every change of its custom role's permissions
 * or of whether the role is disabled. The two-admin rule reads it (ADR-019
 * Decision 7: an approver was not granted a role in the 7 days before the
 * request).
 */
export const adminGrants = pgTable(
  'admin_grants',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** The account the grant is for. */
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /** A built-in role's name; NULL when the grant names a custom role. */
    builtInRole: varchar('built_in_role', { length: ADMIN_ROLE_NAME_MAX_LENGTH }),
    /** A custom role; NULL when the grant names a built-in role. */
    roleId: uuid('role_id').references(() => adminRoles.id, { onDelete: 'no action' }),
    /** The realm the grant covers; NULL for every realm. */
    targetRealmId: uuid('target_realm_id').references(() => realms.id, { onDelete: 'cascade' }),
    /**
     * The admin who created the grant. NULL when the operator CLI or QAuth
     * itself created it, or when that admin's account was deleted since; the
     * admin events keep who it was.
     */
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    /** When the grant was revoked, in epoch ms; NULL while it is live. */
    revokedAt: bigint('revoked_at', { mode: 'number' }),
    lastSecurityChangeAt: bigint('last_security_change_at', { mode: 'number' })
      .notNull()
      .default(EPOCH_MS_NOW),
  },
  (t) => [
    // One live grant per account, role and target: granting it again is a
    // conflict, not a second row that would have to be revoked twice.
    uniqueIndex('idx_admin_grants_live_unique')
      .on(
        t.userId,
        sql`coalesce('custom:' || ${t.roleId}::text, 'built-in:' || ${t.builtInRole})`,
        sql`coalesce(${t.targetRealmId}::text, '*')`
      )
      .where(sql`${t.revokedAt} IS NULL`),
    index('idx_admin_grants_user_id').on(t.userId),
    index('idx_admin_grants_role_id').on(t.roleId),
    index('idx_admin_grants_target_realm_id').on(t.targetRealmId),
    check('admin_grants_one_role', sql`(${t.builtInRole} IS NULL) <> (${t.roleId} IS NULL)`),
    check(
      'admin_grants_built_in_role_grammar',
      sql`${t.builtInRole} ~ ${sql.raw(`'${ADMIN_ROLE_NAME_SQL}'`)}`
    ),
    check(
      'admin_grants_revoked_after_created',
      sql`${t.revokedAt} IS NULL OR ${t.revokedAt} >= ${t.createdAt}`
    ),
  ]
);
