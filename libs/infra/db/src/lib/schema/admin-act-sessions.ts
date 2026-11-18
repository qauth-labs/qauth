import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  index,
  jsonb,
  pgTable,
  unique,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { realms, users } from './core';

/** The longest an act-chain token lives, in milliseconds: ten minutes (#523). */
export const ADMIN_ACT_SESSION_MAX_LIFETIME_MS = 10 * 60 * 1000;

/**
 * Act-chain tokens issued to admins who act for a user (ADR-019 Decision 7,
 * issue #523).
 *
 * There is no impersonation: an admin who acts for a user gets an act-chain
 * token, whose `sub` is the user and whose `act` names the admin. The token is
 * minted inside the transaction of the approved security operation that
 * issues it (`issue-for-other`), and that transaction writes one row here, so
 * the user's account page can show that an administrator acted for them
 * (`listAdminAccess`), with the admin, the time and the approval it ran on.
 *
 * Every call made with the token reads its row (`findLive`): the token is
 * accepted only while its row is there, unexpired, and the approval it names
 * is still `consumed`; the auth server then checks that the admin still holds
 * the permissions in `permission_ids` on the realm, so revoking the admin's
 * grant stops the token on its next use.
 *
 * - The user belongs to the row's realm (`users_id_realm_id_unique`); deleting
 *   the user or the realm removes the rows.
 * - The admin's columns and the approval's id reference no table, as the
 *   admin audit log's do not: what an admin did for a user stays visible to
 *   the user after the admin's account, or the approval row, is gone. A token
 *   whose approval row is gone is refused.
 * - No secret: the row holds the token's `jti`, never the token.
 * - Written once: no role is granted `UPDATE` or `DELETE` on it.
 */
export const adminActSessions = pgTable(
  'admin_act_sessions',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** The realm of the user acted for, whose issuer is the token's `iss`. */
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The user acted for: the token's `sub`. */
    userId: uuid('user_id').notNull(),
    /** The realm the admin's account lives in: the operator realm, or the user's own. */
    adminRealmId: uuid('admin_realm_id').notNull(),
    /** The admin's account: the token's `act.sub`. */
    adminUserId: uuid('admin_user_id').notNull(),
    /** The client the admin called through: the token's `client_id` and `act.client_id`. */
    adminClientId: varchar('admin_client_id', { length: 255 }).notNull(),
    /** The approval of the security operation that issued the token, in the user's realm. */
    approvalId: uuid('approval_id').notNull(),
    /** The security operation that issued the token, such as `users.actChainTokens.create`. */
    operationId: varchar('operation_id', { length: 128 }).notNull(),
    /**
     * The permission ids that operation needed. The token works only while the
     * admin's live grants on the realm still hold every one of them.
     */
    permissionIds: jsonb('permission_ids').notNull().$type<string[]>(),
    /** The token's `jti`. */
    tokenJti: varchar('token_jti', { length: 255 }).notNull(),
    /** The token's scopes, each an account API scope. */
    scopes: jsonb('scopes').notNull().$type<string[]>(),
    /** Epoch ms: when the token was minted. */
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    /** Epoch ms: the token's `exp`. */
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
  },
  (t) => [
    unique('admin_act_sessions_realm_jti_unique').on(t.realmId, t.tokenJti),
    // The user's page lists the realm's rows of one user, newest first.
    index('idx_admin_act_sessions_user').on(t.realmId, t.userId, t.createdAt),
    foreignKey({
      columns: [t.userId, t.realmId],
      foreignColumns: [users.id, users.realmId],
      name: 'admin_act_sessions_user_realm_fk',
    }).onDelete('cascade'),
    check('admin_act_sessions_admin_client_id_not_empty', sql`${t.adminClientId} <> ''`),
    check('admin_act_sessions_operation_id_not_empty', sql`${t.operationId} <> ''`),
    check('admin_act_sessions_token_jti_not_empty', sql`${t.tokenJti} <> ''`),
    check(
      'admin_act_sessions_scopes_strings',
      sql`jsonb_typeof(${t.scopes}) = 'array' AND jsonb_array_length(${t.scopes}) > 0 AND NOT jsonb_path_exists(${t.scopes}, '$[*] ? (@.type() != "string")')`
    ),
    check(
      'admin_act_sessions_permission_ids_strings',
      sql`jsonb_typeof(${t.permissionIds}) = 'array' AND jsonb_array_length(${t.permissionIds}) > 0 AND NOT jsonb_path_exists(${t.permissionIds}, '$[*] ? (@.type() != "string")')`
    ),
    check(
      'admin_act_sessions_lifetime',
      sql`${t.expiresAt} > ${t.createdAt} AND ${t.expiresAt} - ${t.createdAt} <= ${sql.raw(String(ADMIN_ACT_SESSION_MAX_LIFETIME_MS))}`
    ),
  ]
);
