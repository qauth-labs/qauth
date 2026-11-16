import { and, desc, eq, exists, gt, type InferSelectModel } from 'drizzle-orm';

import type { DbClient } from '../../types';
import { ADMIN_ACT_SESSION_MAX_LIFETIME_MS, adminActSessions } from '../schema/admin-act-sessions';
import { adminApprovals } from '../schema/admin-approvals';
import { isAdminRecordId } from './admin-roles.repository';

/** An act-chain token issued to an admin who acts for a user (issue #523). */
export type AdminActSession = InferSelectModel<typeof adminActSessions>;

/** A new act-chain token's row, written in the transaction that mints it. */
export interface NewAdminActSession {
  readonly realmId: string;
  readonly userId: string;
  readonly adminRealmId: string;
  readonly adminUserId: string;
  readonly adminClientId: string;
  readonly approvalId: string;
  readonly operationId: string;
  readonly permissionIds: readonly string[];
  readonly tokenJti: string;
  readonly scopes: readonly string[];
  /** Epoch ms. */
  readonly createdAt: number;
  /** Epoch ms: the token's `exp`, at most ten minutes after `createdAt`. */
  readonly expiresAt: number;
}

/** The most rows {@link AdminActSessionsRepository.listForUser} answers, and its default. */
export const ADMIN_ACT_SESSIONS_LIST_MAX = 100;

/**
 * Act-chain tokens issued to admins (ADR-019 Decision 7, issue #523). See the
 * table (`schema/admin-act-sessions.ts`).
 */
export interface AdminActSessionsRepository {
  /**
   * Write the row of a token just minted, in the transaction of the security
   * operation that minted it, so the row, the operation's audit row and the
   * consumed approval commit together or not at all.
   *
   * @throws {RangeError} for a lifetime over ten minutes, empty scopes or permissions
   */
  create(tx: DbClient, session: NewAdminActSession): Promise<AdminActSession>;

  /**
   * The row of the token `jti` of `realmId` while the token may still be
   * used at `now`: unexpired, and the approval it names is still in the realm
   * and `consumed`. `undefined` otherwise, alike for an unknown token. Whether
   * the admin still holds the row's permissions is the caller's check: the
   * permissions come from the auth server's catalog.
   */
  findLive(realmId: string, jti: string, now: number): Promise<AdminActSession | undefined>;

  /**
   * The act-chain tokens issued for `userId` in `realmId`, newest first, at
   * most `limit` ({@link ADMIN_ACT_SESSIONS_LIST_MAX} by default and at most).
   */
  listForUser(
    realmId: string,
    userId: string,
    options?: { readonly limit?: number }
  ): Promise<AdminActSession[]>;
}

/** Each a non-empty list of non-empty strings, once each. */
function assertNamesList(name: string, values: readonly string[]): string[] {
  if (
    !Array.isArray(values) ||
    values.length === 0 ||
    values.some((value) => typeof value !== 'string' || value.length === 0) ||
    new Set(values).size !== values.length
  ) {
    throw new RangeError(`admin act session: ${name} is a non-empty list of distinct names`);
  }
  return [...values];
}

/**
 * Create the act-chain token repository.
 *
 * @param defaultDb - The database the reads run on.
 */
export function createAdminActSessionsRepository(defaultDb: DbClient): AdminActSessionsRepository {
  return {
    async create(tx, session) {
      const lifetime = session.expiresAt - session.createdAt;
      if (
        !Number.isSafeInteger(session.createdAt) ||
        !Number.isSafeInteger(session.expiresAt) ||
        lifetime <= 0 ||
        lifetime > ADMIN_ACT_SESSION_MAX_LIFETIME_MS
      ) {
        throw new RangeError('admin act session: a token lives at most ten minutes');
      }
      const [row] = await tx
        .insert(adminActSessions)
        .values({
          realmId: session.realmId,
          userId: session.userId,
          adminRealmId: session.adminRealmId,
          adminUserId: session.adminUserId,
          adminClientId: session.adminClientId,
          approvalId: session.approvalId,
          operationId: session.operationId,
          permissionIds: assertNamesList('permissionIds', session.permissionIds),
          tokenJti: session.tokenJti,
          scopes: assertNamesList('scopes', session.scopes),
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
        })
        .returning();
      return row;
    },

    async findLive(realmId, jti, now) {
      if (!isAdminRecordId(realmId) || typeof jti !== 'string' || jti.length === 0) {
        return undefined;
      }
      const [row] = await defaultDb
        .select()
        .from(adminActSessions)
        .where(
          and(
            eq(adminActSessions.realmId, realmId),
            eq(adminActSessions.tokenJti, jti),
            gt(adminActSessions.expiresAt, now),
            exists(
              defaultDb
                .select({ id: adminApprovals.id })
                .from(adminApprovals)
                .where(
                  and(
                    eq(adminApprovals.realmId, adminActSessions.realmId),
                    eq(adminApprovals.id, adminActSessions.approvalId),
                    eq(adminApprovals.status, 'consumed')
                  )
                )
            )
          )
        )
        .limit(1);
      return row;
    },

    async listForUser(realmId, userId, options = {}) {
      if (!isAdminRecordId(realmId) || !isAdminRecordId(userId)) return [];
      const asked = options.limit;
      const limit =
        typeof asked === 'number' && Number.isFinite(asked)
          ? Math.min(Math.max(1, Math.floor(asked)), ADMIN_ACT_SESSIONS_LIST_MAX)
          : ADMIN_ACT_SESSIONS_LIST_MAX;
      return defaultDb
        .select()
        .from(adminActSessions)
        .where(and(eq(adminActSessions.realmId, realmId), eq(adminActSessions.userId, userId)))
        .orderBy(desc(adminActSessions.createdAt), desc(adminActSessions.id))
        .limit(limit);
    },
  };
}
