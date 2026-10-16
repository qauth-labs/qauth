import { NotFoundError } from '@qauth-labs/shared-errors';
import { and, eq, gt, lt } from 'drizzle-orm';

import type {
  AuthorizationCode,
  AuthorizationCodesRepository,
  NewAuthorizationCode,
} from '../../types';
import { DbClient } from '../db';
import { authorizationCodes } from '../schema/tokens';

/**
 * Factory function that creates an authorization codes repository
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository object with authorization code methods
 */
export function createAuthorizationCodesRepository(
  defaultDb: DbClient
): AuthorizationCodesRepository {
  return {
    /**
     * Create a new authorization code
     *
     * @param data - Authorization code data to create
     * @param tx - Optional transaction client
     * @returns Created authorization code
     */
    async create(data: NewAuthorizationCode, tx?: DbClient): Promise<AuthorizationCode> {
      const invoker = tx ?? defaultDb;
      const [authCode] = await invoker.insert(authorizationCodes).values(data).returning();
      return authCode;
    },

    /**
     * Find an authorization code by its code value
     * Only returns codes that are not used and not expired
     *
     * @param code - Authorization code value
     * @param tx - Optional transaction client
     * @returns Authorization code if found and valid, undefined otherwise
     */
    async findByCode(code: string, tx?: DbClient): Promise<AuthorizationCode | undefined> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [result] = await invoker
        .select()
        .from(authorizationCodes)
        .where(
          and(
            eq(authorizationCodes.code, code),
            eq(authorizationCodes.used, false),
            gt(authorizationCodes.expiresAt, now)
          )
        )
        .limit(1);

      return result;
    },

    /**
     * Mark a code as used (atomic operation)
     * Sets used=true and usedAt=now only if not already used.
     * Prevents race conditions where two concurrent requests could both use the same code.
     *
     * @param id - Authorization code ID to mark as used
     * @param tx - Optional transaction client
     * @returns Updated authorization code
     * @throws NotFoundError if authorization code is not found or already used
     */
    async markUsed(id: string, tx?: DbClient): Promise<AuthorizationCode> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [authCode] = await invoker
        .update(authorizationCodes)
        .set({
          used: true,
          usedAt: now,
        })
        .where(and(eq(authorizationCodes.id, id), eq(authorizationCodes.used, false)))
        .returning();

      if (!authCode) {
        throw new NotFoundError('AuthorizationCode', id);
      }

      return authCode;
    },

    /**
     * Invalidate all unredeemed codes for a user
     * Useful for security events (logout, password change, account compromise)
     *
     * Expiry is not part of the predicate: a redemption checks it in
     * `findByCode` only, so a code that expired right after that read is still
     * spent by the `markUsed` that follows and must be caught here too.
     *
     * @param userId - User ID whose codes should be invalidated
     * @param tx - Optional transaction client
     * @returns Number of invalidated codes
     */
    async invalidateForUser(userId: string, tx?: DbClient): Promise<number> {
      const invoker = tx ?? defaultDb;

      const result = await invoker
        .update(authorizationCodes)
        .set({
          used: true,
          usedAt: Date.now(),
        })
        .where(and(eq(authorizationCodes.userId, userId), eq(authorizationCodes.used, false)))
        .returning();

      return result.length;
    },

    /**
     * Invalidate all unredeemed codes a user holds for one client
     * (consent revocation). Same predicate as `invalidateForUser`, narrowed
     * to the client.
     *
     * @param userId - User ID whose codes should be invalidated
     * @param oauthClientId - Client (internal id) the codes were issued to
     * @param tx - Optional transaction client
     * @returns Number of invalidated codes
     */
    async invalidateForUserAndClient(
      userId: string,
      oauthClientId: string,
      tx?: DbClient
    ): Promise<number> {
      const invoker = tx ?? defaultDb;

      const result = await invoker
        .update(authorizationCodes)
        .set({
          used: true,
          usedAt: Date.now(),
        })
        .where(
          and(
            eq(authorizationCodes.userId, userId),
            eq(authorizationCodes.oauthClientId, oauthClientId),
            eq(authorizationCodes.used, false)
          )
        )
        .returning({ id: authorizationCodes.id });

      return result.length;
    },

    /**
     * Delete expired codes
     * Useful for cleanup operations
     *
     * @param tx - Optional transaction client
     * @returns Count of deleted codes
     */
    async deleteExpired(tx?: DbClient): Promise<number> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const deleted = await invoker
        .delete(authorizationCodes)
        .where(lt(authorizationCodes.expiresAt, now))
        .returning({ id: authorizationCodes.id });

      return deleted.length;
    },
  };
}
