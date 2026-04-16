import { NotFoundError } from '@qauth-labs/shared-errors';
import { and, eq, gt, lt } from 'drizzle-orm';

import type { NewRefreshToken, RefreshToken, RefreshTokensRepository } from '../../types';
import { DbClient } from '../db';
import { refreshTokens } from '../schema/tokens';

/**
 * Factory function that creates a refresh tokens repository
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository object with token methods
 */
export function createRefreshTokensRepository(defaultDb: DbClient): RefreshTokensRepository {
  return {
    /**
     * Create a new refresh token
     *
     * @param data - Token data to create
     * @param tx - Optional transaction client
     * @returns Created token
     */
    async create(data: NewRefreshToken, tx?: DbClient): Promise<RefreshToken> {
      const invoker = tx ?? defaultDb;
      const [token] = await invoker.insert(refreshTokens).values(data).returning();
      return token;
    },

    /**
     * Find a token by its token hash
     * Only returns tokens that are not revoked and not expired
     *
     * @param tokenHash - SHA-256 hash of the token
     * @param tx - Optional transaction client
     * @returns Token if found and valid, undefined otherwise
     */
    async findByTokenHash(tokenHash: string, tx?: DbClient): Promise<RefreshToken | undefined> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [result] = await invoker
        .select()
        .from(refreshTokens)
        .where(
          and(
            eq(refreshTokens.tokenHash, tokenHash),
            eq(refreshTokens.revoked, false),
            gt(refreshTokens.expiresAt, now)
          )
        )
        .limit(1);

      return result;
    },

    /**
     * Find all active tokens for a user
     * Returns tokens that are not revoked and not expired
     *
     * @param userId - User ID to find tokens for
     * @param tx - Optional transaction client
     * @returns Array of active tokens for the user
     */
    async findByUserId(userId: string, tx?: DbClient): Promise<RefreshToken[]> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      return await invoker
        .select()
        .from(refreshTokens)
        .where(
          and(
            eq(refreshTokens.userId, userId),
            eq(refreshTokens.revoked, false),
            gt(refreshTokens.expiresAt, now)
          )
        );
    },

    /**
     * Revoke a token by ID
     * Sets revoked=true, revokedAt=now, and optional revocation reason
     *
     * @param id - Token ID to revoke
     * @param reason - Optional reason for revocation
     * @param tx - Optional transaction client
     * @returns Updated token
     * @throws NotFoundError if token is not found
     */
    async revoke(id: string, reason?: string, tx?: DbClient): Promise<RefreshToken> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [token] = await invoker
        .update(refreshTokens)
        .set({
          revoked: true,
          revokedAt: now,
          revokedReason: reason ?? null,
        })
        .where(eq(refreshTokens.id, id))
        .returning();

      if (!token) {
        throw new NotFoundError('RefreshToken', id);
      }

      return token;
    },

    /**
     * Revoke all active tokens for a user
     * Useful for "logout all sessions" functionality
     *
     * @param userId - User ID whose tokens should be revoked
     * @param reason - Optional reason for revocation
     * @param tx - Optional transaction client
     */
    async revokeAllForUser(userId: string, reason?: string, tx?: DbClient): Promise<void> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      await invoker
        .update(refreshTokens)
        .set({
          revoked: true,
          revokedAt: now,
          revokedReason: reason ?? null,
        })
        .where(
          and(
            eq(refreshTokens.userId, userId),
            eq(refreshTokens.revoked, false),
            gt(refreshTokens.expiresAt, now)
          )
        );
    },

    /**
     * Delete expired tokens
     * Useful for cleanup operations
     *
     * @param tx - Optional transaction client
     * @returns Count of deleted tokens
     */
    async deleteExpired(tx?: DbClient): Promise<number> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const deleted = await invoker
        .delete(refreshTokens)
        .where(lt(refreshTokens.expiresAt, now))
        .returning({ id: refreshTokens.id });

      return deleted.length;
    },
  };
}
