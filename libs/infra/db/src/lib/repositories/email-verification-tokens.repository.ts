import { NotFoundError } from '@qauth/shared-errors';
import { and, eq, gt, lt } from 'drizzle-orm';

import type {
  EmailVerificationToken,
  EmailVerificationTokensRepository,
  NewEmailVerificationToken,
} from '../../types';
import { DbClient } from '../db';
import { emailVerificationTokens } from '../schema/tokens';

/**
 * Factory function that creates an email verification tokens repository
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository object with token methods
 */
export function createEmailVerificationTokensRepository(
  defaultDb: DbClient
): EmailVerificationTokensRepository {
  return {
    /**
     * Create a new email verification token
     *
     * @param data - Token data to create
     * @param tx - Optional transaction client
     * @returns Created token
     */
    async create(data: NewEmailVerificationToken, tx?: DbClient): Promise<EmailVerificationToken> {
      const invoker = tx ?? defaultDb;
      const [token] = await invoker.insert(emailVerificationTokens).values(data).returning();
      return token;
    },

    /**
     * Find a token by its token hash
     * Only returns tokens that are not used and not expired
     *
     * @param tokenHash - SHA-256 hash of the token
     * @param tx - Optional transaction client
     * @returns Token if found and valid, undefined otherwise
     */
    async findByTokenHash(
      tokenHash: string,
      tx?: DbClient
    ): Promise<EmailVerificationToken | undefined> {
      const invoker = tx ?? defaultDb;
      // Use current timestamp directly in the query
      const now = Date.now();

      const [result] = await invoker
        .select()
        .from(emailVerificationTokens)
        .where(
          and(
            eq(emailVerificationTokens.tokenHash, tokenHash),
            eq(emailVerificationTokens.used, false),
            gt(emailVerificationTokens.expiresAt, now)
          )
        )
        .limit(1);

      return result;
    },

    /**
     * Mark a token as used
     *
     * @param id - Token ID
     * @param tx - Optional transaction client
     * @returns Updated token
     * @throws NotFoundError if token is not found
     */
    async markUsed(id: string, tx?: DbClient): Promise<EmailVerificationToken> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [token] = await invoker
        .update(emailVerificationTokens)
        .set({
          used: true,
          usedAt: now,
        })
        .where(eq(emailVerificationTokens.id, id))
        .returning();

      if (!token) {
        throw new NotFoundError('EmailVerificationToken', id);
      }

      return token;
    },

    /**
     * Invalidate all active tokens for a user
     * Marks all unused, non-expired tokens for the user as used
     *
     * @param userId - User ID whose tokens should be invalidated
     * @param tx - Optional transaction client
     * @returns Number of tokens invalidated
     */
    async invalidateUserTokens(userId: string, tx?: DbClient): Promise<number> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const result = await invoker
        .update(emailVerificationTokens)
        .set({
          used: true,
          usedAt: now,
        })
        .where(
          and(
            eq(emailVerificationTokens.userId, userId),
            eq(emailVerificationTokens.used, false),
            gt(emailVerificationTokens.expiresAt, now)
          )
        )
        .returning();

      return result.length;
    },

    /**
     * Delete expired tokens
     * Useful for cleanup operations
     *
     * @param tx - Optional transaction client
     * @returns Array of deleted tokens
     */
    async deleteExpired(tx?: DbClient): Promise<EmailVerificationToken[]> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const deleted = await invoker
        .delete(emailVerificationTokens)
        .where(lt(emailVerificationTokens.expiresAt, now))
        .returning();

      return deleted;
    },
  };
}
