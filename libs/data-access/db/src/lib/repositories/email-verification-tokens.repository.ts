import { NotFoundError } from '@qauth/errors';
import { and, eq, gt, InferInsertModel, InferSelectModel, lt } from 'drizzle-orm';

import { db, DbClient } from '../db';
import { emailVerificationTokens } from '../schema/tokens';

export type EmailVerificationToken = InferSelectModel<typeof emailVerificationTokens>;
export type NewEmailVerificationToken = InferInsertModel<typeof emailVerificationTokens>;

/**
 * Factory function that creates an email verification tokens repository
 *
 * @param defaultDb - Default database client to use (defaults to main db instance)
 * @returns Repository object with token methods
 */
export function createEmailVerificationTokensRepository(defaultDb: DbClient = db) {
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
     * Find a token by its token value
     * Only returns tokens that are not used and not expired
     *
     * @param token - Token value
     * @param tx - Optional transaction client
     * @returns Token if found and valid, undefined otherwise
     */
    async findByToken(token: string, tx?: DbClient): Promise<EmailVerificationToken | undefined> {
      const invoker = tx ?? defaultDb;
      // Use current timestamp directly in the query
      const now = Date.now();

      const [result] = await invoker
        .select()
        .from(emailVerificationTokens)
        .where(
          and(
            eq(emailVerificationTokens.token, token),
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

/**
 * Default email verification tokens repository instance
 */
export const emailVerificationTokensRepository = createEmailVerificationTokensRepository();
