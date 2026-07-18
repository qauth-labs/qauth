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
     * Mark a token as used — a COMPARE-AND-SET (#258, mirroring the
     * authorization-code single-use guard from #167): the UPDATE only wins
     * when `used` is still false, so two concurrent verification attempts
     * with the same token serialize on the row and exactly one succeeds.
     *
     * @param id - Token ID
     * @param tx - Optional transaction client
     * @returns The updated token, or undefined when the token was already
     * used (or does not exist) — an expected race outcome, not an exception;
     * callers map it to their surface's generic error.
     */
    async markUsed(id: string, tx?: DbClient): Promise<EmailVerificationToken | undefined> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [token] = await invoker
        .update(emailVerificationTokens)
        .set({
          used: true,
          usedAt: now,
        })
        .where(and(eq(emailVerificationTokens.id, id), eq(emailVerificationTokens.used, false)))
        .returning();

      return token;
    },

    /**
     * Invalidate all active tokens for a credential
     * Marks all unused, non-expired tokens targeting the credential as used
     *
     * Keyed on `credential_id` since #230 (`user_id` no longer exists on this
     * table); the caller holds the credential from its own lookup.
     *
     * @param credentialId - Credential whose tokens should be invalidated
     * @param tx - Optional transaction client
     * @returns Number of tokens invalidated
     */
    async invalidateCredentialTokens(credentialId: string, tx?: DbClient): Promise<number> {
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
            eq(emailVerificationTokens.credentialId, credentialId),
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
