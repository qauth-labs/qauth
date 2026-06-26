import {
  extractConstraintName,
  isUniqueConstraintError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { and, desc, eq, isNull } from 'drizzle-orm';

import type { ApiKey, ApiKeysRepository, NewApiKey } from '../../types/repository';
import { DbClient } from '../db';
import { apiKeys } from '../schema/core';

/**
 * Factory for the static developer API keys repository (ADR-008 §6, issue #97).
 *
 * Storage only — the environment gate that decides whether a key may be issued
 * or may authenticate (`resolveEnvironmentPolicy(...).staticApiKeysAllowed`)
 * lives at the route/helper layer. The plaintext key is never passed here: the
 * caller supplies a pre-computed argon2id `keyHash` and the non-secret `prefix`
 * / `last4` display handles, mirroring how client secrets are stored.
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository implementing {@link ApiKeysRepository}
 */
export function createApiKeysRepository(defaultDb: DbClient): ApiKeysRepository {
  return {
    async create(data: NewApiKey, tx?: DbClient): Promise<ApiKey> {
      const invoker = tx ?? defaultDb;
      try {
        const [apiKey] = await invoker.insert(apiKeys).values(data).returning();
        return apiKey;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint = extractConstraintName(error) || 'idx_api_keys_prefix_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    async findByPrefix(prefix: string, tx?: DbClient): Promise<ApiKey | undefined> {
      const invoker = tx ?? defaultDb;
      const [apiKey] = await invoker
        .select()
        .from(apiKeys)
        .where(eq(apiKeys.prefix, prefix))
        .limit(1);
      return apiKey;
    },

    async findById(id: string, tx?: DbClient): Promise<ApiKey | undefined> {
      const invoker = tx ?? defaultDb;
      const [apiKey] = await invoker.select().from(apiKeys).where(eq(apiKeys.id, id)).limit(1);
      return apiKey;
    },

    async listByClient(clientId: string, tx?: DbClient): Promise<ApiKey[]> {
      const invoker = tx ?? defaultDb;
      return invoker
        .select()
        .from(apiKeys)
        .where(eq(apiKeys.clientId, clientId))
        .orderBy(desc(apiKeys.createdAt));
    },

    async revoke(id: string, tx?: DbClient): Promise<ApiKey | undefined> {
      const invoker = tx ?? defaultDb;
      // Idempotent: only stamp `revokedAt` on a row that is still live. A
      // second revoke matches no row (already revoked) and returns the existing
      // state via the findById fallback so the route stays idempotent.
      const [updated] = await invoker
        .update(apiKeys)
        .set({ revokedAt: Date.now() })
        .where(and(eq(apiKeys.id, id), isNull(apiKeys.revokedAt)))
        .returning();
      if (updated) {
        return updated;
      }
      return this.findById(id, tx);
    },

    async touchLastUsed(id: string, tx?: DbClient): Promise<void> {
      const invoker = tx ?? defaultDb;
      await invoker.update(apiKeys).set({ lastUsedAt: Date.now() }).where(eq(apiKeys.id, id));
    },
  };
}
