import { and, eq, sql } from 'drizzle-orm';

import type {
  UpsertUserAttributeInput,
  UserAttributeRow,
  UserAttributesRepository,
} from '../../types';
import { DbClient } from '../db';
import { userAttributes } from '../schema/identity';

/**
 * Factory for the `user_attributes` repository (ADR-002, #228).
 *
 * The runtime write path is an UPSERT on the `(user_id, source, attr_key)`
 * unique index, per the schema contract in `identity.ts` — one value per
 * attribute per source per user, refreshed in place.
 */
export function createUserAttributesRepository(defaultDb: DbClient): UserAttributesRepository {
  return {
    /**
     * Upsert one row per attribute for a user in a single multi-row statement
     * (`ON CONFLICT (user_id, source, attr_key) DO UPDATE`). Array-shaped to
     * match `CredentialProvider.extractAttributes()` output; `expiresAt` is
     * epoch-ms per the schema's bigint convention.
     */
    async upsertMany(
      userId: string,
      attrs: readonly UpsertUserAttributeInput[],
      tx?: DbClient
    ): Promise<UserAttributeRow[]> {
      if (attrs.length === 0) return [];
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const rows = attrs.map((attr) => ({
        userId,
        source: attr.source,
        attrKey: attr.attrKey,
        attrValue: attr.attrValue,
        verified: attr.verified,
        expiresAt: attr.expiresAt ?? null,
        createdAt: now,
        updatedAt: now,
      }));

      return invoker
        .insert(userAttributes)
        .values(rows)
        .onConflictDoUpdate({
          target: [userAttributes.userId, userAttributes.source, userAttributes.attrKey],
          set: {
            attrValue: sql`excluded.attr_value`,
            verified: sql`excluded.verified`,
            expiresAt: sql`excluded.expires_at`,
            updatedAt: now,
          },
        })
        .returning();
    },

    /**
     * Targeted `verified` flip for one `(user_id, source, attr_key)` row
     * (email-verification completion). Returns the updated row, or undefined
     * when no such attribute exists — callers decide whether that is
     * log-worthy; it is never client-visible.
     */
    async setVerified(
      userId: string,
      source: string,
      attrKey: string,
      verified: boolean,
      tx?: DbClient
    ): Promise<UserAttributeRow | undefined> {
      const invoker = tx ?? defaultDb;
      const [row] = await invoker
        .update(userAttributes)
        .set({ verified, updatedAt: Date.now() })
        .where(
          and(
            eq(userAttributes.userId, userId),
            eq(userAttributes.source, source),
            eq(userAttributes.attrKey, attrKey)
          )
        )
        .returning();
      return row;
    },
  };
}
