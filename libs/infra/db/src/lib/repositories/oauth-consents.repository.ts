import { NotFoundError } from '@qauth-labs/shared-errors';
import { and, desc, eq, isNull } from 'drizzle-orm';

import type {
  NewOAuthConsent,
  OAuthConsent,
  OAuthConsentsRepository,
} from '../../types/repository';
import { DbClient } from '../db';
import { oauthConsents } from '../schema/consents';

/**
 * Factory for the oauth_consents repository.
 *
 * Consent rows are write-once from the user's perspective: a grant creates a
 * row, a revoke sets `revokedAt`, and subsequent consent for the same
 * (user, client) pair inserts a new active row rather than resurrecting the
 * revoked one. This preserves history for audit while keeping a partial
 * unique index enforceable on the active row.
 */
export function createOAuthConsentsRepository(defaultDb: DbClient): OAuthConsentsRepository {
  return {
    async create(data: NewOAuthConsent, tx?: DbClient): Promise<OAuthConsent> {
      const invoker = tx ?? defaultDb;
      const [row] = await invoker.insert(oauthConsents).values(data).returning();
      return row;
    },

    async findActive(
      userId: string,
      oauthClientId: string,
      tx?: DbClient
    ): Promise<OAuthConsent | undefined> {
      const invoker = tx ?? defaultDb;
      const [row] = await invoker
        .select()
        .from(oauthConsents)
        .where(
          and(
            eq(oauthConsents.userId, userId),
            eq(oauthConsents.oauthClientId, oauthClientId),
            isNull(oauthConsents.revokedAt)
          )
        )
        .limit(1);
      return row;
    },

    async listActiveForUser(userId: string, tx?: DbClient): Promise<OAuthConsent[]> {
      const invoker = tx ?? defaultDb;
      return invoker
        .select()
        .from(oauthConsents)
        .where(and(eq(oauthConsents.userId, userId), isNull(oauthConsents.revokedAt)))
        .orderBy(desc(oauthConsents.grantedAt));
    },

    async upsertGrant(
      userId: string,
      oauthClientId: string,
      realmId: string,
      scopes: string[],
      tx?: DbClient
    ): Promise<OAuthConsent> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [existing] = await invoker
        .select()
        .from(oauthConsents)
        .where(
          and(
            eq(oauthConsents.userId, userId),
            eq(oauthConsents.oauthClientId, oauthClientId),
            isNull(oauthConsents.revokedAt)
          )
        )
        .limit(1);

      if (existing) {
        // Union the scope sets so a narrower subsequent grant cannot silently
        // remove previously-granted scopes. Callers rely on this to detect
        // "already consented" for scope-subset checks.
        const union = Array.from(new Set([...existing.scopes, ...scopes])).sort();
        const [updated] = await invoker
          .update(oauthConsents)
          .set({ scopes: union, grantedAt: now })
          .where(eq(oauthConsents.id, existing.id))
          .returning();
        return updated;
      }

      const [created] = await invoker
        .insert(oauthConsents)
        .values({
          userId,
          oauthClientId,
          realmId,
          scopes: [...scopes].sort(),
          grantedAt: now,
        })
        .returning();
      return created;
    },

    async revoke(id: string, tx?: DbClient): Promise<OAuthConsent> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [row] = await invoker
        .update(oauthConsents)
        .set({ revokedAt: now })
        .where(and(eq(oauthConsents.id, id), isNull(oauthConsents.revokedAt)))
        .returning();

      if (!row) {
        throw new NotFoundError('OAuthConsent', id);
      }
      return row;
    },
  };
}
