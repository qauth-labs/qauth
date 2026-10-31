import { NotFoundError } from '@qauth-labs/shared-errors';
import { and, desc, eq, isNull, lt, or } from 'drizzle-orm';

import type {
  KeysetPage,
  NewOAuthConsent,
  OAuthConsent,
  OAuthConsentsRepository,
} from '../../types/repository';
import { DbClient } from '../db';
import { oauthConsents } from '../schema/consents';
import { oauthClients } from '../schema/core';

/**
 * The active consent of one (user, client) pair in one realm. The realm is
 * part of every read (#489): a consent of another realm is no consent.
 */
function activeConsentOf(realmId: string, userId: string, oauthClientId: string) {
  return and(
    eq(oauthConsents.realmId, realmId),
    eq(oauthConsents.userId, userId),
    eq(oauthConsents.oauthClientId, oauthClientId),
    isNull(oauthConsents.revokedAt)
  );
}

/** The active consents a user of the realm holds. */
function activeConsentsOf(realmId: string, userId: string) {
  return and(
    eq(oauthConsents.realmId, realmId),
    eq(oauthConsents.userId, userId),
    isNull(oauthConsents.revokedAt)
  );
}

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
      realmId: string,
      userId: string,
      oauthClientId: string,
      tx?: DbClient
    ): Promise<OAuthConsent | undefined> {
      const invoker = tx ?? defaultDb;
      const [row] = await invoker
        .select()
        .from(oauthConsents)
        .where(activeConsentOf(realmId, userId, oauthClientId))
        .limit(1);
      return row;
    },

    async findActiveForShare(
      realmId: string,
      userId: string,
      oauthClientId: string,
      tx: DbClient
    ): Promise<OAuthConsent | undefined> {
      // `FOR SHARE` blocks a concurrent `revoke` (an UPDATE of this row)
      // until `tx` ends; one that committed first makes PostgreSQL re-check
      // `revoked_at IS NULL` on the new row version, which drops the row.
      const [row] = await tx
        .select()
        .from(oauthConsents)
        .where(activeConsentOf(realmId, userId, oauthClientId))
        .limit(1)
        .for('share');
      return row;
    },

    async listActiveForUser(
      realmId: string,
      userId: string,
      tx?: DbClient
    ): Promise<OAuthConsent[]> {
      const invoker = tx ?? defaultDb;
      return invoker
        .select()
        .from(oauthConsents)
        .where(activeConsentsOf(realmId, userId))
        .orderBy(desc(oauthConsents.grantedAt));
    },

    async listActiveForUserWithClient(realmId: string, userId: string, tx?: DbClient) {
      const invoker = tx ?? defaultDb;
      const rows = await invoker
        .select({
          consent: oauthConsents,
          clientClientId: oauthClients.clientId,
          clientName: oauthClients.name,
        })
        .from(oauthConsents)
        .innerJoin(oauthClients, eq(oauthConsents.oauthClientId, oauthClients.id))
        .where(activeConsentsOf(realmId, userId))
        .orderBy(desc(oauthConsents.grantedAt));

      return rows.map((r) => ({
        ...r.consent,
        clientClientId: r.clientClientId,
        clientName: r.clientName,
      }));
    },

    /**
     * One page of the active consents a user of the realm holds, with each
     * one's client, newest first (#524): ordered by `granted_at` and then
     * `id`, both descending, starting after `page.after`.
     */
    async pageActiveForUserWithClient(
      realmId: string,
      userId: string,
      page: KeysetPage,
      tx?: DbClient
    ) {
      const invoker = tx ?? defaultDb;
      const after = page.after;
      const rows = await invoker
        .select({
          consent: oauthConsents,
          clientClientId: oauthClients.clientId,
          clientName: oauthClients.name,
        })
        .from(oauthConsents)
        .innerJoin(oauthClients, eq(oauthConsents.oauthClientId, oauthClients.id))
        .where(
          and(
            activeConsentsOf(realmId, userId),
            after === undefined
              ? undefined
              : or(
                  lt(oauthConsents.grantedAt, after.at),
                  and(eq(oauthConsents.grantedAt, after.at), lt(oauthConsents.id, after.id))
                )
          )
        )
        .orderBy(desc(oauthConsents.grantedAt), desc(oauthConsents.id))
        .limit(page.limit);

      return rows.map((r) => ({
        ...r.consent,
        clientClientId: r.clientClientId,
        clientName: r.clientName,
      }));
    },

    async upsertGrant(
      realmId: string,
      userId: string,
      oauthClientId: string,
      scopes: string[],
      resources: readonly string[] = [],
      tx?: DbClient
    ): Promise<OAuthConsent> {
      // Read-then-update/insert MUST be atomic — two concurrent "allow
      // forever" clicks with overlapping-but-distinct scope sets would
      // otherwise race and silently drop one side's union. Caller may
      // supply a `tx` (participates); otherwise we open one here.
      const run = async (invoker: DbClient): Promise<OAuthConsent> => {
        const now = Date.now();

        const [existing] = await invoker
          .select()
          .from(oauthConsents)
          .where(activeConsentOf(realmId, userId, oauthClientId))
          .limit(1)
          .for('update');

        if (existing) {
          // Union the scope sets so a narrower subsequent grant cannot silently
          // remove previously-granted scopes. Callers rely on this to detect
          // "already consented" for scope-subset checks.
          const union = Array.from(new Set([...existing.scopes, ...scopes])).sort();
          // RFC 8707: the same union, per resource and never across them —
          // scopes approved for one resource server say nothing about another.
          const merged = new Map(Object.entries(existing.resourceScopes));
          for (const resource of resources) {
            const prior = merged.get(resource) ?? [];
            merged.set(resource, Array.from(new Set([...prior, ...scopes])).sort());
          }
          const resourceScopes = Object.fromEntries(merged);
          const [updated] = await invoker
            .update(oauthConsents)
            .set({ scopes: union, resourceScopes, grantedAt: now })
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
            resourceScopes: Object.fromEntries(resources.map((r) => [r, [...scopes].sort()])),
            grantedAt: now,
          })
          .returning();
        return created;
      };

      return tx ? run(tx) : defaultDb.transaction((innerTx) => run(innerTx));
    },

    async revoke(realmId: string, id: string, tx?: DbClient): Promise<OAuthConsent> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [row] = await invoker
        .update(oauthConsents)
        .set({ revokedAt: now })
        .where(
          and(
            eq(oauthConsents.realmId, realmId),
            eq(oauthConsents.id, id),
            isNull(oauthConsents.revokedAt)
          )
        )
        .returning();

      if (!row) {
        throw new NotFoundError('OAuthConsent', id);
      }
      return row;
    },
  };
}
