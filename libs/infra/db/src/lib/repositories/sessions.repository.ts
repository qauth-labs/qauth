import { and, desc, eq, gt, isNull, lte } from 'drizzle-orm';

import type {
  NewSession,
  Session,
  SessionsRepository,
  UpdateSessionLastSeenOptions,
} from '../../types';
import { DbClient } from '../db';
import { type SessionRevokedReason, sessions } from '../schema/sessions';

/**
 * Factory for the browser sessions repository (ADR-019 Decision 3, issue
 * #468).
 *
 * Every statement but the insert filters on the realm id it is given, so a
 * session id from one realm never reaches a row of another.
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository implementing {@link SessionsRepository}
 */
export function createSessionsRepository(defaultDb: DbClient): SessionsRepository {
  return {
    async create(data: NewSession, tx?: DbClient): Promise<Session> {
      const invoker = tx ?? defaultDb;
      // The type already leaves these out; a caller that casts them back in
      // still gets a database id and a live session.
      const [session] = await invoker
        .insert(sessions)
        .values({ ...data, id: undefined, revokedAt: null, revokedReason: null })
        .returning();
      return session;
    },

    async findById(realmId: string, id: string, tx?: DbClient): Promise<Session | undefined> {
      const invoker = tx ?? defaultDb;
      const [session] = await invoker
        .select()
        .from(sessions)
        .where(and(eq(sessions.realmId, realmId), eq(sessions.id, id)))
        .limit(1);
      return session;
    },

    async updateLastSeen(
      realmId: string,
      id: string,
      options: UpdateSessionLastSeenOptions = {},
      tx?: DbClient
    ): Promise<boolean> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();
      const written = await invoker
        .update(sessions)
        .set({ lastSeenAt: now })
        .where(
          and(
            eq(sessions.realmId, realmId),
            eq(sessions.id, id),
            isNull(sessions.revokedAt),
            gt(sessions.expiresAt, now),
            lte(sessions.lastSeenAt, now - (options.minIntervalMs ?? 0))
          )
        )
        .returning({ id: sessions.id });
      return written.length > 0;
    },

    async revoke(
      realmId: string,
      id: string,
      reason: SessionRevokedReason,
      tx?: DbClient
    ): Promise<Session | undefined> {
      const invoker = tx ?? defaultDb;
      const [session] = await invoker
        .update(sessions)
        .set({ revokedAt: Date.now(), revokedReason: reason })
        .where(and(eq(sessions.realmId, realmId), eq(sessions.id, id), isNull(sessions.revokedAt)))
        .returning();
      return session;
    },

    async listActiveForUser(realmId: string, userId: string, tx?: DbClient): Promise<Session[]> {
      const invoker = tx ?? defaultDb;
      return invoker
        .select()
        .from(sessions)
        .where(
          and(
            eq(sessions.realmId, realmId),
            eq(sessions.userId, userId),
            isNull(sessions.revokedAt),
            gt(sessions.expiresAt, Date.now())
          )
        )
        .orderBy(desc(sessions.createdAt), desc(sessions.id));
    },
  };
}
