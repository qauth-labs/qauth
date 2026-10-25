import { and, asc, desc, eq, gt, isNull, lte, type SQL } from 'drizzle-orm';

import type {
  NewSession,
  Session,
  SessionClient,
  SessionsRepository,
  UpdateSessionLastSeenOptions,
} from '../../types';
import { DbClient } from '../db';
import { sessionClients, type SessionRevokedReason, sessions } from '../schema/sessions';

/**
 * Factory for the browser sessions repository (ADR-019 Decision 3, issue
 * #468), and of the registry of the clients each session served
 * (`session_clients`, issue #549).
 *
 * Every statement but the inserts filters on the realm id it is given, so a
 * session id from one realm never reaches a row of another.
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository implementing {@link SessionsRepository}
 */
export function createSessionsRepository(defaultDb: DbClient): SessionsRepository {
  /**
   * The registry rows of the realm's sessions that `where` selects, oldest
   * first. The join on `sessions` is what confines them to the realm.
   */
  async function registryRows(
    realmId: string,
    where: SQL | undefined,
    tx?: DbClient
  ): Promise<SessionClient[]> {
    const invoker = tx ?? defaultDb;
    return invoker
      .select({
        sessionId: sessionClients.sessionId,
        oauthClientId: sessionClients.oauthClientId,
        firstSeenAt: sessionClients.firstSeenAt,
      })
      .from(sessionClients)
      .innerJoin(sessions, eq(sessions.id, sessionClients.sessionId))
      .where(and(eq(sessions.realmId, realmId), where))
      .orderBy(
        asc(sessionClients.firstSeenAt),
        asc(sessionClients.sessionId),
        asc(sessionClients.oauthClientId)
      );
  }

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
      return invoker.transaction(async (t) => {
        const [session] = await t
          .update(sessions)
          .set({ revokedAt: Date.now(), revokedReason: reason })
          .where(
            and(eq(sessions.realmId, realmId), eq(sessions.id, id), isNull(sessions.revokedAt))
          )
          .returning();
        if (session === undefined) return undefined;
        // A second statement, not a CTE beside the UPDATE: it reads a fresh
        // snapshot, taken after the UPDATE got the row. A code minted under
        // `recordClient`'s share lock has committed its registry row by then,
        // so the row is seen and deleted rather than outliving the session.
        await t.delete(sessionClients).where(eq(sessionClients.sessionId, session.id));
        return session;
      });
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

    async recordClient(
      realmId: string,
      sessionId: string,
      oauthClientId: string,
      tx: DbClient
    ): Promise<boolean> {
      // `FOR SHARE` holds off a concurrent `revoke` (an UPDATE of this row)
      // until `tx` ends, and that revocation then deletes the row written
      // here. One that committed first makes PostgreSQL re-check the WHERE
      // on the new row version, which drops the row: no live session.
      const [live] = await tx
        .select({ id: sessions.id })
        .from(sessions)
        .where(
          and(
            eq(sessions.realmId, realmId),
            eq(sessions.id, sessionId),
            isNull(sessions.revokedAt),
            gt(sessions.expiresAt, Date.now())
          )
        )
        .for('share');
      if (live === undefined) return false;
      await tx
        .insert(sessionClients)
        .values({ sessionId: live.id, oauthClientId })
        .onConflictDoNothing();
      return true;
    },

    listClientsForSession(
      realmId: string,
      sessionId: string,
      tx?: DbClient
    ): Promise<SessionClient[]> {
      return registryRows(realmId, eq(sessionClients.sessionId, sessionId), tx);
    },

    listClientsForUser(realmId: string, userId: string, tx?: DbClient): Promise<SessionClient[]> {
      return registryRows(realmId, eq(sessions.userId, userId), tx);
    },

    listSessionsForClient(
      realmId: string,
      oauthClientId: string,
      tx?: DbClient
    ): Promise<SessionClient[]> {
      return registryRows(realmId, eq(sessionClients.oauthClientId, oauthClientId), tx);
    },
  };
}
