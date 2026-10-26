import { and, asc, desc, eq, gt, isNull, lte, type SQL, sql } from 'drizzle-orm';

import type {
  DbTransaction,
  NewSession,
  RevokedSession,
  Session,
  SessionClient,
  SessionsRepository,
  UpdateSessionLastSeenOptions,
} from '../../types';
import { DbClient } from '../db';
import { oauthClients } from '../schema/core';
import { sessionClients, type SessionRevokedReason, sessions } from '../schema/sessions';
import { authorizationCodes } from '../schema/tokens';

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
   * The registry rows of the realm's live sessions (not revoked, before
   * `expires_at`) that `where` selects, oldest first. The join on `sessions`
   * is what confines them to the realm.
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
      .where(
        and(
          eq(sessions.realmId, realmId),
          isNull(sessions.revokedAt),
          gt(sessions.expiresAt, Date.now()),
          where
        )
      )
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
    ): Promise<RevokedSession | undefined> {
      const end = async (t: DbClient): Promise<RevokedSession | undefined> => {
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
        // so the row is seen, deleted and returned rather than outliving the
        // session unnoticed.
        const clients = await t
          .delete(sessionClients)
          .where(eq(sessionClients.sessionId, session.id))
          .returning();
        // The codes minted under the session and not yet redeemed are spent,
        // as a logout spends a user's codes: an ID token redeemed from one
        // would name a session that has ended. The same fresh snapshot sees
        // every code a `recordClient` committed with its registry row.
        await t
          .update(authorizationCodes)
          .set({ used: true, usedAt: Date.now() })
          .where(
            and(eq(authorizationCodes.sessionId, session.id), eq(authorizationCodes.used, false))
          );
        return { session, clients };
      };
      // READ COMMITTED whatever the server's default: only that level gives
      // the DELETE a snapshot taken after the UPDATE. A caller's transaction
      // must be READ COMMITTED too, which is checked rather than assumed; the
      // revocation runs as a savepoint inside it.
      if (tx === undefined) {
        return defaultDb.transaction(end, { isolationLevel: 'read committed' });
      }
      const { rows } = await tx.execute<{ level: string }>(
        sql`select current_setting('transaction_isolation') as level`
      );
      const level = rows[0]?.level;
      if (level !== 'read committed') {
        throw new Error(
          `sessions.revoke needs a READ COMMITTED transaction, and the caller's runs ${String(level)}`
        );
      }
      return tx.transaction(end);
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
      tx: DbTransaction
    ): Promise<boolean> {
      // `FOR SHARE` holds off a concurrent `revoke` (an UPDATE of this row)
      // until `tx` ends, and that revocation then deletes the row written
      // here. One that committed first makes PostgreSQL re-check the WHERE
      // on the new row version, which drops the row: no live session.
      // The join refuses a client of another realm (ADR-019 Decision 1):
      // `session_clients` has no realm of its own.
      const [live] = await tx
        .select({ id: sessions.id })
        .from(sessions)
        .innerJoin(
          oauthClients,
          and(eq(oauthClients.id, oauthClientId), eq(oauthClients.realmId, sessions.realmId))
        )
        .where(
          and(
            eq(sessions.realmId, realmId),
            eq(sessions.id, sessionId),
            isNull(sessions.revokedAt),
            gt(sessions.expiresAt, Date.now())
          )
        )
        .for('share', { of: sessions });
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
