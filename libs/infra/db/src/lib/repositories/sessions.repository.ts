import {
  and,
  asc,
  desc,
  eq,
  getTableColumns,
  gt,
  gte,
  isNotNull,
  isNull,
  lt,
  lte,
  ne,
  or,
  type SQL,
  sql,
  type SQLWrapper,
} from 'drizzle-orm';

import type {
  DbTransaction,
  ListedSession,
  NewSession,
  RevokedSession,
  RevokedSessionsBatch,
  Session,
  SessionClient,
  SessionClientDetail,
  SessionListPage,
  SessionsRepository,
  UpdateSessionLastSeenOptions,
} from '../../types';
import { DbClient } from '../db';
import { oauthClients, realms } from '../schema/core';
import { sessionClients, type SessionRevokedReason, sessions } from '../schema/sessions';
import { authorizationCodes } from '../schema/tokens';

/**
 * Factory for the browser sessions repository (ADR-019 Decision 3, issue
 * #468), and of the registry of the clients each session served
 * (`session_clients`, issue #549), with the session lists, the bulk
 * revocations and the purge (issue #550).
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

  /**
   * Run `work` in a READ COMMITTED transaction: a new one, or a savepoint of
   * the caller's `tx` once it is checked to be READ COMMITTED. Only that
   * level gives each statement of a revocation a snapshot taken after the
   * rows were locked (see {@link finishEnded}), so a `tx` at another level is
   * refused before anything is written.
   *
   * A transaction of its own that Postgres aborts as a deadlock is run again,
   * up to {@link DEADLOCK_ATTEMPTS} times: it wrote nothing, so a second run
   * is the same revocation. Revocations lock sessions in id order, so they
   * cannot deadlock among themselves; deleting a client or a realm cascades
   * through `session_clients` in another order and can. In a caller's
   * transaction the error is the caller's.
   */
  async function inReadCommitted<T>(
    method: string,
    work: (t: DbClient) => Promise<T>,
    tx?: DbClient
  ): Promise<T> {
    if (tx === undefined) {
      for (let attempt = 1; ; attempt++) {
        try {
          return await defaultDb.transaction(work, { isolationLevel: 'read committed' });
        } catch (error) {
          if (attempt >= DEADLOCK_ATTEMPTS || !isDeadlock(error)) throw error;
        }
      }
    }
    const { rows } = await tx.execute<{ level: string }>(
      sql`select current_setting('transaction_isolation') as level`
    );
    const level = rows[0]?.level;
    if (level !== 'read committed') {
      throw new Error(
        `${method} needs a READ COMMITTED transaction, and the caller's runs ${String(level)}`
      );
    }
    return tx.transaction(work);
  }

  /**
   * The registry rows of `rows` with their clients' public identity, oldest
   * first. A row whose client is gone, or is not of the session's realm,
   * is left out.
   */
  async function withClientDetails(
    t: DbClient,
    rows: readonly SessionClient[],
    realmOf: ReadonlyMap<string, string>
  ): Promise<SessionClientDetail[]> {
    if (rows.length === 0) return [];
    const ids = [...new Set(rows.map((row) => row.oauthClientId))];
    const clients = await t
      .select({
        id: oauthClients.id,
        realmId: oauthClients.realmId,
        clientId: oauthClients.clientId,
        name: oauthClients.name,
      })
      .from(oauthClients)
      .where(anyOf(oauthClients.id, ids));
    const byId = new Map(clients.map((client) => [client.id, client]));
    return rows
      .flatMap((row) => {
        const client = byId.get(row.oauthClientId);
        if (client === undefined || client.realmId !== realmOf.get(row.sessionId)) return [];
        return [{ ...row, clientId: client.clientId, clientName: client.name }];
      })
      .sort(
        (a, b) =>
          a.firstSeenAt - b.firstSeenAt ||
          compare(a.sessionId, b.sessionId) ||
          compare(a.oauthClientId, b.oauthClientId)
      );
  }

  /**
   * What follows the `UPDATE` that ended `ended`, in the same transaction:
   * delete and return their registry rows, and spend their unredeemed codes.
   *
   * Separate statements, not CTEs beside the UPDATE: each reads a fresh
   * snapshot, taken after the UPDATE got the rows. A code minted under
   * `recordClient`'s share lock has committed its registry row by then, so the
   * row is seen, deleted and returned rather than outliving the session
   * unnoticed. The codes are spent as a logout spends a user's codes: an ID
   * token redeemed from one would name a session that has ended, and the same
   * fresh snapshot sees every code a `recordClient` committed with its row.
   */
  async function finishEnded(
    t: DbClient,
    ended: readonly Session[],
    at: number
  ): Promise<RevokedSession[]> {
    if (ended.length === 0) return [];
    const ids = ended.map((session) => session.id);
    const bySession =
      ids.length === 1
        ? eq(sessionClients.sessionId, ids[0])
        : anyOf(sessionClients.sessionId, ids);
    const removed = await t.delete(sessionClients).where(bySession).returning();
    const clients = await withClientDetails(
      t,
      removed,
      new Map(ended.map((session) => [session.id, session.realmId]))
    );
    await t
      .update(authorizationCodes)
      .set({ used: true, usedAt: at })
      .where(
        and(
          ids.length === 1
            ? eq(authorizationCodes.sessionId, ids[0])
            : anyOf(authorizationCodes.sessionId, ids),
          eq(authorizationCodes.used, false)
        )
      );
    return [...ended]
      .sort((a, b) => compare(a.id, b.id))
      .map((session) => ({
        session,
        clients: clients.filter((client) => client.sessionId === session.id),
      }));
  }

  /**
   * End the sessions `where` selects that are not yet revoked, with one
   * reason: lock them in id order (at most `limit`), then revoke them and
   * finish as {@link finishEnded}. Locking in one order keeps two bulk
   * revocations from deadlocking on each other's rows. A row another
   * transaction revokes while this one waits is re-checked after the wait
   * and dropped.
   */
  async function endSelected(
    t: DbClient,
    where: SQL | undefined,
    reason: SessionRevokedReason,
    limit?: number
  ): Promise<RevokedSessionsBatch> {
    const at = Date.now();
    const select = t
      .select({ id: sessions.id })
      .from(sessions)
      .where(and(isNull(sessions.revokedAt), where))
      .orderBy(asc(sessions.id))
      .$dynamic();
    const locked = await (limit === undefined ? select : select.limit(limit)).for('update');
    if (locked.length === 0) return { ended: [], last: null, selected: 0 };
    const ended = await t
      .update(sessions)
      .set({ revokedAt: at, revokedReason: reason })
      .where(
        and(
          anyOf(
            sessions.id,
            locked.map((row) => row.id)
          ),
          isNull(sessions.revokedAt)
        )
      )
      .returning();
    return {
      ended: await finishEnded(t, ended, at),
      last: locked[locked.length - 1].id,
      selected: locked.length,
    };
  }

  /**
   * One page of the realm's sessions that `where` selects, newest first, with
   * the clients each one's registry holds. `viaClient` joins the registry
   * first, for a `where` on its client.
   */
  async function listPage(
    realmId: string,
    where: SQL,
    page: SessionListPage,
    viaClient: boolean,
    tx?: DbClient
  ): Promise<ListedSession[]> {
    const invoker = tx ?? defaultDb;
    const after =
      page.after === undefined
        ? undefined
        : or(
            lt(sessions.createdAt, page.after.createdAt),
            and(eq(sessions.createdAt, page.after.createdAt), lt(sessions.id, page.after.id))
          );
    const base = invoker.select(getTableColumns(sessions)).from(sessions).$dynamic();
    const rows = await (
      viaClient ? base.innerJoin(sessionClients, eq(sessionClients.sessionId, sessions.id)) : base
    )
      .where(and(eq(sessions.realmId, realmId), where, after))
      .orderBy(desc(sessions.createdAt), desc(sessions.id))
      .limit(page.limit);
    if (rows.length === 0) return [];
    // A revoked session holds no client. One a previous release revoked
    // during a rolling upgrade may still have registry rows; they are not
    // shown.
    const unrevoked = rows.filter((row) => row.revokedAt === null).map((row) => row.id);
    const registry =
      unrevoked.length === 0
        ? []
        : await invoker
            .select()
            .from(sessionClients)
            .where(anyOf(sessionClients.sessionId, unrevoked));
    const clients = await withClientDetails(
      invoker,
      registry,
      new Map(rows.map((row) => [row.id, row.realmId]))
    );
    return rows.map((session) => ({
      session,
      clients: clients.filter((client) => client.sessionId === session.id),
    }));
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
        const at = Date.now();
        const [session] = await t
          .update(sessions)
          .set({ revokedAt: at, revokedReason: reason })
          .where(
            and(eq(sessions.realmId, realmId), eq(sessions.id, id), isNull(sessions.revokedAt))
          )
          .returning();
        if (session === undefined) return undefined;
        const [ended] = await finishEnded(t, [session], at);
        return ended;
      };
      return inReadCommitted('sessions.revoke', end, tx);
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

    listForUser(realmId, userId, page, tx) {
      return listPage(realmId, eq(sessions.userId, userId), page, false, tx);
    },

    listForClient(realmId, oauthClientId, page, tx) {
      return listPage(
        realmId,
        and(eq(sessionClients.oauthClientId, oauthClientId), isNull(sessions.revokedAt)) as SQL,
        page,
        true,
        tx
      );
    },

    async revokeForUser(realmId, userId, reason, filter = {}, tx) {
      const batch = await inReadCommitted(
        'sessions.revokeForUser',
        (t) =>
          endSelected(
            t,
            and(
              eq(sessions.realmId, realmId),
              eq(sessions.userId, userId),
              filter.exceptId === undefined ? undefined : ne(sessions.id, filter.exceptId),
              filter.createdBefore === undefined
                ? undefined
                : lt(sessions.createdAt, filter.createdBefore)
            ),
            reason
          ),
        tx
      );
      return batch.ended;
    },

    revokeRealmBatch(realmId, reason, batch) {
      return inReadCommitted('sessions.revokeRealmBatch', (t) =>
        endSelected(
          t,
          and(
            eq(sessions.realmId, realmId),
            batch.after === undefined ? undefined : gt(sessions.id, batch.after),
            lte(sessions.createdAt, batch.createdThrough),
            batch.activeSince === undefined
              ? undefined
              : gte(sessions.lastSeenAt, batch.activeSince)
          ),
          reason,
          batch.limit
        )
      );
    },

    revokeLapsedBatch(batch) {
      // The session service's rules (`sessionEnds`): the absolute end is the
      // stored `expires_at`, or earlier when the realm's current maximum
      // lifespan (SESSION_COOKIE_TTL without one) ends it sooner; the idle end
      // is the stored `last_seen_at` plus the realm's idle limit. Each end is
      // the first moment the session is no longer live.
      const absoluteEnd = sql`least(${sessions.expiresAt}, ${sessions.createdAt} + coalesce(${realms.ssoMaxLifespan} * 1000, ${batch.defaultMaxLifespanMs}::bigint))`;
      const idleEnd = sql`${sessions.lastSeenAt} + ${realms.ssoIdleTimeout} * 1000`;
      const lapsed = or(
        sql`${absoluteEnd} <= ${batch.now}::bigint`,
        and(isNotNull(realms.ssoIdleTimeout), sql`${idleEnd} <= ${batch.now}::bigint`)
      );
      return inReadCommitted('sessions.revokeLapsedBatch', async (t) => {
        const locked = await t
          .select({ id: sessions.id })
          .from(sessions)
          .innerJoin(realms, eq(realms.id, sessions.realmId))
          .where(
            and(
              isNull(sessions.revokedAt),
              batch.after === undefined ? undefined : gt(sessions.id, batch.after),
              lapsed
            )
          )
          .orderBy(asc(sessions.id))
          .limit(batch.limit)
          .for('update', { of: sessions });
        if (locked.length === 0) return { ended: [], last: null, selected: 0 };
        // The end that came first names the reason; the absolute end wins a
        // tie, and a realm with no idle limit has a NULL idle end, which the
        // comparison leaves to the absolute end. `revoked_at` is the time of
        // the mark: retention counts from it, so a session a shortened
        // lifespan ends now is still listed for the whole retention.
        const ended = await t
          .update(sessions)
          .set({
            revokedAt: batch.now,
            revokedReason: sql`case when ${idleEnd} < ${absoluteEnd} then 'idle' else 'expired' end`,
          })
          .from(realms)
          .where(
            and(
              eq(realms.id, sessions.realmId),
              anyOf(
                sessions.id,
                locked.map((row) => row.id)
              ),
              isNull(sessions.revokedAt),
              lapsed
            )
          )
          .returning(getTableColumns(sessions));
        return {
          ended: await finishEnded(t, ended, batch.now),
          last: locked[locked.length - 1].id,
          selected: locked.length,
        };
      });
    },

    async deleteEnded(batch) {
      const ended = or(lt(sessions.revokedAt, batch.before), lt(sessions.expiresAt, batch.before));
      const doomed = await defaultDb
        .select({ id: sessions.id })
        .from(sessions)
        .where(and(batch.after === undefined ? undefined : gt(sessions.id, batch.after), ended))
        .orderBy(asc(sessions.id))
        .limit(batch.limit);
      if (doomed.length === 0) return { deleted: 0, last: null, selected: 0 };
      // The condition again: a row is deleted only if it still holds when the
      // DELETE reaches it.
      const deleted = await defaultDb
        .delete(sessions)
        .where(
          and(
            anyOf(
              sessions.id,
              doomed.map((row) => row.id)
            ),
            ended
          )
        )
        .returning({ id: sessions.id });
      return {
        deleted: deleted.length,
        last: doomed[doomed.length - 1].id,
        selected: doomed.length,
      };
    },
  };
}

/** How many times a transaction of its own is run when Postgres aborts it as a deadlock. */
const DEADLOCK_ATTEMPTS = 3;

/** Whether `error`, or the driver error drizzle wrapped in it, is a deadlock (40P01). */
function isDeadlock(error: unknown): boolean {
  for (let current: unknown = error, depth = 0; current && depth < 3; depth++) {
    if ((current as { code?: unknown }).code === '40P01') return true;
    current = (current as { cause?: unknown }).cause;
  }
  return false;
}

/**
 * `column = any($1::uuid[])`: the ids as ONE array parameter. `inArray` sends
 * one parameter per id, and the protocol allows at most 65,535, so a user
 * with that many sessions could not be signed out.
 */
function anyOf(column: SQLWrapper, ids: readonly string[]): SQL {
  return sql`${column} = any(${sql.param([...ids])}::uuid[])`;
}

/** Byte order of two ids: the order Postgres sorts `uuid` values in. */
function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
