import { randomUUID } from 'node:crypto';

import { sessionEnds } from '../lib/lifetimes';
import type {
  SessionCache,
  SessionCacheLookup,
  SessionRevocationBatch,
  SessionStore,
} from '../lib/ports';
import type {
  CachedSession,
  EndedSession,
  NewSessionRecord,
  RealmSessionLifetimes,
  SessionClientRecord,
  SessionRecord,
  SessionRevokedReason,
  StoredSession,
} from '../lib/types';

/**
 * In-memory ports for tests: the service runs on them exactly as on Postgres
 * and Redis, so a caller's unit test can use the real service over them.
 */

/** A clock a test moves by hand. */
export interface ManualClock {
  now(): number;
  advance(ms: number): void;
  set(epochMs: number): void;
}

export function createManualClock(start = Date.UTC(2026, 0, 1)): ManualClock {
  let current = start;
  return {
    now: () => current,
    advance(ms: number) {
      current += ms;
    },
    set(epochMs: number) {
      current = epochMs;
    },
  };
}

/** Counts of what reached the in-memory store. */
export interface MemorySessionStoreCalls {
  realmReads: number;
  inserts: number;
  reads: number;
  /** Conditional last-seen updates sent, whether they wrote or not. */
  touchAttempts: number;
  /** Conditional last-seen updates that wrote the row. */
  touchWrites: number;
  revokes: number;
  /** Transactions of the bulk revocations: one per user call, one per batch. */
  revocationBatches: number;
  /** Batches the purge sent. */
  purgeBatches: number;
}

/** {@link SessionStore} in memory, with the repository's conditions. */
export interface MemorySessionStore extends SessionStore {
  /** Add or replace a realm and its lifetimes. */
  putRealm(realmId: string, lifetimes?: Partial<RealmSessionLifetimes>): void;
  /** The stored row, or `undefined`. */
  row(sid: string): SessionRecord | undefined;
  /** Change a stored row, as another writer would. */
  update(sid: string, changes: Partial<SessionRecord>): void;
  /**
   * Record that a session served a client, as a code mint does (#549).
   * Nothing is recorded for a session not in the store.
   */
  recordClient(
    sid: string,
    client: Omit<SessionClientRecord, 'firstSeenAt'> & { firstSeenAt?: number }
  ): void;
  /** The clients the registry holds for a session, oldest first. */
  clientsOf(sid: string): SessionClientRecord[];
  readonly calls: MemorySessionStoreCalls;
  /** While `true`, every method throws, as with Postgres stopped. */
  down: boolean;
}

function copyOf(row: SessionRecord): SessionRecord {
  return { ...row, amr: [...row.amr] };
}

/** Byte order of two ids, as Postgres sorts `uuid` values. */
function byId(a: { id: string }, b: { id: string }): number {
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

export function createMemorySessionStore(clock: { now(): number }): MemorySessionStore {
  const realms = new Map<string, RealmSessionLifetimes>();
  const rows = new Map<string, SessionRecord>();
  const registry = new Map<string, SessionClientRecord[]>();
  const calls: MemorySessionStoreCalls = {
    realmReads: 0,
    inserts: 0,
    reads: 0,
    touchAttempts: 0,
    touchWrites: 0,
    revokes: 0,
    revocationBatches: 0,
    purgeBatches: 0,
  };

  function clientsOf(sid: string): SessionClientRecord[] {
    return [...(registry.get(sid) ?? [])]
      .sort(
        (a, b) =>
          a.firstSeenAt - b.firstSeenAt ||
          (a.oauthClientId < b.oauthClientId ? -1 : a.oauthClientId > b.oauthClientId ? 1 : 0)
      )
      .map((client) => ({ ...client }));
  }

  /** End `row` as the repository does: revoked, its registry taken with it. */
  function end(
    row: SessionRecord,
    reason: SessionRevokedReason,
    at: number = clock.now()
  ): EndedSession {
    const ended: SessionRecord = { ...row, revokedAt: at, revokedReason: reason };
    rows.set(row.id, ended);
    const clients = clientsOf(row.id);
    registry.delete(row.id);
    return { session: copyOf(ended), clients };
  }

  function batchOf(
    selected: SessionRecord[],
    endOne: (row: SessionRecord) => EndedSession
  ): SessionRevocationBatch {
    calls.revocationBatches += 1;
    return {
      ended: selected.map(endOne),
      last: selected.length === 0 ? null : selected[selected.length - 1].id,
      selected: selected.length,
    };
  }

  const store: MemorySessionStore = {
    calls,
    down: false,

    putRealm(realmId, lifetimes = {}) {
      realms.set(realmId, {
        maxLifespanSeconds: lifetimes.maxLifespanSeconds ?? null,
        idleTimeoutSeconds: lifetimes.idleTimeoutSeconds ?? null,
      });
    },

    row(sid) {
      const row = rows.get(sid);
      return row === undefined ? undefined : copyOf(row);
    },

    update(sid, changes) {
      const row = rows.get(sid);
      if (row === undefined) throw new Error(`no session ${sid}`);
      rows.set(sid, { ...row, ...changes });
    },

    recordClient(sid, client) {
      const row = rows.get(sid);
      if (row === undefined || row.revokedAt !== null) return;
      const held = registry.get(sid) ?? [];
      if (held.some((existing) => existing.oauthClientId === client.oauthClientId)) return;
      registry.set(sid, [...held, { ...client, firstSeenAt: client.firstSeenAt ?? clock.now() }]);
    },

    clientsOf,

    async findRealmLifetimes(realmId) {
      if (store.down) throw new Error('store down');
      calls.realmReads += 1;
      const lifetimes = realms.get(realmId);
      return lifetimes === undefined ? undefined : { ...lifetimes };
    },

    async insert(session: NewSessionRecord) {
      if (store.down) throw new Error('store down');
      calls.inserts += 1;
      if (!realms.has(session.realmId)) throw new Error('foreign key: no such realm');
      const row: SessionRecord = {
        ...session,
        amr: [...session.amr],
        id: randomUUID(),
        revokedAt: null,
        revokedReason: null,
      };
      rows.set(row.id, row);
      return copyOf(row);
    },

    async find(realmId, sid): Promise<StoredSession | undefined> {
      if (store.down) throw new Error('store down');
      calls.reads += 1;
      const row = rows.get(sid);
      const lifetimes = realms.get(realmId);
      if (row === undefined || row.realmId !== realmId || lifetimes === undefined) {
        return undefined;
      }
      return { session: copyOf(row), lifetimes: { ...lifetimes } };
    },

    async touchLastSeen(realmId, sid, minIntervalMs) {
      if (store.down) throw new Error('store down');
      calls.touchAttempts += 1;
      const now = clock.now();
      const row = rows.get(sid);
      if (
        row === undefined ||
        row.realmId !== realmId ||
        row.revokedAt !== null ||
        row.expiresAt <= now ||
        row.lastSeenAt > now - minIntervalMs
      ) {
        return false;
      }
      rows.set(sid, { ...row, lastSeenAt: now });
      calls.touchWrites += 1;
      return true;
    },

    async revoke(realmId, sid, reason: SessionRevokedReason, owner = {}) {
      if (store.down) throw new Error('store down');
      calls.revokes += 1;
      const row = rows.get(sid);
      if (
        row === undefined ||
        row.realmId !== realmId ||
        row.revokedAt !== null ||
        (owner.userId !== undefined && row.userId !== owner.userId)
      ) {
        return undefined;
      }
      return end(row, reason);
    },

    async revokeForUser(realmId, userId, reason, filter) {
      if (store.down) throw new Error('store down');
      const selected = [...rows.values()]
        .filter(
          (row) =>
            row.realmId === realmId &&
            row.userId === userId &&
            row.revokedAt === null &&
            row.id !== filter.exceptSid &&
            (filter.createdBefore === undefined || row.createdAt < filter.createdBefore)
        )
        .sort(byId);
      return batchOf(selected, (row) => end(row, reason)).ended;
    },

    async revokeRealmBatch(realmId, reason, batch) {
      if (store.down) throw new Error('store down');
      const selected = [...rows.values()]
        .filter(
          (row) =>
            row.realmId === realmId &&
            row.revokedAt === null &&
            (batch.after === null || row.id > batch.after) &&
            row.createdAt <= batch.createdThrough &&
            (batch.activeSince === undefined || row.lastSeenAt >= batch.activeSince)
        )
        .sort(byId)
        .slice(0, batch.limit);
      return batchOf(selected, (row) => end(row, reason));
    },

    async revokeLapsedBatch(batch) {
      if (store.down) throw new Error('store down');
      const lapsed: Array<{ row: SessionRecord; reason: SessionRevokedReason; at: number }> = [];
      for (const row of [...rows.values()].sort(byId)) {
        const lifetimes = realms.get(row.realmId);
        if (row.revokedAt !== null || lifetimes === undefined) continue;
        if (batch.after !== null && row.id <= batch.after) continue;
        const ends = sessionEnds(row, lifetimes, batch.defaultMaxLifespanSeconds);
        const idle = ends.idle ?? Number.POSITIVE_INFINITY;
        const at = Math.min(ends.absolute, idle);
        if (at > batch.now) continue;
        lapsed.push({ row, reason: idle < ends.absolute ? 'idle' : 'expired', at: batch.now });
        if (lapsed.length === batch.limit) break;
      }
      const reasons = new Map(lapsed.map((item) => [item.row.id, item]));
      return batchOf(
        lapsed.map((item) => item.row),
        (row) => {
          const item = reasons.get(row.id);
          if (item === undefined) throw new Error('unreachable');
          return end(row, item.reason, item.at);
        }
      );
    },

    async list(realmId, owner, page) {
      if (store.down) throw new Error('store down');
      calls.reads += 1;
      const lifetimes = realms.get(realmId);
      if (lifetimes === undefined) return undefined;
      const selected = [...rows.values()]
        .filter(
          (row) =>
            row.realmId === realmId &&
            ('userId' in owner
              ? row.userId === owner.userId
              : row.revokedAt === null &&
                (registry.get(row.id) ?? []).some(
                  (client) => client.oauthClientId === owner.oauthClientId
                ))
        )
        .sort((a, b) => b.createdAt - a.createdAt || byId(b, a))
        .filter(
          (row) =>
            page.after === undefined ||
            row.createdAt < page.after.createdAt ||
            (row.createdAt === page.after.createdAt && row.id < page.after.sid)
        )
        .slice(0, page.limit);
      return {
        lifetimes: { ...lifetimes },
        sessions: selected.map((row) => ({
          session: copyOf(row),
          clients: row.revokedAt === null ? clientsOf(row.id) : [],
        })),
      };
    },

    async deleteEnded(batch) {
      if (store.down) throw new Error('store down');
      calls.purgeBatches += 1;
      const doomed = [...rows.values()]
        .filter(
          (row) =>
            (batch.after === null || row.id > batch.after) &&
            ((row.revokedAt !== null && row.revokedAt < batch.before) ||
              row.expiresAt < batch.before)
        )
        .sort(byId)
        .slice(0, batch.limit);
      for (const row of doomed) {
        rows.delete(row.id);
        registry.delete(row.id);
      }
      return {
        deleted: doomed.length,
        last: doomed.length === 0 ? null : doomed[doomed.length - 1].id,
        selected: doomed.length,
      };
    },
  };
  return store;
}

/** Counts of what reached the in-memory cache. */
export interface MemorySessionCacheCalls {
  reads: number;
  writes: number;
  tombstones: number;
}

/** {@link SessionCache} in memory, with expiry on the given clock. */
export interface MemorySessionCache extends SessionCache {
  /** The live entry of a session, or `undefined`. */
  entry(realmId: string, sid: string): CachedSession | undefined;
  /** The remaining time to live of an entry, in milliseconds, or `undefined`. */
  ttlOf(realmId: string, sid: string): number | undefined;
  /** Drop everything, as a Redis that lost its data. */
  clear(): void;
  readonly calls: MemorySessionCacheCalls;
  /** While `true`, every method throws, as with Redis stopped. */
  down: boolean;
}

interface Expiring<T> {
  value: T;
  expiresAt: number;
}

export function createMemorySessionCache(clock: { now(): number }): MemorySessionCache {
  const entries = new Map<string, Expiring<CachedSession>>();
  const tombstones = new Map<string, Expiring<true>>();
  const calls: MemorySessionCacheCalls = { reads: 0, writes: 0, tombstones: 0 };

  const keyOf = (realmId: string, sid: string) => `${realmId}:${sid}`;

  function live<T>(map: Map<string, Expiring<T>>, key: string): T | undefined {
    const item = map.get(key);
    if (item === undefined) return undefined;
    if (item.expiresAt <= clock.now()) {
      map.delete(key);
      return undefined;
    }
    return item.value;
  }

  const cache: MemorySessionCache = {
    calls,
    down: false,

    entry(realmId, sid) {
      const value = live(entries, keyOf(realmId, sid));
      return value === undefined ? undefined : structuredClone(value);
    },

    ttlOf(realmId, sid) {
      const key = keyOf(realmId, sid);
      if (live(entries, key) === undefined) return undefined;
      return (entries.get(key)?.expiresAt ?? 0) - clock.now();
    },

    clear() {
      entries.clear();
      tombstones.clear();
    },

    async read(realmId, sid): Promise<SessionCacheLookup> {
      if (cache.down) throw new Error('cache down');
      calls.reads += 1;
      const key = keyOf(realmId, sid);
      if (live(tombstones, key) !== undefined) return { kind: 'revoked' };
      const entry = live(entries, key);
      return entry === undefined
        ? { kind: 'empty' }
        : { kind: 'entry', entry: structuredClone(entry) };
    },

    async write(entry, ttlMs) {
      if (cache.down) throw new Error('cache down');
      calls.writes += 1;
      entries.set(keyOf(entry.record.realmId, entry.record.id), {
        value: structuredClone(entry),
        expiresAt: clock.now() + ttlMs,
      });
    },

    async markRevoked(realmId, sid, ttlMs) {
      if (cache.down) throw new Error('cache down');
      calls.tombstones += 1;
      const key = keyOf(realmId, sid);
      tombstones.set(key, { value: true, expiresAt: clock.now() + ttlMs });
      entries.delete(key);
    },
  };
  return cache;
}
