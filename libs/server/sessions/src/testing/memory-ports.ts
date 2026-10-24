import { randomUUID } from 'node:crypto';

import type { SessionCache, SessionCacheLookup, SessionStore } from '../lib/ports';
import type {
  CachedSession,
  NewSessionRecord,
  RealmSessionLifetimes,
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
}

/** {@link SessionStore} in memory, with the repository's conditions. */
export interface MemorySessionStore extends SessionStore {
  /** Add or replace a realm and its lifetimes. */
  putRealm(realmId: string, lifetimes?: Partial<RealmSessionLifetimes>): void;
  /** The stored row, or `undefined`. */
  row(sid: string): SessionRecord | undefined;
  /** Change a stored row, as another writer would. */
  update(sid: string, changes: Partial<SessionRecord>): void;
  readonly calls: MemorySessionStoreCalls;
  /** While `true`, every method throws, as with Postgres stopped. */
  down: boolean;
}

function copyOf(row: SessionRecord): SessionRecord {
  return { ...row, amr: [...row.amr] };
}

export function createMemorySessionStore(clock: { now(): number }): MemorySessionStore {
  const realms = new Map<string, RealmSessionLifetimes>();
  const rows = new Map<string, SessionRecord>();
  const calls: MemorySessionStoreCalls = {
    realmReads: 0,
    inserts: 0,
    reads: 0,
    touchAttempts: 0,
    touchWrites: 0,
    revokes: 0,
  };

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

    async revoke(realmId, sid, reason: SessionRevokedReason) {
      if (store.down) throw new Error('store down');
      calls.revokes += 1;
      const row = rows.get(sid);
      if (row === undefined || row.realmId !== realmId || row.revokedAt !== null) {
        return undefined;
      }
      const ended: SessionRecord = { ...row, revokedAt: clock.now(), revokedReason: reason };
      rows.set(sid, ended);
      return copyOf(ended);
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
