import type {
  CachedSession,
  NewSessionRecord,
  RealmSessionLifetimes,
  SessionRecord,
  SessionRevokedReason,
  StoredSession,
} from './types';

/**
 * The Postgres port: where sessions are true. The auth-server implements it
 * over the sessions and realms repositories of `@qauth-labs/infra-db`.
 *
 * Every method that names a session takes its realm, and a session of another
 * realm is never found, touched or ended. A method throws when the database
 * cannot answer; the service turns that into an absent session on reads.
 */
export interface SessionStore {
  /** The realm's lifetimes, or `undefined` when there is no such realm. */
  findRealmLifetimes(realmId: string): Promise<RealmSessionLifetimes | undefined>;
  /** Insert a live session. The database makes its id. */
  insert(session: NewSessionRecord): Promise<SessionRecord>;
  /**
   * The session with that id in that realm, whatever its state, with the
   * realm's lifetimes; `undefined` when the realm holds no such session.
   */
  find(realmId: string, sid: string): Promise<StoredSession | undefined>;
  /**
   * Set `last_seen_at` to now in one conditional `UPDATE`: only on a live row
   * (not revoked, before `expires_at`) whose stored value is at least
   * `minIntervalMs` old. Of several nodes calling it within the interval, only
   * the first writes.
   *
   * @returns `true` when this call wrote the row
   */
  touchLastSeen(realmId: string, sid: string, minIntervalMs: number): Promise<boolean>;
  /**
   * Set `revoked_at` and `revoked_reason` on a row not yet revoked.
   *
   * @returns the ended row, or `undefined` when the realm holds no such
   * session or it was already revoked
   */
  revoke(
    realmId: string,
    sid: string,
    reason: SessionRevokedReason
  ): Promise<SessionRecord | undefined>;
}

/** What the cache holds for a session. */
export type SessionCacheLookup =
  | { kind: 'empty' }
  /** A tombstone: the session was ended a short while ago. */
  | { kind: 'revoked' }
  | { kind: 'entry'; entry: CachedSession };

/**
 * The cache port, in front of Postgres. The auth-server uses
 * {@link createRedisSessionCache}. Losing its data costs Postgres reads and
 * nothing else; a method throws when the cache cannot answer.
 */
export interface SessionCache {
  /** The entry and the tombstone of a session, read together. */
  read(realmId: string, sid: string): Promise<SessionCacheLookup>;
  /** Store an entry for `ttlMs` milliseconds, replacing an older one. */
  write(entry: CachedSession, ttlMs: number): Promise<void>;
  /**
   * Write a tombstone for `ttlMs` milliseconds, then delete the entry. A read
   * that sees the tombstone answers "absent" whatever entry it also sees, so
   * an entry filled from a read that began before the revocation cannot bring
   * the session back.
   */
  markRevoked(realmId: string, sid: string, ttlMs: number): Promise<void>;
}

/** How a cache read went: `hit` and `miss` give the cache hit rate. */
export type SessionCacheResult = 'hit' | 'miss' | 'revoked' | 'error';
/** How a Postgres read of a session went. */
export type SessionStoreReadResult = 'ok' | 'error';
/** How a last-seen write went: `skipped` when another node had written it. */
export type SessionLastSeenWriteResult = 'written' | 'skipped' | 'error';

/**
 * Where the service counts its work. A prom-client `Counter<'result'>` fits
 * each one.
 */
export interface SessionMetrics {
  /** One per cache read made by {@link SessionService.get}. */
  cacheLookups: { inc(labels: { result: SessionCacheResult }): void };
  /** One per Postgres read of a session. */
  storeReads: { inc(labels: { result: SessionStoreReadResult }): void };
  /** One per conditional `last_seen_at` update sent to Postgres. */
  lastSeenWrites: { inc(labels: { result: SessionLastSeenWriteResult }): void };
}

/** The part of a pino-style logger the service uses. */
export interface SessionLogger {
  warn(fields: Record<string, unknown>, message: string): void;
}
