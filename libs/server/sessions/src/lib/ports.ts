import type {
  CachedSession,
  EndedSession,
  NewSessionRecord,
  RealmSessionLifetimes,
  SessionClientRecord,
  SessionRecord,
  SessionRevokedReason,
  StoredSession,
} from './types';

/** Whose sessions a list reads: a user's, or those that served a client. */
export type SessionListOwner = { userId: string } | { oauthClientId: string };

/** The last row a page showed: the next page starts after it. */
export interface SessionListPosition {
  createdAt: number;
  sid: string;
}

/** What {@link SessionStore.list} reads. */
export interface StoredSessionList {
  /** The realm's current lifetimes, to judge each session's state. */
  lifetimes: RealmSessionLifetimes;
  /** Newest first (`createdAt`, then `sid`). */
  sessions: Array<{ session: SessionRecord; clients: SessionClientRecord[] }>;
}

/** What one batch of a bulk revocation did. */
export interface SessionRevocationBatch {
  /** The sessions it ended. */
  ended: EndedSession[];
  /** The id the next batch starts after; `null` when it selected none. */
  last: string | null;
  /** How many sessions it selected: fewer than its limit ends the run. */
  selected: number;
}

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
   * Set `revoked_at` and `revoked_reason` on a row not yet revoked, and take
   * its registry rows with it, in one transaction.
   *
   * @returns the ended row and the clients it served, or `undefined` when the
   * realm holds no such session or it was already revoked
   */
  revoke(
    realmId: string,
    sid: string,
    reason: SessionRevokedReason
  ): Promise<EndedSession | undefined>;
  /**
   * End a user's sessions not yet revoked, but `exceptSid` and those created
   * at or after `createdBefore`, in one transaction, as {@link revoke}.
   *
   * @returns the sessions this call ended
   */
  revokeForUser(
    realmId: string,
    userId: string,
    reason: SessionRevokedReason,
    filter: { exceptSid?: string; createdBefore?: number }
  ): Promise<EndedSession[]>;
  /**
   * End one batch of the realm's sessions not yet revoked, in id order after
   * `batch.after`, created by `batch.createdThrough` and, with
   * `batch.activeSince`, last seen since then: one transaction per call.
   */
  revokeRealmBatch(
    realmId: string,
    reason: SessionRevokedReason,
    batch: { after: string | null; createdThrough: number; activeSince?: number; limit: number }
  ): Promise<SessionRevocationBatch>;
  /**
   * Mark one batch of sessions, of every realm, past their absolute end or
   * their realm's idle limit at `batch.now`, under the rules of
   * `sessionEnds`, as `expired` or `idle`, with the time each one ended.
   */
  revokeLapsedBatch(batch: {
    now: number;
    defaultMaxLifespanSeconds: number;
    after: string | null;
    limit: number;
  }): Promise<SessionRevocationBatch>;
  /**
   * One page of sessions of the realm, newest first, after `page.after`.
   *
   * @returns `undefined` when there is no such realm
   */
  list(
    realmId: string,
    owner: SessionListOwner,
    page: { limit: number; after?: SessionListPosition }
  ): Promise<StoredSessionList | undefined>;
  /**
   * Delete one batch of rows, of every realm, revoked or past their stored
   * `expires_at` before `batch.before`, in id order after `batch.after`.
   */
  deleteEnded(batch: {
    before: number;
    after: string | null;
    limit: number;
  }): Promise<{ deleted: number; last: string | null; selected: number }>;
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
