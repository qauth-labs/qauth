import {
  lastSeenIntervalMs,
  sessionEnd,
  sessionEnds,
  type SessionVerdict,
  sessionVerdict,
} from './lifetimes';
import type { SessionCache, SessionLogger, SessionMetrics, SessionStore } from './ports';
import type {
  BrowserSession,
  CachedSession,
  CachedSessionRecord,
  CreateSessionInput,
  RealmSessionLifetimes,
  RevokeSessionInput,
  SessionQuery,
  SessionRecord,
  SessionService,
} from './types';

/** `SESSION_LAST_SEEN_INTERVAL`'s default: one minute (ADR-019, answers). */
export const DEFAULT_SESSION_LAST_SEEN_INTERVAL_SECONDS = 60;

/** How long a cache entry may serve a session without Postgres, by default. */
export const DEFAULT_SESSION_CACHE_TTL_SECONDS = 60;

/** How long a cache call may take before the service goes on without it, by default. */
export const DEFAULT_SESSION_CACHE_TIMEOUT_MS = 250;

/** The settings of {@link createSessionService}. */
export interface SessionServiceSettings {
  /**
   * `SESSION_COOKIE_TTL`: the absolute end, in seconds from creation, for a
   * realm that sets no `sso_max_lifespan`.
   */
  defaultMaxLifespanSeconds: number;
  /**
   * `SESSION_LAST_SEEN_INTERVAL`: `last_seen_at` is written at most once per
   * this many seconds per session. Defaults to
   * {@link DEFAULT_SESSION_LAST_SEEN_INTERVAL_SECONDS}.
   */
  lastSeenIntervalSeconds?: number;
  /**
   * How long, in seconds, a cache entry may serve a session without asking
   * Postgres, and how long a revocation's tombstone stays. Defaults to
   * {@link DEFAULT_SESSION_CACHE_TTL_SECONDS}.
   */
  cacheTtlSeconds?: number;
  /**
   * How long, in milliseconds, a cache call may take before the service treats
   * the cache as down for that call: a read goes to Postgres, a write is
   * dropped. A Redis that does not answer would otherwise hold every read for
   * as long as its client retries. Defaults to
   * {@link DEFAULT_SESSION_CACHE_TIMEOUT_MS}.
   */
  cacheTimeoutMs?: number;
}

/** What {@link createSessionService} works with. */
export interface SessionServiceOptions {
  store: SessionStore;
  cache: SessionCache;
  settings: SessionServiceSettings;
  metrics?: SessionMetrics;
  logger?: SessionLogger;
  /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
  now?: () => number;
}

/** Thrown by {@link SessionService.create} for a realm id with no realm row. */
export class UnknownSessionRealmError extends Error {
  constructor(readonly realmId: string) {
    super(`No realm with id ${realmId}: a session cannot be created in it`);
    this.name = 'UnknownSessionRealmError';
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const NO_METRICS: SessionMetrics = {
  cacheLookups: { inc: () => undefined },
  storeReads: { inc: () => undefined },
  lastSeenWrites: { inc: () => undefined },
};

const NO_LOGGER: SessionLogger = { warn: () => undefined };

/** A live session as the service holds it between the ports and the caller. */
interface LiveSession {
  record: CachedSessionRecord;
  lifetimes: RealmSessionLifetimes;
}

function positive(name: string, value: number, unit: string): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new RangeError(`${name} must be a positive number of ${unit}, got ${value}`);
  }
  return value;
}

function positiveSeconds(name: string, value: number): number {
  return positive(name, value, 'seconds');
}

/** A cache call that did not answer in time. */
class SessionCacheTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`The session cache did not answer within ${timeoutMs} ms`);
    this.name = 'SessionCacheTimeoutError';
  }
}

function cachedRecordOf(session: SessionRecord): CachedSessionRecord {
  return {
    id: session.id,
    realmId: session.realmId,
    userId: session.userId,
    authTime: session.authTime,
    amr: [...session.amr],
    assuranceLevel: session.assuranceLevel,
    expiresAt: session.expiresAt,
    createdAt: session.createdAt,
    lastSeenAt: session.lastSeenAt,
  };
}

/**
 * Create the browser session service (ADR-019 Decision 3, issue #469).
 *
 * Postgres ({@link SessionStore}) is the source of truth and the cache
 * ({@link SessionCache}) serves reads:
 *
 * - `create` writes Postgres, then the cache.
 * - `get` reads the cache, and Postgres on a miss, then fills the cache for at
 *   most the cache time and never past the session's end. A cache entry is
 *   never served past that time, whatever the cache's own expiry does. When
 *   the cache cannot answer, Postgres does; when Postgres cannot answer and
 *   is needed, the session is absent.
 * - `last_seen_at` is written at most once per interval per session, by one
 *   conditional `UPDATE`, so several nodes do not all write. Concurrent reads
 *   of one session on one node share one Postgres round trip.
 * - `revoke` writes Postgres, then a tombstone over the cache entry.
 *
 * Volatile per-flow values (the CSRF values, the consent scopes) are not part
 * of a session here and never reach Postgres: the caller keeps them in a
 * cache-only record of its own.
 */
export function createSessionService(options: SessionServiceOptions): SessionService {
  const { store, cache } = options;
  const metrics = options.metrics ?? NO_METRICS;
  const logger = options.logger ?? NO_LOGGER;
  const now = options.now ?? Date.now;
  const defaultMaxLifespanSeconds = positiveSeconds(
    'defaultMaxLifespanSeconds',
    options.settings.defaultMaxLifespanSeconds
  );
  const lastSeenIntervalSeconds = positiveSeconds(
    'lastSeenIntervalSeconds',
    options.settings.lastSeenIntervalSeconds ?? DEFAULT_SESSION_LAST_SEEN_INTERVAL_SECONDS
  );
  const cacheTtlMs =
    positiveSeconds(
      'cacheTtlSeconds',
      options.settings.cacheTtlSeconds ?? DEFAULT_SESSION_CACHE_TTL_SECONDS
    ) * 1000;
  const cacheTimeoutMs = positive(
    'cacheTimeoutMs',
    options.settings.cacheTimeoutMs ?? DEFAULT_SESSION_CACHE_TIMEOUT_MS,
    'milliseconds'
  );

  /** One Postgres round trip per session at a time on this node. */
  const inFlight = new Map<string, Promise<LiveSession | null>>();

  /**
   * A cache call, given up after {@link cacheTimeoutMs}. The call itself is
   * left to finish or fail on its own; its late failure is ignored.
   */
  function bounded<T>(call: Promise<T>): Promise<T> {
    call.catch(() => undefined);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new SessionCacheTimeoutError(cacheTimeoutMs)),
        cacheTimeoutMs
      );
    });
    return Promise.race([call, timeout]).finally(() => clearTimeout(timer));
  }

  function verdictOf(live: LiveSession, at: number): SessionVerdict {
    return sessionVerdict(sessionEnds(live.record, live.lifetimes, defaultMaxLifespanSeconds), at);
  }

  function touchIsDue(live: LiveSession, at: number): boolean {
    return (
      at - live.record.lastSeenAt >= lastSeenIntervalMs(live.lifetimes, lastSeenIntervalSeconds)
    );
  }

  function browserSessionOf(live: LiveSession): BrowserSession {
    const ends = sessionEnds(live.record, live.lifetimes, defaultMaxLifespanSeconds);
    return {
      sid: live.record.id,
      realmId: live.record.realmId,
      userId: live.record.userId,
      authTime: live.record.authTime,
      amr: Object.freeze([...live.record.amr]),
      assuranceLevel: live.record.assuranceLevel,
      createdAt: live.record.createdAt,
      lastSeenAt: live.record.lastSeenAt,
      expiresAt: ends.absolute,
      idleExpiresAt: ends.idle,
    };
  }

  /**
   * Store `live` in the cache until `freshUntil`, capped at the session's end.
   * The time already spent since the Postgres read counts against it. A cache
   * failure is logged and otherwise ignored: Postgres has the session.
   */
  async function fillCache(live: LiveSession, freshUntil: number): Promise<void> {
    const until = Math.min(
      freshUntil,
      sessionEnd(sessionEnds(live.record, live.lifetimes, defaultMaxLifespanSeconds))
    );
    const ttlMs = until - now();
    if (ttlMs <= 0) return;
    const entry: CachedSession = {
      record: live.record,
      lifetimes: live.lifetimes,
      freshUntil: until,
    };
    try {
      await bounded(cache.write(entry, ttlMs));
    } catch (error) {
      logger.warn(
        { err: error, realmId: live.record.realmId },
        'Session cache write failed; the session is served from Postgres'
      );
    }
  }

  /**
   * Write `last_seen_at` if the stored value is at least one interval old.
   * `error` means Postgres did not answer.
   */
  async function touch(live: LiveSession): Promise<'written' | 'skipped' | 'error'> {
    try {
      const written = await store.touchLastSeen(
        live.record.realmId,
        live.record.id,
        lastSeenIntervalMs(live.lifetimes, lastSeenIntervalSeconds)
      );
      metrics.lastSeenWrites.inc({ result: written ? 'written' : 'skipped' });
      return written ? 'written' : 'skipped';
    } catch (error) {
      metrics.lastSeenWrites.inc({ result: 'error' });
      logger.warn(
        { err: error, realmId: live.record.realmId },
        'Session last-seen write failed; the session is treated as absent'
      );
      return 'error';
    }
  }

  /** Read the session from Postgres, touch it when due, and fill the cache. */
  async function readThrough(realmId: string, sid: string): Promise<LiveSession | null> {
    const readAt = now();
    let stored;
    try {
      stored = await store.find(realmId, sid);
      metrics.storeReads.inc({ result: 'ok' });
    } catch (error) {
      metrics.storeReads.inc({ result: 'error' });
      logger.warn({ err: error, realmId }, 'Session read failed; the session is treated as absent');
      return null;
    }
    if (stored === undefined) return null;
    const { session, lifetimes } = stored;
    if (session.realmId !== realmId || session.id !== sid || session.revokedAt !== null) {
      return null;
    }
    let live: LiveSession = { record: cachedRecordOf(session), lifetimes };
    if (verdictOf(live, readAt) !== 'live') return null;
    if (touchIsDue(live, readAt)) {
      const touched = await touch(live);
      if (touched === 'error') return null;
      if (touched === 'written') live = { ...live, record: { ...live.record, lastSeenAt: readAt } };
    }
    await fillCache(live, readAt + cacheTtlMs);
    return live;
  }

  /**
   * A cache hit whose last-seen time is due for a write, or whose cached
   * last-seen time says idle (another node may have written a newer one).
   */
  async function refreshHit(entry: CachedSession, at: number): Promise<LiveSession | null> {
    const live: LiveSession = { record: entry.record, lifetimes: entry.lifetimes };
    if (verdictOf(live, at) === 'live') {
      const touched = await touch(live);
      if (touched === 'error') return null;
      if (touched === 'written') {
        const seen: LiveSession = { ...live, record: { ...live.record, lastSeenAt: at } };
        // Postgres has confirmed the session is live, but the entry keeps the
        // freshness of the read it came from: the realm row is read again
        // when it lapses.
        await fillCache(seen, entry.freshUntil);
        return seen;
      }
      // Skipped: another node wrote it first, or the session ended since the
      // entry was filled. Postgres says which.
    }
    return readThrough(live.record.realmId, live.record.id);
  }

  function shared(key: string, work: () => Promise<LiveSession | null>) {
    const running = inFlight.get(key);
    if (running !== undefined) return running;
    const started: Promise<LiveSession | null> = work().finally(() => {
      if (inFlight.get(key) === started) inFlight.delete(key);
    });
    inFlight.set(key, started);
    return started;
  }

  return {
    async create(input: CreateSessionInput): Promise<BrowserSession> {
      const lifetimes = await store.findRealmLifetimes(input.realmId);
      if (lifetimes === undefined) throw new UnknownSessionRealmError(input.realmId);
      const createdAt = now();
      // Only the session's own columns are written: whatever else a caller
      // passes (a CSRF value, consent scopes) never reaches Postgres.
      const session = await store.insert({
        realmId: input.realmId,
        userId: input.userId,
        authTime: input.authTime,
        amr: [...(input.amr ?? [])],
        assuranceLevel: input.assuranceLevel ?? null,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
        createdAt,
        lastSeenAt: createdAt,
        expiresAt: createdAt + (lifetimes.maxLifespanSeconds ?? defaultMaxLifespanSeconds) * 1000,
      });
      const live: LiveSession = { record: cachedRecordOf(session), lifetimes };
      await fillCache(live, createdAt + cacheTtlMs);
      return browserSessionOf(live);
    },

    async get(query: SessionQuery): Promise<BrowserSession | null> {
      const realmId = query.realmId.toLowerCase();
      const sid = query.sid.toLowerCase();
      // A malformed id names no session, and must not reach Postgres as a
      // query error that would read as an outage.
      if (!UUID.test(realmId) || !UUID.test(sid)) return null;

      const at = now();
      const key = `${realmId}:${sid}`;
      let lookup;
      try {
        lookup = await bounded(cache.read(realmId, sid));
      } catch (error) {
        metrics.cacheLookups.inc({ result: 'error' });
        logger.warn({ err: error, realmId }, 'Session cache read failed; reading Postgres');
      }

      if (lookup?.kind === 'revoked') {
        metrics.cacheLookups.inc({ result: 'revoked' });
        return null;
      }
      if (lookup?.kind === 'entry') {
        const { entry } = lookup;
        // An entry past its freshness is a miss, whatever expiry the cache
        // itself gave it: the cache alone never vouches for longer.
        const usable =
          entry.record.realmId === realmId && entry.record.id === sid && entry.freshUntil > at;
        if (usable) {
          metrics.cacheLookups.inc({ result: 'hit' });
          const live: LiveSession = { record: entry.record, lifetimes: entry.lifetimes };
          const verdict = verdictOf(live, at);
          if (verdict === 'ended') return null;
          if (verdict === 'live' && !touchIsDue(live, at)) return browserSessionOf(live);
          const refreshed = await shared(key, () => refreshHit(entry, at));
          return refreshed === null ? null : browserSessionOf(refreshed);
        }
      }
      if (lookup !== undefined) metrics.cacheLookups.inc({ result: 'miss' });

      const read = await shared(key, () => readThrough(realmId, sid));
      return read === null ? null : browserSessionOf(read);
    },

    async revoke(input: RevokeSessionInput): Promise<SessionRecord | null> {
      const realmId = input.realmId.toLowerCase();
      const sid = input.sid.toLowerCase();
      if (!UUID.test(realmId) || !UUID.test(sid)) return null;
      const ended = await store.revoke(realmId, sid, input.reason);
      // A read started on this node before the end must not answer the reads
      // that come after it.
      inFlight.delete(`${realmId}:${sid}`);
      // Written whether or not this call ended the row: a stale entry of a
      // session that was already ended goes too.
      try {
        await bounded(cache.markRevoked(realmId, sid, cacheTtlMs));
      } catch (error) {
        logger.warn(
          { err: error, realmId },
          'Session cache tombstone write failed; another node may serve the session until its cache entry lapses'
        );
      }
      return ended ?? null;
    },
  };
}
