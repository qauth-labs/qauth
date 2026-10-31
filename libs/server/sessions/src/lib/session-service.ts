import {
  lastSeenIntervalMs,
  sessionEnd,
  sessionEnds,
  type SessionVerdict,
  sessionVerdict,
} from './lifetimes';
import type {
  SessionCache,
  SessionCacheLookup,
  SessionListOwner,
  SessionLogger,
  SessionMetrics,
  SessionStore,
  StoredSessionList,
} from './ports';
import { decodeSessionCursor, encodeSessionCursor, type SessionList } from './session-cursor';
import {
  type BrowserSession,
  type CachedSession,
  type CachedSessionRecord,
  type CreateSessionInput,
  type EndedSession,
  type ListedSession,
  type RealmSessionLifetimes,
  type RevokeSessionInput,
  type RevokeSessionResult,
  SESSION_ACTOR_TYPES,
  SESSION_REVOKED_REASONS,
  type SessionActor,
  type SessionPage,
  type SessionPageRequest,
  type SessionQuery,
  type SessionRecord,
  type SessionRevokedReason,
  type SessionsEndedListener,
  type SessionService,
  type SessionState,
} from './types';

/** `SESSION_LAST_SEEN_INTERVAL`'s default: one minute (ADR-019, answers). */
export const DEFAULT_SESSION_LAST_SEEN_INTERVAL_SECONDS = 60;

/** How long a cache entry may serve a session without Postgres, by default. */
export const DEFAULT_SESSION_CACHE_TTL_SECONDS = 60;

/** How long a cache call may take before the service goes on without it, by default. */
export const DEFAULT_SESSION_CACHE_TIMEOUT_MS = 250;

/** Sessions per page when the caller asks for no limit: the APIs' `PAGE_LIMIT_DEFAULT`. */
export const DEFAULT_SESSION_PAGE_LIMIT = 50;

/** The largest page: the APIs' `PAGE_LIMIT_MAX`. A larger limit is refused, not clamped. */
export const MAX_SESSION_PAGE_LIMIT = 200;

/**
 * Sessions a bulk revocation ends per transaction, by default: short enough
 * that no transaction holds a realm's rows for long.
 */
export const DEFAULT_SESSION_REVOCATION_BATCH_SIZE = 500;

/** Rows the purge deletes per statement, by default. */
export const DEFAULT_SESSION_PURGE_BATCH_SIZE = 1000;

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
   * Postgres; a revocation's tombstone stays twice as long. Defaults to
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

/** The system actor: what the service's own sweeps end sessions as. */
const SYSTEM_ACTOR: SessionActor = Object.freeze({ type: 'system' });

const EMPTY_PAGE: SessionPage = Object.freeze({ items: [], nextCursor: null }) as SessionPage;

/** An id as the service compares it, or `undefined` when it names nothing. */
function idOf(value: string): string | undefined {
  const id = value.toLowerCase();
  return UUID.test(id) ? id : undefined;
}

function checkedReason(reason: SessionRevokedReason): SessionRevokedReason {
  if (!(SESSION_REVOKED_REASONS as readonly string[]).includes(reason)) {
    throw new RangeError(`Unknown session revocation reason: ${String(reason)}`);
  }
  return reason;
}

function checkedActor(actor: SessionActor): SessionActor {
  if (
    typeof actor !== 'object' ||
    actor === null ||
    !(SESSION_ACTOR_TYPES as readonly string[]).includes(actor.type) ||
    (actor.id !== undefined && (typeof actor.id !== 'string' || actor.id.length === 0))
  ) {
    throw new RangeError('A session revocation needs an actor: a known type and a non-empty id');
  }
  return actor.id === undefined ? { type: actor.type } : { type: actor.type, id: actor.id };
}

function checkedTime(name: string, value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isFinite(value)) {
    throw new RangeError(`${name} must be epoch milliseconds, got ${value}`);
  }
  return value;
}

function checkedBatchSize(value: number | undefined, fallback: number): number {
  const size = value ?? fallback;
  if (!Number.isInteger(size) || size < 1) {
    throw new RangeError(`A batch size must be a positive integer, got ${size}`);
  }
  return size;
}

function checkedLimit(page: SessionPageRequest | undefined): number {
  const limit = page?.limit ?? DEFAULT_SESSION_PAGE_LIMIT;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_SESSION_PAGE_LIMIT) {
    throw new RangeError(
      `A page limit must be an integer from 1 to ${MAX_SESSION_PAGE_LIMIT}, got ${limit}`
    );
  }
  return limit;
}

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
 * - `revoke`, `revokeAllForUser` and `revokeAllForRealm` write Postgres,
 *   then a tombstone over each ended session's cache entry, then tell the
 *   `onSessionsEnded` listeners. The realm-wide one works in batches.
 * - `endLapsed` marks the sessions past an end, which `get` already treats as
 *   absent, so their registry rows go too; `purge` deletes old ended rows.
 * - `listForUser` and `listForClient` page through sessions, newest first,
 *   with their state and clients.
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

  /** The listeners of `onSessionsEnded`, in registration order. */
  const listeners = new Set<SessionsEndedListener>();

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

  /**
   * Read the session from Postgres, touch it when due, and fill the cache,
   * unless `fill` is off because the cache did not answer the read before.
   */
  async function readThrough(
    realmId: string,
    sid: string,
    fill: boolean
  ): Promise<LiveSession | null> {
    // The entry's freshness counts from before the read, so it lapses before
    // the tombstone of a revocation that came after the read.
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
    // Judged when the answer is in, not when the read began.
    const judgedAt = now();
    if (verdictOf(live, judgedAt) !== 'live') return null;
    if (touchIsDue(live, judgedAt)) {
      const touched = await touch(live);
      if (touched === 'error') return null;
      if (touched === 'written') {
        live = { ...live, record: { ...live.record, lastSeenAt: judgedAt } };
      }
    }
    if (fill) await fillCache(live, readAt + cacheTtlMs);
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
    return readThrough(live.record.realmId, live.record.id, true);
  }

  /**
   * What follows the end of `ended` in Postgres: reads already waiting on
   * Postgres on this node no longer answer for them, a tombstone replaces
   * each cache entry, then the listeners hear of them.
   *
   * Each tombstone lasts twice the cache time, so it outlives any entry
   * filled from a read before the end, even one whose write reached the cache
   * late, read by a node whose clock lags. A tombstone the cache does not
   * take leaves another node serving the session until its entry lapses,
   * within the cache time.
   */
  async function afterEnded(
    realmId: string,
    reason: SessionRevokedReason,
    actor: SessionActor,
    ended: readonly EndedSession[]
  ): Promise<void> {
    if (ended.length === 0) return;
    for (const { session } of ended) inFlight.delete(`${realmId}:${session.id}`);
    const written = await Promise.all(
      ended.map(({ session }) =>
        bounded(cache.markRevoked(realmId, session.id, 2 * cacheTtlMs)).then(
          () => true,
          () => false
        )
      )
    );
    const failed = written.filter((ok) => !ok).length;
    if (failed > 0) {
      logger.warn(
        { realmId, sessions: failed },
        'Session cache tombstone write failed; another node may serve the session until its cache entry lapses'
      );
    }
    await notify({ realmId, reason, actor, sessions: ended });
  }

  /** Hand a notice to each listener in turn. A listener's failure is logged and stops nothing. */
  async function notify(notice: {
    realmId: string;
    reason: SessionRevokedReason;
    actor: SessionActor;
    sessions: readonly EndedSession[];
  }): Promise<void> {
    for (const listener of [...listeners]) {
      try {
        await listener(Object.freeze({ ...notice, sessions: Object.freeze([...notice.sessions]) }));
      } catch (error) {
        logger.warn(
          {
            err: error,
            realmId: notice.realmId,
            reason: notice.reason,
            sessions: notice.sessions.length,
          },
          'A sessions-ended listener failed; the sessions stay ended'
        );
      }
    }
  }

  /** A listed row as the caller sees it, judged at `at`. */
  function listedSessionOf(
    row: StoredSessionList['sessions'][number],
    lifetimes: RealmSessionLifetimes,
    at: number
  ): ListedSession {
    const { session } = row;
    const ends = sessionEnds(session, lifetimes, defaultMaxLifespanSeconds);
    let state: SessionState;
    if (session.revokedAt !== null) {
      // The purge job marks a lapsed session with the end it passed.
      state =
        session.revokedReason === 'idle'
          ? 'idle'
          : session.revokedReason === 'expired'
            ? 'expired'
            : 'revoked';
    } else {
      const verdict = sessionVerdict(ends, at);
      state = verdict === 'ended' ? 'expired' : verdict;
    }
    return {
      sid: session.id,
      realmId: session.realmId,
      userId: session.userId,
      authTime: session.authTime,
      amr: Object.freeze([...session.amr]),
      assuranceLevel: session.assuranceLevel,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      createdAt: session.createdAt,
      lastSeenAt: session.lastSeenAt,
      expiresAt: ends.absolute,
      idleExpiresAt: ends.idle,
      state,
      revokedAt: session.revokedAt,
      revokedReason: session.revokedReason,
      clients: Object.freeze(row.clients.map((client) => ({ ...client }))),
    };
  }

  /** One page of `list`: `limit` rows and, when there are more, the next page's cursor. */
  async function listPage(
    realmId: string | undefined,
    owner: SessionListOwner | undefined,
    page: SessionPageRequest | undefined
  ): Promise<SessionPage> {
    const limit = checkedLimit(page);
    // A malformed id names no realm, user or client: an empty list, and no
    // query error that would read as an outage.
    if (realmId === undefined || owner === undefined) return EMPTY_PAGE;
    const list: SessionList = { realmId, owner };
    const after = page?.cursor === undefined ? undefined : decodeSessionCursor(list, page.cursor);
    const stored = await store.list(realmId, owner, {
      limit: limit + 1,
      ...(after === undefined ? {} : { after }),
    });
    if (stored === undefined) return EMPTY_PAGE;
    const at = now();
    const items = stored.sessions
      .slice(0, limit)
      .map((row) => listedSessionOf(row, stored.lifetimes, at));
    const last = items[items.length - 1];
    return {
      items,
      nextCursor:
        stored.sessions.length > limit && last !== undefined
          ? encodeSessionCursor(list, { createdAt: last.createdAt, sid: last.sid })
          : null,
    };
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
      if (!UUID.test(input.realmId.toLowerCase())) {
        throw new UnknownSessionRealmError(input.realmId);
      }
      const lifetimes = await store.findRealmLifetimes(input.realmId);
      if (lifetimes === undefined) throw new UnknownSessionRealmError(input.realmId);
      const current = now();
      const createdAt =
        input.issuedAt !== undefined && Number.isFinite(input.issuedAt)
          ? Math.min(input.issuedAt, current)
          : current;
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

      const key = `${realmId}:${sid}`;
      let lookup: SessionCacheLookup | undefined;
      try {
        lookup = await bounded(cache.read(realmId, sid));
      } catch (error) {
        metrics.cacheLookups.inc({ result: 'error' });
        logger.warn({ err: error, realmId }, 'Session cache read failed; reading Postgres');
      }
      // Taken after the read, which may have waited up to the cache timeout.
      const at = now();

      if (lookup?.kind === 'revoked') {
        metrics.cacheLookups.inc({ result: 'revoked' });
        return null;
      }
      if (lookup?.kind === 'entry') {
        const { entry } = lookup;
        // An entry past its freshness is a miss, whatever expiry the cache
        // itself gave it: the cache alone never vouches for longer. So is one
        // that claims more than the cache time from now, which no node of
        // this deployment writes.
        const usable =
          entry.record.realmId === realmId &&
          entry.record.id === sid &&
          entry.freshUntil > at &&
          entry.freshUntil <= at + cacheTtlMs;
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

      // A cache that did not answer the read is not asked to store the result.
      const cacheAnswered = lookup !== undefined;
      const read = await shared(key, () => readThrough(realmId, sid, cacheAnswered));
      return read === null ? null : browserSessionOf(read);
    },

    async revoke(input: RevokeSessionInput): Promise<RevokeSessionResult> {
      const reason = checkedReason(input.reason);
      const actor = checkedActor(input.actor);
      const realmId = idOf(input.realmId);
      const sid = idOf(input.sid);
      if (realmId === undefined || sid === undefined) return { outcome: 'not_found' };
      const ended = await store.revoke(realmId, sid, reason);
      if (ended !== undefined) {
        await afterEnded(realmId, reason, actor, [ended]);
        return { outcome: 'ended', session: ended.session, clients: ended.clients };
      }
      // Nothing ended here. A read started on this node before an earlier
      // end must still not answer the reads after it, and a stale entry of a
      // session that was already ended goes too.
      inFlight.delete(`${realmId}:${sid}`);
      try {
        await bounded(cache.markRevoked(realmId, sid, 2 * cacheTtlMs));
      } catch (error) {
        logger.warn(
          { err: error, realmId },
          'Session cache tombstone write failed; another node may serve the session until its cache entry lapses'
        );
      }
      const stored = await store.find(realmId, sid);
      return stored !== undefined && stored.session.revokedAt !== null
        ? { outcome: 'already_ended', session: stored.session }
        : { outcome: 'not_found' };
    },

    async revokeAllForUser(input) {
      const reason = checkedReason(input.reason);
      const actor = checkedActor(input.actor);
      const createdBefore = checkedTime('createdBefore', input.createdBefore);
      let exceptSid: string | undefined;
      if (input.exceptSid !== undefined) {
        exceptSid = idOf(input.exceptSid);
        // Ending the one session the caller meant to keep is not a fallback.
        if (exceptSid === undefined) throw new RangeError('exceptSid is not a session id');
      }
      const realmId = idOf(input.realmId);
      const userId = idOf(input.userId);
      if (realmId === undefined || userId === undefined) return { sessions: [] };
      const ended = await store.revokeForUser(realmId, userId, reason, {
        ...(exceptSid === undefined ? {} : { exceptSid }),
        ...(createdBefore === undefined ? {} : { createdBefore }),
      });
      await afterEnded(realmId, reason, actor, ended);
      return { sessions: ended };
    },

    async revokeAllForRealm(input) {
      const reason = checkedReason(input.reason);
      const actor = checkedActor(input.actor);
      const activeSince = checkedTime('activeSince', input.activeSince);
      const limit = checkedBatchSize(input.batchSize, DEFAULT_SESSION_REVOCATION_BATCH_SIZE);
      const realmId = idOf(input.realmId);
      if (realmId === undefined) return { ended: 0, batches: 0 };
      // Sessions created after the call began are not ended: a sign-in after
      // a key retirement or a bulk revocation was decided stands.
      const createdThrough = now();
      let after: string | null = null;
      let ended = 0;
      let batches = 0;
      for (;;) {
        const batch = await store.revokeRealmBatch(realmId, reason, {
          after,
          createdThrough,
          ...(activeSince === undefined ? {} : { activeSince }),
          limit,
        });
        if (batch.selected === 0) break;
        batches += 1;
        ended += batch.ended.length;
        await afterEnded(realmId, reason, actor, batch.ended);
        if (batch.selected < limit || batch.last === null) break;
        after = batch.last;
      }
      return { ended, batches };
    },

    async endLapsed(input = {}) {
      const limit = checkedBatchSize(input.batchSize, DEFAULT_SESSION_REVOCATION_BATCH_SIZE);
      // One moment for the whole run, so the id order moves forward through
      // a fixed set; what lapses during the run is the next run's.
      const at = now();
      let after: string | null = null;
      let ended = 0;
      for (;;) {
        input.signal?.throwIfAborted();
        const batch = await store.revokeLapsedBatch({
          now: at,
          defaultMaxLifespanSeconds,
          after,
          limit,
        });
        if (batch.selected === 0) break;
        ended += batch.ended.length;
        // A notice is one realm and one reason.
        const groups = new Map<string, EndedSession[]>();
        for (const item of batch.ended) {
          const key = `${item.session.realmId} ${String(item.session.revokedReason)}`;
          groups.set(key, [...(groups.get(key) ?? []), item]);
        }
        for (const group of groups.values()) {
          const { realmId, revokedReason } = group[0].session;
          await afterEnded(realmId, revokedReason ?? 'expired', SYSTEM_ACTOR, group);
        }
        if (batch.selected < limit || batch.last === null) break;
        after = batch.last;
      }
      return { ended };
    },

    async purge(input) {
      const before = checkedTime('endedBefore', input.endedBefore);
      if (before === undefined) throw new RangeError('endedBefore is required');
      const limit = checkedBatchSize(input.batchSize, DEFAULT_SESSION_PURGE_BATCH_SIZE);
      let after: string | null = null;
      let deleted = 0;
      for (;;) {
        input.signal?.throwIfAborted();
        const batch = await store.deleteEnded({ before, after, limit });
        deleted += batch.deleted;
        if (batch.selected < limit || batch.last === null) break;
        after = batch.last;
      }
      return { deleted };
    },

    listForUser(input) {
      const userId = idOf(input.userId);
      return listPage(
        idOf(input.realmId),
        userId === undefined ? undefined : { userId },
        input.page
      );
    },

    listForClient(input) {
      const oauthClientId = idOf(input.oauthClientId);
      return listPage(
        idOf(input.realmId),
        oauthClientId === undefined ? undefined : { oauthClientId },
        input.page
      );
    },

    onSessionsEnded(listener) {
      if (typeof listener !== 'function') throw new TypeError('A listener must be a function');
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}
