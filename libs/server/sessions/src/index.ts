// Browser session service: Postgres as source of truth, Redis as cache (ADR-019 Decision 3)
export {
  lastSeenIntervalMs,
  type SessionEnds,
  sessionEnds,
  type SessionVerdict,
  sessionVerdict,
} from './lib/lifetimes';
export type {
  SessionCache,
  SessionCacheLookup,
  SessionCacheResult,
  SessionLastSeenWriteResult,
  SessionLogger,
  SessionMetrics,
  SessionStore,
  SessionStoreReadResult,
} from './lib/ports';
export {
  createRedisSessionCache,
  sessionCacheKey,
  type SessionRedisClient,
  sessionTombstoneKey,
} from './lib/redis-session-cache';
export {
  createSessionService,
  DEFAULT_SESSION_CACHE_TIMEOUT_MS,
  DEFAULT_SESSION_CACHE_TTL_SECONDS,
  DEFAULT_SESSION_LAST_SEEN_INTERVAL_SECONDS,
  type SessionServiceOptions,
  type SessionServiceSettings,
  UnknownSessionRealmError,
} from './lib/session-service';
export {
  type BrowserSession,
  type CachedSession,
  type CachedSessionRecord,
  type CreateSessionInput,
  type NewSessionRecord,
  type RealmSessionLifetimes,
  type RevokeSessionInput,
  SESSION_REVOKED_REASONS,
  type SessionAssuranceLevel,
  type SessionQuery,
  type SessionRecord,
  type SessionRevokedReason,
  type SessionService,
  type StoredSession,
} from './lib/types';
// In-memory ports, for the unit tests of this library and of its callers
export {
  createManualClock,
  createMemorySessionCache,
  createMemorySessionStore,
  type ManualClock,
  type MemorySessionCache,
  type MemorySessionCacheCalls,
  type MemorySessionStore,
  type MemorySessionStoreCalls,
} from './testing/memory-ports';
