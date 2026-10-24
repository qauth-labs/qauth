/**
 * Why a browser session ended. The same list as `SESSION_REVOKED_REASONS` in
 * `@qauth-labs/infra-db`, whose CHECK `sessions_revoked_reason_valid` accepts
 * exactly these. This library may not import the database library, so the list
 * is repeated; the auth-server's store adapter passes a reason through to the
 * repository, and the compiler refuses a value the repository does not accept.
 */
export const SESSION_REVOKED_REASONS = [
  'sign_out',
  'sign_out_everywhere',
  'admin',
  'reset',
  'key_retired',
  'browser_limit',
  'idle',
  'expired',
] as const;

export type SessionRevokedReason = (typeof SESSION_REVOKED_REASONS)[number];

/** The eIDAS level of assurance a session's authentication established. */
export type SessionAssuranceLevel = 'substantial' | 'high';

/**
 * A `sessions` row, as the store port reads it. Times are epoch milliseconds.
 */
export interface SessionRecord {
  /** The session's `sid`. */
  id: string;
  realmId: string;
  userId: string;
  /** When the user authenticated (the ID token's `auth_time`). */
  authTime: number;
  /** The authentication methods used (the `amr` claim). */
  amr: string[];
  /** NULL when nothing above `low` was established. */
  assuranceLevel: SessionAssuranceLevel | null;
  ipAddress: string | null;
  userAgent: string | null;
  /** The absolute end set at creation. */
  expiresAt: number;
  revokedAt: number | null;
  revokedReason: SessionRevokedReason | null;
  createdAt: number;
  /** The last stored use; written at most once per interval. */
  lastSeenAt: number;
}

/**
 * What the store port inserts: every column but the id, which the database
 * makes, and the revocation pair, since a session starts live.
 */
export type NewSessionRecord = Omit<SessionRecord, 'id' | 'revokedAt' | 'revokedReason'>;

/**
 * A realm's browser session lifetimes, in seconds, from its `realms` row.
 */
export interface RealmSessionLifetimes {
  /**
   * `sso_max_lifespan`: the absolute end, counted from the session's creation.
   * NULL when the realm sets none; the service then uses `SESSION_COOKIE_TTL`.
   */
  maxLifespanSeconds: number | null;
  /**
   * `sso_idle_timeout`: how long a session may go unused. NULL when the realm
   * sets none, and then there is no idle limit.
   */
  idleTimeoutSeconds: number | null;
}

/** A session row together with its realm's lifetimes, as the store reads them. */
export interface StoredSession {
  session: SessionRecord;
  lifetimes: RealmSessionLifetimes;
}

/**
 * The part of a live session the cache holds. The address and the user agent
 * stay in Postgres, and so do the revocation columns: only a live session is
 * cached.
 */
export type CachedSessionRecord = Omit<
  SessionRecord,
  'ipAddress' | 'userAgent' | 'revokedAt' | 'revokedReason'
>;

/**
 * A cache entry: a live session as Postgres last showed it, its realm's
 * lifetimes at that moment, and the time after which the entry must not be
 * served without asking Postgres again.
 */
export interface CachedSession {
  record: CachedSessionRecord;
  lifetimes: RealmSessionLifetimes;
  /**
   * Epoch milliseconds: at most the cache time after the Postgres read the
   * entry came from, and never past the session's end.
   */
  freshUntil: number;
}

/** A signed-in browser session, as the service hands it out. */
export interface BrowserSession {
  /** The session id: the ID token's `sid` and the cookie's subject. */
  sid: string;
  realmId: string;
  userId: string;
  /** When the user authenticated, in epoch milliseconds. */
  authTime: number;
  amr: readonly string[];
  assuranceLevel: SessionAssuranceLevel | null;
  createdAt: number;
  /** The last stored use. May lag the last use by up to the write interval. */
  lastSeenAt: number;
  /**
   * The absolute end, in epoch milliseconds: the earlier of the stored
   * `expires_at` and the creation time plus the realm's current maximum
   * lifespan.
   */
  expiresAt: number;
  /**
   * When the realm's idle limit ends the session if it is not used again;
   * NULL when the realm has no idle limit.
   */
  idleExpiresAt: number | null;
}

/** Input of {@link SessionService.create}. */
export interface CreateSessionInput {
  realmId: string;
  userId: string;
  /** When the user authenticated, in epoch milliseconds. */
  authTime: number;
  /** The authentication methods used, such as `["pwd"]`. Defaults to none. */
  amr?: readonly string[];
  assuranceLevel?: SessionAssuranceLevel | null;
  /** The client address of the sign-in request. */
  ipAddress?: string | null;
  /** The `User-Agent` of the sign-in request. */
  userAgent?: string | null;
}

/** Names one session. Every lookup takes the realm (ADR-019 Decision 1). */
export interface SessionQuery {
  realmId: string;
  sid: string;
}

/** Input of {@link SessionService.revoke}. */
export interface RevokeSessionInput extends SessionQuery {
  reason: SessionRevokedReason;
}

/**
 * The browser session service (ADR-019 Decision 3). Postgres holds the truth,
 * the cache serves reads, and last-seen writes are throttled.
 */
export interface SessionService {
  /**
   * Store a new session: always a new row and a new id. Postgres first, then
   * the cache. Throws when Postgres cannot store it, or when the realm does
   * not exist ({@link UnknownSessionRealmError}).
   */
  create(input: CreateSessionInput): Promise<BrowserSession>;
  /**
   * The live session of that realm with that id, or `null`. A session is
   * absent when it is revoked, past its absolute end, past the realm's idle
   * limit, in another realm, or when Postgres is needed and cannot answer.
   * Never throws for an unreachable cache or database.
   *
   * Writes `last_seen_at` when the stored value is at least one interval old.
   */
  get(query: SessionQuery): Promise<BrowserSession | null>;
  /**
   * End a session: Postgres first, then the cache entry is replaced by a
   * short tombstone. Returns the ended row, or `null` when the realm holds no
   * live session with that id. Throws when Postgres cannot store the end.
   */
  revoke(input: RevokeSessionInput): Promise<SessionRecord | null>;
}
