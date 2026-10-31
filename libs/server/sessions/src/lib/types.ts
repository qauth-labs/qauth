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
  /**
   * When the session is issued, in epoch milliseconds: its `createdAt`. A
   * sign-in passes the time it took before it read the account (#748), so a
   * disablement that commits after that read finds the session issued before
   * it. Absent, or later than the service's clock, it is the service's clock.
   */
  issuedAt?: number;
}

/** Names one session. Every lookup takes the realm (ADR-019 Decision 1). */
export interface SessionQuery {
  realmId: string;
  sid: string;
}

/**
 * The kinds of actor that end sessions: the actor types of QAuth's events
 * (`ACTOR_TYPES` in `@qauth-labs/shared-events`), so a listener that emits an
 * event passes the actor on as it is. An admin is a `user`.
 */
export const SESSION_ACTOR_TYPES = ['user', 'client', 'system', 'operator_cli'] as const;

export type SessionActorType = (typeof SESSION_ACTOR_TYPES)[number];

/**
 * Who or what ended a session, in the shape of an event's actor. It is not
 * stored: the listeners of {@link SessionService.onSessionsEnded} receive it.
 */
export interface SessionActor {
  type: SessionActorType;
  /**
   * A user id, a client's `client_id`, or the operating-system user for
   * `operator_cli`: required for those, at most 255 characters. Absent for
   * `system`.
   */
  id?: string;
}

/** A client a session served, from its `session_clients` row (#549). */
export interface SessionClientRecord {
  /** The client's row id (`oauth_clients.id`). */
  oauthClientId: string;
  /** The client's public `client_id`. */
  clientId: string;
  /** The client's display name. */
  name: string;
  /** When the session first authorized the client, in epoch milliseconds. */
  firstSeenAt: number;
}

/**
 * A session a revocation ended, with the clients it had served: whom
 * back-channel logout notifies. The registry rows are deleted with the
 * revocation, so this is the one complete list.
 */
export interface EndedSession {
  /** The row as it ended: `revokedAt` and `revokedReason` are set. */
  session: SessionRecord;
  /** Oldest first. */
  clients: readonly SessionClientRecord[];
}

/**
 * What a listener of {@link SessionService.onSessionsEnded} receives: sessions
 * of one realm, ended for one reason by one actor. Each ended session reaches
 * the listeners once, in one notice.
 */
export interface SessionsEndedNotice {
  realmId: string;
  reason: SessionRevokedReason;
  actor: SessionActor;
  /** Never empty. */
  sessions: readonly EndedSession[];
}

/** A listener of {@link SessionService.onSessionsEnded}. */
export type SessionsEndedListener = (notice: SessionsEndedNotice) => void | Promise<void>;

/**
 * Where a listed session stands: `live`, past the realm's idle limit
 * (`idle`), past its absolute end (`expired`), or ended by a revocation
 * (`revoked`). A session the purge job marked as idle or expired keeps that
 * state.
 */
export type SessionState = 'live' | 'idle' | 'expired' | 'revoked';

/** A session as a list shows it. */
export interface ListedSession {
  sid: string;
  realmId: string;
  userId: string;
  /** When the user authenticated (the ID token's `auth_time`), in epoch milliseconds. */
  authTime: number;
  amr: readonly string[];
  assuranceLevel: SessionAssuranceLevel | null;
  /** The client address of the sign-in. */
  ipAddress: string | null;
  /** The `User-Agent` of the sign-in. */
  userAgent: string | null;
  createdAt: number;
  /** The last stored use. */
  lastSeenAt: number;
  /** The absolute end, as {@link BrowserSession.expiresAt}. */
  expiresAt: number;
  /** The idle end, as {@link BrowserSession.idleExpiresAt}. */
  idleExpiresAt: number | null;
  state: SessionState;
  revokedAt: number | null;
  revokedReason: SessionRevokedReason | null;
  /**
   * The clients the session served, oldest first. Empty once it ended: the
   * revocation took them.
   */
  clients: readonly SessionClientRecord[];
}

/**
 * Which page of a list to read: the paging of the admin, account and
 * developer APIs, `limit` and an opaque `cursor`.
 */
export interface SessionPageRequest {
  /** 1 to {@link MAX_SESSION_PAGE_LIMIT}; {@link DEFAULT_SESSION_PAGE_LIMIT} by default. */
  limit?: number;
  /** The `nextCursor` of the previous page of the same list. */
  cursor?: string;
}

/** One page of a session list, newest first. */
export interface SessionPage {
  items: ListedSession[];
  /** The cursor of the next page; `null` on the last one. */
  nextCursor: string | null;
}

/** Input of {@link SessionService.listForUser}. */
export interface ListUserSessionsInput {
  realmId: string;
  userId: string;
  page?: SessionPageRequest;
}

/** Input of {@link SessionService.listForClient}. */
export interface ListClientSessionsInput {
  realmId: string;
  /** The client's row id (`oauth_clients.id`), as the API paths of this repository name a client. */
  oauthClientId: string;
  page?: SessionPageRequest;
}

/** Input of {@link SessionService.revoke}. */
export interface RevokeSessionInput extends SessionQuery {
  /**
   * The user whose session the caller means to end: a session of another
   * user is `not_found`, untouched, and nothing of it is returned. A `sid` is
   * no secret (an ID token carries it), so a caller acting for a user names
   * that user. Required when `actor.type` is `user` (an admin is a `user`
   * too, and names the session's owner); the service throws without it.
   */
  userId?: string;
  reason: SessionRevokedReason;
  actor: SessionActor;
}

/**
 * What {@link SessionService.revoke} did: ended the session, found it ended
 * already (by this reason or another; the first one stays), or found no such
 * session in the realm.
 */
export type RevokeSessionResult =
  | { outcome: 'ended'; session: SessionRecord; clients: readonly SessionClientRecord[] }
  | { outcome: 'already_ended'; session: SessionRecord }
  | { outcome: 'not_found' };

/** Input of {@link SessionService.revokeAllForUser}. */
export interface RevokeUserSessionsInput {
  realmId: string;
  userId: string;
  /** Keep this session: "sign out everywhere else". */
  exceptSid?: string;
  /**
   * End only the sessions created before this time, in epoch milliseconds: a
   * password reset ends the sessions older than the new password, which is
   * how #550 covers ADR-017's session epoch.
   *
   * It ends the sessions Postgres holds when the call runs. A sign-in that
   * checked the old password before the reset committed, and stores its
   * session only after this call, is not ended. A caller that must refuse
   * that one too also checks the reset time when the session is read, as
   * `not_valid_before` does for a disabled account (#748).
   */
  createdBefore?: number;
  reason: SessionRevokedReason;
  actor: SessionActor;
}

/** What {@link SessionService.revokeAllForUser} ended. */
export interface RevokedSessions {
  /** The sessions this call ended, in id order (oldest first). */
  sessions: readonly EndedSession[];
}

/** Input of {@link SessionService.revokeAllForRealm}. */
export interface RevokeRealmSessionsInput {
  realmId: string;
  /**
   * End only the sessions used at or after this time, in epoch milliseconds.
   * `last_seen_at` lags use by up to `SESSION_LAST_SEEN_INTERVAL`, so a
   * session stored as seen up to that long before this time is ended too.
   * Every session of the realm when absent.
   */
  activeSince?: number;
  reason: SessionRevokedReason;
  actor: SessionActor;
  /**
   * Sessions per transaction; {@link DEFAULT_SESSION_REVOCATION_BATCH_SIZE}
   * by default, at most {@link MAX_SESSION_BATCH_SIZE}.
   */
  batchSize?: number;
}

/** What {@link SessionService.revokeAllForRealm} did. */
export interface RealmSessionsRevocation {
  /** How many sessions it ended. */
  ended: number;
  /** In how many transactions. */
  batches: number;
}

/** Input of {@link SessionService.endLapsed}. */
export interface EndLapsedSessionsInput {
  /** Sessions per transaction; {@link DEFAULT_SESSION_REVOCATION_BATCH_SIZE} by default. */
  batchSize?: number;
  /** Checked between batches: the job runner's signal. */
  signal?: AbortSignal;
}

/** Input of {@link SessionService.purge}. */
export interface PurgeSessionsInput {
  /**
   * Delete the rows revoked, or past their stored `expires_at`, before this
   * time, in epoch milliseconds.
   */
  endedBefore: number;
  /** Rows per statement; {@link DEFAULT_SESSION_PURGE_BATCH_SIZE} by default. */
  batchSize?: number;
  /** Checked between batches: the job runner's signal. */
  signal?: AbortSignal;
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
   * End one session: Postgres first, then the cache entry is replaced by a
   * short tombstone, then the listeners of {@link onSessionsEnded} hear of
   * it. Safe to call twice: the second call changes nothing and answers
   * `already_ended`. Throws when Postgres cannot store the end.
   *
   * Only the session ends. Its refresh-token families and the access tokens
   * already issued under it stay valid, Authority Trees and consents are not
   * touched (ADR-014: trees survive sign-out), and no CAEP signal is sent.
   * Every caller pairs it with the token revocation and the signal its case
   * needs; a session revocation alone does not sign anyone out of a client.
   */
  revoke(input: RevokeSessionInput): Promise<RevokeSessionResult>;
  /**
   * End a user's sessions in the realm, but `exceptSid` and those created at
   * or after `createdBefore`, in one transaction, as {@link revoke} ends one.
   * Returns the sessions this call ended; a second call ends nothing more.
   * Like {@link revoke}, it revokes no token and sends no signal: the caller
   * pairs it with both.
   */
  revokeAllForUser(input: RevokeUserSessionsInput): Promise<RevokedSessions>;
  /**
   * End the realm's sessions in batches, each its own short transaction, in
   * id order: key retirement and bulk revocation. A session created more
   * than `SESSION_CLOCK_SKEW_ALLOWANCE_MS` after the call began is left alone;
   * one created within it is ended, so a node whose clock runs ahead cannot
   * stamp a session made before the call past the cut. Each batch's sessions
   * reach the listeners as the batch commits; the call returns only counts,
   * so a realm of any size fits in memory. Safe to repeat. Like
   * {@link revoke}, it revokes no token and sends no signal: the caller pairs
   * it with both.
   */
  revokeAllForRealm(input: RevokeRealmSessionsInput): Promise<RealmSessionsRevocation>;
  /**
   * Mark every session, of every realm, past its absolute end or its realm's
   * idle limit as `expired` or `idle`, as {@link get} already treats it, so
   * its registry rows go and the listeners hear of it, with the `system`
   * actor. `revokedAt` is the time of the mark. The `session-expiry` job runs
   * it every five minutes.
   */
  endLapsed(input?: EndLapsedSessionsInput): Promise<{ ended: number }>;
  /**
   * Delete the rows of sessions, of every realm, that ended before
   * `endedBefore`. A live session is never deleted, nor one past its end that
   * {@link endLapsed} has not marked yet: its end reaches the listeners
   * (back-channel logout) first, however long the expiry job was down. The
   * session purge job runs it with `SESSION_RETENTION_DAYS`.
   */
  purge(input: PurgeSessionsInput): Promise<{ deleted: number }>;
  /**
   * One page of a user's sessions in the realm, newest first, whatever their
   * state, until {@link purge} deletes them; never another realm's. Throws
   * {@link InvalidSessionCursorError} for a cursor of another list and a
   * `RangeError` for a limit out of range.
   */
  listForUser(input: ListUserSessionsInput): Promise<SessionPage>;
  /**
   * One page of the realm's sessions that served a client, newest first, for
   * an admin only: each with its user id, its IP address, its user agent and
   * ALL the other clients the session served. Never expose it as is to the
   * client's own developer, who must not learn who else its users sign in
   * to, or from where. A revoked session no longer holds its clients, so
   * only sessions not yet revoked are listed. Throws as {@link listForUser}.
   */
  listForClient(input: ListClientSessionsInput): Promise<SessionPage>;
  /**
   * Call `listener` after every revocation this process makes that ends
   * sessions, once per ended session: after Postgres committed the end and
   * the cache tombstones were written. Listeners run in the order they
   * registered, one at a time, and the revocation waits for them: they run
   * inside the request or job that revoked, so a listener only enqueues work
   * (a back-channel logout, a signal) and never does it inline. A listener
   * that throws is logged and the others still run; the revocation stands.
   *
   * At most once, and in this process only: a process that stops between
   * the commit and a listener loses that notice, and nothing repeats it (a
   * second revocation of the session ends nothing). Work that must not be
   * lost, such as the session events of the transactional outbox (ADR-019
   * Decision 8) or the queued back-channel logout of #624, belongs in the
   * revocation's transaction, not only here.
   *
   * @returns a function that removes the listener
   */
  onSessionsEnded(listener: SessionsEndedListener): () => void;
}
