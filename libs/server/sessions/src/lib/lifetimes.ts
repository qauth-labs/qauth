import type { CachedSessionRecord, RealmSessionLifetimes } from './types';

/** Where a session stands at a given moment. */
export type SessionVerdict = 'live' | 'ended' | 'idle';

/** When a session ends, in epoch milliseconds. */
export interface SessionEnds {
  /**
   * The absolute end: the stored `expires_at`, or earlier when the realm's
   * maximum lifespan (or `SESSION_COOKIE_TTL` without one) now ends it sooner.
   */
  absolute: number;
  /** The idle end, from the stored `last_seen_at`; `null` without an idle limit. */
  idle: number | null;
}

/**
 * The ends of a session under its realm's lifetimes.
 *
 * The maximum lifespan is applied again at every read, counted from the
 * creation, so a realm that shortens it shortens its live sessions too. A
 * longer one never extends a session past the `expires_at` it was given.
 *
 * @param defaultMaxLifespanSeconds - `SESSION_COOKIE_TTL`, for a realm with no
 * `sso_max_lifespan`
 */
export function sessionEnds(
  record: Pick<CachedSessionRecord, 'createdAt' | 'expiresAt' | 'lastSeenAt'>,
  lifetimes: RealmSessionLifetimes,
  defaultMaxLifespanSeconds: number
): SessionEnds {
  const maxLifespanMs = (lifetimes.maxLifespanSeconds ?? defaultMaxLifespanSeconds) * 1000;
  return {
    absolute: Math.min(record.expiresAt, record.createdAt + maxLifespanMs),
    idle:
      lifetimes.idleTimeoutSeconds === null
        ? null
        : record.lastSeenAt + lifetimes.idleTimeoutSeconds * 1000,
  };
}

/** The earlier of a session's two ends. */
export function sessionEnd(ends: SessionEnds): number {
  return ends.idle === null ? ends.absolute : Math.min(ends.absolute, ends.idle);
}

/**
 * Whether a session is live at `now`: `ended` past its absolute end, `idle`
 * past its idle end, else `live`. Each end is the first moment the session is
 * no longer live.
 */
export function sessionVerdict(ends: SessionEnds, now: number): SessionVerdict {
  if (now >= ends.absolute) return 'ended';
  if (ends.idle !== null && now >= ends.idle) return 'idle';
  return 'live';
}

/**
 * How old the stored `last_seen_at` must be before it is written again, in
 * milliseconds: the configured interval, or half the realm's idle limit when
 * that is shorter. Idle time is judged from the stored value, so an interval as
 * long as the idle limit would end a session that is in use; half of it keeps
 * a session used at least that often alive.
 */
export function lastSeenIntervalMs(
  lifetimes: RealmSessionLifetimes,
  configuredIntervalSeconds: number
): number {
  const configured = configuredIntervalSeconds * 1000;
  if (lifetimes.idleTimeoutSeconds === null) return configured;
  return Math.min(configured, (lifetimes.idleTimeoutSeconds * 1000) / 2);
}
