import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { REDIS_KEYS } from '../constants';

/**
 * The Redis client type, derived from the `fastify.redis` decorator that the
 * cache plugin (`@qauth-labs/fastify-plugin-cache`) augments onto the instance.
 * Sourcing it this way avoids a direct dependency on the infra-cache lib.
 */
type RedisClient = FastifyInstance['redis'];

/**
 * Failed-login throttling / lockout (QAuth §3.1.12, #115).
 *
 * Tracks failed login counts per identifier (email and/or IP) in Redis and,
 * after `FAILED_LOGIN_MAX_ATTEMPTS` failures inside `FAILED_LOGIN_WINDOW`,
 * applies a temporary lockout for `FAILED_LOGIN_LOCKOUT_DURATION` seconds.
 *
 * Decay/reset:
 *  - the attempt counter has a TTL equal to the window, so it naturally decays
 *    when failures stop;
 *  - a successful login clears both the counter and any lockout;
 *  - the lockout marker expires on its own after the lockout duration.
 *
 * All operations are best-effort: if Redis is unavailable the helper fails open
 * (login proceeds, logged elsewhere) rather than locking every user out.
 */

/** Result of checking whether an identifier is currently locked out. */
export interface LockoutStatus {
  /** Whether the identifier is currently locked out. */
  locked: boolean;
  /** Seconds remaining on the lockout, when locked. */
  retryAfterSeconds?: number;
}

/**
 * Check whether any of the given identifiers is currently locked out.
 *
 * @param redis - The Redis client (`fastify.redis`).
 * @param identifiers - Identifiers to check (e.g. email hash and/or IP).
 * @returns The lockout status; `locked: false` when tracking is disabled or
 *          Redis is unreachable.
 */
export async function checkLockout(
  redis: RedisClient,
  identifiers: string[]
): Promise<LockoutStatus> {
  if (!env.FAILED_LOGIN_TRACKING_ENABLED) {
    return { locked: false };
  }

  try {
    for (const identifier of identifiers) {
      const ttl = await redis.ttl(REDIS_KEYS.FAILED_LOGIN_LOCKOUT(identifier));
      if (ttl > 0) {
        return { locked: true, retryAfterSeconds: ttl };
      }
    }
    return { locked: false };
  } catch {
    // Fail open: never block logins because the cache is down.
    return { locked: false };
  }
}

/** Outcome of recording a failed attempt. */
export interface RecordFailureResult {
  /** Whether this failure tripped a lockout for at least one identifier. */
  lockedOut: boolean;
}

/**
 * Record a failed login attempt for each identifier, incrementing its
 * sliding-window counter and applying a lockout once the threshold is reached.
 *
 * @param redis - The Redis client (`fastify.redis`).
 * @param identifiers - Identifiers to penalise (e.g. email hash and/or IP).
 * @returns Whether a lockout was triggered by this failure.
 */
export async function recordFailedAttempt(
  redis: RedisClient,
  identifiers: string[]
): Promise<RecordFailureResult> {
  if (!env.FAILED_LOGIN_TRACKING_ENABLED) {
    return { lockedOut: false };
  }

  let lockedOut = false;

  try {
    for (const identifier of identifiers) {
      const attemptsKey = REDIS_KEYS.FAILED_LOGIN_ATTEMPTS(identifier);
      const attempts = await redis.incr(attemptsKey);

      // Set the window TTL on the first failure (and re-assert if it was lost).
      if (attempts === 1) {
        await redis.expire(attemptsKey, env.FAILED_LOGIN_WINDOW);
      }

      if (attempts >= env.FAILED_LOGIN_MAX_ATTEMPTS) {
        await redis.set(
          REDIS_KEYS.FAILED_LOGIN_LOCKOUT(identifier),
          '1',
          'EX',
          env.FAILED_LOGIN_LOCKOUT_DURATION
        );
        lockedOut = true;
      }
    }
  } catch {
    // Best-effort: a cache failure must not break the login flow.
    return { lockedOut: false };
  }

  return { lockedOut };
}

/**
 * Clear failed-login state for the given identifiers after a successful login,
 * resetting both the attempt counter and any active lockout.
 *
 * @param redis - The Redis client (`fastify.redis`).
 * @param identifiers - Identifiers to reset (e.g. email hash and/or IP).
 */
export async function resetFailedAttempts(
  redis: RedisClient,
  identifiers: string[]
): Promise<void> {
  if (!env.FAILED_LOGIN_TRACKING_ENABLED) {
    return;
  }

  try {
    const keys = identifiers.flatMap((identifier) => [
      REDIS_KEYS.FAILED_LOGIN_ATTEMPTS(identifier),
      REDIS_KEYS.FAILED_LOGIN_LOCKOUT(identifier),
    ]);
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  } catch {
    // Best-effort cleanup.
  }
}
