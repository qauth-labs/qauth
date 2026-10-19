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
 * Tracks login attempts per identifier (email and/or IP) in Redis and,
 * after `FAILED_LOGIN_MAX_ATTEMPTS` failures inside `FAILED_LOGIN_WINDOW`,
 * applies a temporary lockout for `FAILED_LOGIN_LOCKOUT_DURATION` seconds.
 *
 * An attempt is counted BEFORE its password is verified, and the atomic
 * `INCR` of that count is the gate. Counting a failure only once Argon2id had
 * returned was check-then-act: a verification takes ~100 ms and queues, so
 * every guess sent before the threshold failure was recorded got verified,
 * however many there were. Now the attempt that reaches the threshold arms the
 * lockout on its way in (`SET NX`, so exactly one attempt in flight can), and
 * any attempt behind it is refused without being counted.
 *
 * Decay/reset:
 *  - the attempt counter has a TTL equal to the window, so it naturally decays
 *    when failures stop;
 *  - a successful login clears the counter and any lockout of the email whose
 *    password it proved. On the source address it gives back only the count
 *    it took itself: that counter holds the failures of every account guessed
 *    at from the address, and registration is open, so anyone could otherwise
 *    reset it by logging in to an account of their own. Those failures stay
 *    until the window expires, which users behind one shared address (NAT,
 *    an IPv6 /64) share;
 *  - the lockout marker expires on its own after the lockout duration.
 *
 * All operations are best-effort: if Redis is unavailable the helper fails open
 * (login proceeds, logged elsewhere) rather than locking every user out.
 */

/** Result of registering a login attempt. */
export interface LockoutStatus {
  /** Whether the attempt is refused: an identifier is locked out. */
  locked: boolean;
  /** Seconds remaining on the lockout, when locked. */
  retryAfterSeconds?: number;
}

/** A registered login attempt, and what it took that a success gives back. */
export interface LoginAttempt extends LockoutStatus {
  /** Identifiers the attempt was counted against. */
  counted?: readonly string[];
  /** Identifiers whose lockout the attempt armed on its way in. */
  armed?: readonly string[];
}

/**
 * Count a login attempt against each identifier, unless one of them is
 * locked out. Call it BEFORE the credential is verified, and verify only when
 * it returns `locked: false`. A failed attempt then needs no further
 * bookkeeping: it stays counted. A successful one is settled with
 * `recordSuccessfulLogin`.
 *
 * A refused attempt is not counted: an identifier already locked out refuses
 * it before anything is incremented, and an attempt that loses the race to arm
 * a lockout gives back what it had taken.
 *
 * @param redis - The Redis client (`fastify.redis`).
 * @param identifiers - Identifiers to check and count (e.g. email hash and/or
 *                      IP).
 * @returns The lockout status; `locked: false` when tracking is disabled or
 *          Redis is unreachable.
 */
export async function registerLoginAttempt(
  redis: RedisClient,
  identifiers: string[]
): Promise<LoginAttempt> {
  if (!env.FAILED_LOGIN_TRACKING_ENABLED) {
    return { locked: false };
  }

  const counted: string[] = [];
  const armed: string[] = [];
  try {
    for (const identifier of identifiers) {
      const ttl = await redis.ttl(REDIS_KEYS.FAILED_LOGIN_LOCKOUT(identifier));
      if (ttl > 0) {
        return { locked: true, retryAfterSeconds: ttl };
      }
    }

    for (const identifier of identifiers) {
      const attemptsKey = REDIS_KEYS.FAILED_LOGIN_ATTEMPTS(identifier);
      const attempts = await redis.incr(attemptsKey);
      counted.push(identifier);

      // Set the window TTL on the first attempt.
      if (attempts === 1) {
        await redis.expire(attemptsKey, env.FAILED_LOGIN_WINDOW);
      }

      // The attempt that reaches the threshold is the last one let through,
      // and arms the lockout on its way in. NX lets exactly one attempt arm
      // it; any other attempt at or past the threshold finds it armed and is
      // refused, however far ahead of it the lockout check let it get.
      if (attempts >= env.FAILED_LOGIN_MAX_ATTEMPTS) {
        const result = await redis.set(
          REDIS_KEYS.FAILED_LOGIN_LOCKOUT(identifier),
          '1',
          'EX',
          env.FAILED_LOGIN_LOCKOUT_DURATION,
          'NX'
        );
        if (result !== 'OK') {
          await withdrawAttempt(redis, counted, armed);
          return { locked: true, retryAfterSeconds: env.FAILED_LOGIN_LOCKOUT_DURATION };
        }
        armed.push(identifier);
      }
    }
    return { locked: false, counted, armed };
  } catch {
    // Fail open: never block logins because the cache is down.
    return { locked: false, counted, armed };
  }
}

/**
 * Settle a successful login. The identifiers it proved (the email whose
 * password was just verified) are cleared, counter and lockout. On every other
 * identifier the attempt was counted against (the source address), only what
 * this attempt took is given back: its own count, and the lockout if it armed
 * it on its way in. The failures counted there by other attempts stay until
 * the window expires, so logging in to an account of one's own does not wipe
 * the failures of a password spray from the same address.
 *
 * @param redis - The Redis client (`fastify.redis`).
 * @param attempt - What `registerLoginAttempt` returned for this login.
 * @param proven - Identifiers the login proved (the `email:` identifier).
 */
export async function recordSuccessfulLogin(
  redis: RedisClient,
  attempt: LoginAttempt,
  proven: string[]
): Promise<void> {
  if (!env.FAILED_LOGIN_TRACKING_ENABLED) {
    return;
  }

  await resetFailedAttempts(redis, proven);
  await withdrawAttempt(
    redis,
    (attempt.counted ?? []).filter((identifier) => !proven.includes(identifier)),
    (attempt.armed ?? []).filter((identifier) => !proven.includes(identifier))
  );
}

/**
 * Give back what an attempt took: one count on each identifier it was counted
 * against, and any lockout it armed. Best-effort.
 */
async function withdrawAttempt(
  redis: RedisClient,
  counted: readonly string[],
  armed: readonly string[]
): Promise<void> {
  try {
    if (armed.length > 0) {
      await redis.del(...armed.map((identifier) => REDIS_KEYS.FAILED_LOGIN_LOCKOUT(identifier)));
    }
    for (const identifier of counted) {
      const attemptsKey = REDIS_KEYS.FAILED_LOGIN_ATTEMPTS(identifier);
      // Below zero, the counter had expired or been cleared meanwhile, and
      // DECR recreated it without a TTL: drop it rather than keep it forever.
      if ((await redis.decr(attemptsKey)) < 0) {
        await redis.del(attemptsKey);
      }
    }
  } catch {
    // Best-effort: the attempt is refused either way.
  }
}

/**
 * Clear failed-login state for the given identifiers, resetting both the
 * attempt counter and any active lockout.
 *
 * Pass only identifiers a successful login proved, i.e. the email whose
 * password was just verified; `recordSuccessfulLogin` does so. The source
 * address is never one of them (see above).
 *
 * @param redis - The Redis client (`fastify.redis`).
 * @param identifiers - Identifiers to reset (e.g. email hash).
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
