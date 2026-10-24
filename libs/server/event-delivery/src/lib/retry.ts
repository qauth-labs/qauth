/**
 * The retry schedule of the delivery role (issue #460): exponential backoff
 * with jitter.
 *
 * After attempt `n` fails, attempt `n + 1` waits `initialDelayMs ×
 * multiplier^(n - 1)`, at most `maxDelayMs`, less a random share of up to
 * `jitter` of it. The jitter spreads the retries of many deliveries that
 * failed together, such as every delivery to a destination that was down,
 * so they do not all arrive at once when it comes back. While
 * `multiplier × (1 - jitter)` is above 1, which the defaults keep, each delay
 * is longer than the one before until the cap.
 */

/** The shape of the backoff. */
export interface RetrySchedule {
  /** The wait after the first failed attempt, in milliseconds. */
  readonly initialDelayMs: number;
  /** The longest wait, in milliseconds. */
  readonly maxDelayMs: number;
  /** Each wait is this many times the one before, until `maxDelayMs`. At least 1. */
  readonly multiplier: number;
  /** The share of each wait taken off at random, from 0 up to but not including 1. */
  readonly jitter: number;
}

/**
 * The default schedule: 30 seconds, doubling, at most 6 hours, less up to
 * 20%. With the default 12 attempts, the last one comes 11.6 to 14.5 hours
 * after the first.
 */
export const DEFAULT_RETRY_SCHEDULE: RetrySchedule = Object.freeze({
  initialDelayMs: 30_000,
  maxDelayMs: 6 * 60 * 60_000,
  multiplier: 2,
  jitter: 0.2,
});

/** The longest wait a schedule may set: 7 days. */
export const MAX_RETRY_DELAY_MS = 7 * 24 * 60 * 60_000;

/**
 * Check a schedule.
 *
 * @throws {TypeError} when a delay is not a whole number of milliseconds from
 *   1 to {@link MAX_RETRY_DELAY_MS}, the cap is below the first delay, the
 *   multiplier is below 1, or the jitter is outside [0, 1)
 */
export function checkRetrySchedule(schedule: RetrySchedule): RetrySchedule {
  const { initialDelayMs, maxDelayMs, multiplier, jitter } = schedule;
  for (const [name, value] of [
    ['initialDelayMs', initialDelayMs],
    ['maxDelayMs', maxDelayMs],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1 || value > MAX_RETRY_DELAY_MS) {
      throw new TypeError(
        `retry schedule: ${name} must be a whole number of milliseconds from 1 to ${MAX_RETRY_DELAY_MS}`
      );
    }
  }
  if (maxDelayMs < initialDelayMs) {
    throw new TypeError('retry schedule: maxDelayMs must be at least initialDelayMs');
  }
  if (!Number.isFinite(multiplier) || multiplier < 1) {
    throw new TypeError('retry schedule: multiplier must be at least 1');
  }
  if (!Number.isFinite(jitter) || jitter < 0 || jitter >= 1) {
    throw new TypeError('retry schedule: jitter must be from 0 up to but not including 1');
  }
  return Object.freeze({ initialDelayMs, maxDelayMs, multiplier, jitter });
}

/**
 * The wait before the next attempt, after attempt `failedAttempt` failed.
 *
 * @param failedAttempt - The attempt that failed, 1 for the first.
 * @param random - A number in [0, 1); `Math.random` by default.
 */
export function retryDelayMs(
  failedAttempt: number,
  schedule: RetrySchedule,
  random: () => number = Math.random
): number {
  if (!Number.isSafeInteger(failedAttempt) || failedAttempt < 1) {
    throw new TypeError('retryDelayMs: the failed attempt must be a whole number from 1');
  }
  const base = Math.min(
    schedule.maxDelayMs,
    schedule.initialDelayMs * schedule.multiplier ** (failedAttempt - 1)
  );
  const share = Math.min(Math.max(random(), 0), 1);
  return Math.max(1, Math.round(base * (1 - schedule.jitter * share)));
}
