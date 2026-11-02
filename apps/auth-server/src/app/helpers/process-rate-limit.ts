/**
 * An in-process, fixed-window rate limit (issue #500), for the routes that
 * must answer while Redis does not: `/health` and `/ready`. The app's other
 * limits share Redis (`plugins/rate-limit.ts`), so with Redis down they fail,
 * and with Redis unreachable they wait for it: a liveness check behind them
 * would report the process dead for its dependency. These counters live in
 * the process, so each process counts its own callers, which is what a
 * health check of that process needs.
 *
 * The number of buckets is bounded: past `maxKeys`, the expired ones go
 * first, then the oldest. A caller that rotates its address can push another
 * caller's bucket out, which only lets that caller start counting again.
 */

/** The bounds of one limiter. */
export interface ProcessRateLimitOptions {
  /** Requests a key may make per window. */
  readonly max: number;
  /** The window, in milliseconds. */
  readonly windowMs: number;
  /** The most keys counted at once; 10 000 when unset. */
  readonly maxKeys?: number;
  /** The clock, for a test. */
  readonly now?: () => number;
}

/** What one request's count says. */
export interface ProcessRateLimitDecision {
  /** Whether the request is within the limit. */
  readonly allowed: boolean;
  /** The limit per window. */
  readonly limit: number;
  /** What the key may still make in this window. */
  readonly remaining: number;
  /** Seconds until the window ends, at least 1. */
  readonly resetSeconds: number;
}

/** Count one request of a key; see {@link createProcessRateLimit}. */
export type ProcessRateLimit = (key: string) => ProcessRateLimitDecision;

/** The default bound on keys counted at once. */
export const DEFAULT_PROCESS_RATE_LIMIT_KEYS = 10_000;

/** Build a limiter that counts each key's requests per window, in memory. */
export function createProcessRateLimit(options: ProcessRateLimitOptions): ProcessRateLimit {
  const now = options.now ?? Date.now;
  const maxKeys = options.maxKeys ?? DEFAULT_PROCESS_RATE_LIMIT_KEYS;
  const buckets = new Map<string, { count: number; resetAt: number }>();

  function makeRoom(at: number): void {
    if (buckets.size < maxKeys) return;
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= at) buckets.delete(key);
    }
    // A Map iterates in insertion order: the first keys are the oldest.
    for (const key of buckets.keys()) {
      if (buckets.size < maxKeys) break;
      buckets.delete(key);
    }
  }

  return (key: string): ProcessRateLimitDecision => {
    const at = now();
    let bucket = buckets.get(key);
    if (bucket === undefined || bucket.resetAt <= at) {
      if (bucket !== undefined) buckets.delete(key);
      makeRoom(at);
      bucket = { count: 0, resetAt: at + options.windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    return {
      allowed: bucket.count <= options.max,
      limit: options.max,
      remaining: Math.max(0, options.max - bucket.count),
      resetSeconds: Math.max(1, Math.ceil((bucket.resetAt - at) / 1000)),
    };
  };
}
