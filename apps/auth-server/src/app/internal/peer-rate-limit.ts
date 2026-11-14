/**
 * A RATE PER PEER (issue #497): a token bucket per peer of the internal
 * listener, kept in this process's memory.
 *
 * A peer is a client certificate (`requestPeerIdentity`), so the processes
 * that share one certificate share its bucket, and each process of the signer
 * keeps its own. A peer may call `burst` times at once, and `ratePerSecond`
 * times a second after that. Nothing leaves the process: the limit holds a
 * peer that runs away, or one an attacker took over, to a rate the signer
 * can serve beside the others, and needs no Redis round trip on the path of
 * every signature.
 */

/** Options of {@link createPeerRateLimit}. */
export interface PeerRateLimitOptions {
  /** The calls a second a peer may make once its burst is spent. */
  readonly ratePerSecond: number;
  /** The calls a peer may make at once. */
  readonly burst: number;
  /**
   * The most peers whose buckets are kept; past it, the peer seen longest
   * ago is forgotten, and starts again with a full bucket. Peers are
   * certificates the CA file issued, so they are few.
   */
  readonly maxPeers?: number;
  /** The clock, in epoch ms. */
  readonly now?: () => number;
}

/** What {@link PeerRateLimit.take} decided. */
export type PeerRateVerdict =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      /** How long until the peer may call again, in ms. */
      readonly retryAfterMs: number;
      /**
       * The refusals of this peer not logged since the last one that was,
       * or `undefined` to log none for this one: at most one line a minute
       * per peer.
       */
      readonly logSuppressed: number | undefined;
    };

/** The buckets of every peer. */
export interface PeerRateLimit {
  /**
   * Spend `cost` tokens of `peer`'s bucket, one by default, when it holds
   * them. A cost above the burst is charged as the burst, so a call is never
   * refused for good.
   */
  take(peer: string, cost?: number): PeerRateVerdict;
}

/** The most peers kept when nothing else is asked. */
const DEFAULT_MAX_PEERS = 1_024;

/** The shortest time between two log lines about one peer's refusals. */
const REFUSAL_LOG_INTERVAL_MS = 60_000;

interface Bucket {
  tokens: number;
  updatedAt: number;
  loggedAt: number;
  suppressed: number;
}

/** Make the buckets. */
export function createPeerRateLimit(options: PeerRateLimitOptions): PeerRateLimit {
  const { ratePerSecond, burst } = options;
  if (!(ratePerSecond > 0) || !Number.isSafeInteger(burst) || burst < 1) {
    throw new TypeError('createPeerRateLimit: the rate and the burst must be positive');
  }
  const maxPeers = options.maxPeers ?? DEFAULT_MAX_PEERS;
  const now = options.now ?? (() => Date.now());
  // In order of last use: the first is the peer seen longest ago.
  const buckets = new Map<string, Bucket>();

  return {
    take(peer: string, costInput = 1): PeerRateVerdict {
      const cost = Math.min(burst, Math.max(1, Math.ceil(costInput)));
      const at = now();
      let bucket = buckets.get(peer);
      if (bucket === undefined) {
        bucket = {
          tokens: burst,
          updatedAt: at,
          loggedAt: Number.NEGATIVE_INFINITY,
          suppressed: 0,
        };
        if (buckets.size >= maxPeers) {
          const [oldest] = buckets.keys();
          if (oldest !== undefined) buckets.delete(oldest);
        }
      } else {
        buckets.delete(peer);
        const elapsed = Math.max(0, at - bucket.updatedAt);
        bucket.tokens = Math.min(burst, bucket.tokens + (elapsed * ratePerSecond) / 1000);
        bucket.updatedAt = at;
      }
      buckets.set(peer, bucket);
      if (bucket.tokens >= cost) {
        bucket.tokens -= cost;
        return { allowed: true };
      }
      const retryAfterMs = Math.ceil(((cost - bucket.tokens) * 1000) / ratePerSecond);
      if (at - bucket.loggedAt < REFUSAL_LOG_INTERVAL_MS) {
        bucket.suppressed += 1;
        return { allowed: false, retryAfterMs, logSuppressed: undefined };
      }
      const logSuppressed = bucket.suppressed;
      bucket.loggedAt = at;
      bucket.suppressed = 0;
      return { allowed: false, retryAfterMs, logSuppressed };
    },
  };
}

/** The calls in flight of every peer. */
export interface PeerConcurrencyLimit {
  /**
   * Count one more call of `peer` in flight, or refuse it (`false`) when the
   * peer has `max` already. Each `true` is paired with one {@link leave}.
   */
  enter(peer: string): boolean;
  /** One call of `peer` ended. */
  leave(peer: string): void;
}

/**
 * A cap on the calls each peer has in flight at once, so that a peer that
 * holds its calls open, such as by trickling their bodies, holds at most
 * `max` of them, and the memory their bodies take, whatever its rate.
 */
export function createPeerConcurrencyLimit(max: number): PeerConcurrencyLimit {
  if (!Number.isSafeInteger(max) || max < 1) {
    throw new TypeError('createPeerConcurrencyLimit: the cap must be a positive integer');
  }
  const inFlight = new Map<string, number>();
  return {
    enter(peer: string): boolean {
      const count = inFlight.get(peer) ?? 0;
      if (count >= max) return false;
      inFlight.set(peer, count + 1);
      return true;
    },
    leave(peer: string): void {
      const count = inFlight.get(peer) ?? 0;
      if (count <= 1) inFlight.delete(peer);
      else inFlight.set(peer, count - 1);
    },
  };
}

/** Options of {@link createLogSampler}. */
export interface LogSamplerOptions {
  /** The shortest time between two lines of one key, in ms; a minute by default. */
  readonly intervalMs?: number;
  /** The most keys kept; past it, the key seen longest ago is forgotten. */
  readonly maxKeys?: number;
  /** The clock, in epoch ms. */
  readonly now?: () => number;
}

/** One log line per key per interval. */
export interface LogSampler {
  /**
   * The lines of `key` not written since the last one that was, when this
   * one is to be written; `undefined` to write none for it.
   */
  take(key: string): number | undefined;
}

/**
 * Lets one line per key through per interval, and counts the others, so a
 * peer that repeats a refused call writes one line a minute with how many it
 * stands for, not one per call.
 */
export function createLogSampler(options: LogSamplerOptions = {}): LogSampler {
  const intervalMs = options.intervalMs ?? REFUSAL_LOG_INTERVAL_MS;
  const maxKeys = options.maxKeys ?? DEFAULT_MAX_PEERS;
  const now = options.now ?? (() => Date.now());
  // In order of last use: the first is the key seen longest ago.
  const keys = new Map<string, { loggedAt: number; suppressed: number }>();
  return {
    take(key: string): number | undefined {
      const at = now();
      let entry = keys.get(key);
      if (entry === undefined) {
        entry = { loggedAt: Number.NEGATIVE_INFINITY, suppressed: 0 };
        if (keys.size >= maxKeys) {
          const [oldest] = keys.keys();
          if (oldest !== undefined) keys.delete(oldest);
        }
      } else {
        keys.delete(key);
      }
      keys.set(key, entry);
      if (at - entry.loggedAt < intervalMs) {
        entry.suppressed += 1;
        return undefined;
      }
      const suppressed = entry.suppressed;
      entry.loggedAt = at;
      entry.suppressed = 0;
      return suppressed;
    },
  };
}
