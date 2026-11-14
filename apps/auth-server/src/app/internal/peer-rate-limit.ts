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
  /** Spend one call of `peer`'s bucket, when it holds one. */
  take(peer: string): PeerRateVerdict;
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
    take(peer: string): PeerRateVerdict {
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
      if (bucket.tokens >= 1) {
        bucket.tokens -= 1;
        return { allowed: true };
      }
      const retryAfterMs = Math.ceil(((1 - bucket.tokens) * 1000) / ratePerSecond);
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
