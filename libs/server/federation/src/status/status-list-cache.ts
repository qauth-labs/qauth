import type { VerifiedStatusList } from './status-list-token';

/**
 * Caching verified status lists (draft-14 §6, issue #297).
 *
 * ## Why caching is a correctness requirement, not an optimisation
 *
 * A status list is consulted on EVERY wallet login. Without a cache each login
 * carries a blocking outbound HTTPS round-trip to a third party, which makes
 * QAuth's login latency and availability a function of someone else's uptime —
 * and turns the status endpoint into a way to observe QAuth's login traffic in
 * real time. #297 makes "a wallet login does not perform an uncached fetch
 * every time" an acceptance criterion for exactly that reason.
 *
 * ## Why the cache is a seam
 *
 * The default is in-memory and per-process. That is the right default for a
 * modular monolith and the wrong one for a horizontally-scaled deployment,
 * where a shared cache (`@qauth-labs/infra-cache`) would cut the fan-out by the
 * replica count. `server-federation` is a `scope:server` library and may not
 * depend on `scope:infra`, so the interface lives here and the Redis-backed
 * implementation can be supplied by a Fastify plugin, which may depend on both.
 *
 * ## What is cached, and what is not
 *
 * The VERIFIED status list — after signature, chain, `typ`, `sub` and `iss`
 * binding have all passed. Caching the raw token instead would mean either
 * re-verifying on every hit (most of the cost, kept) or trusting an unverified
 * blob out of the cache (the cost saved by giving up the guarantee). The
 * compressed `lst` is kept as-is and inflated per lookup: a decompressed list
 * can be 16 MiB, and holding that per issuer per replica trades a bounded CPU
 * cost for an unbounded memory one.
 *
 * The TTL is the MINIMUM of the issuer's `ttl`, the token's `exp`, and the
 * operator's ceiling. draft-14 §6 requires `exp`/`ttl` to take priority over
 * HTTP caching headers, which is why the HTTP layer's headers are not consulted
 * at all — there is nothing they could be trusted to say that the signed claims
 * do not say better.
 */

/** A cached, already-verified status list plus the instant it stops being usable. */
export interface CachedStatusList {
  readonly statusList: VerifiedStatusList;
  /** Epoch milliseconds after which this entry must not be served. */
  readonly expiresAtMs: number;
}

/**
 * The cache seam.
 *
 * Synchronous on purpose: an async cache would put an `await` in front of every
 * status lookup even for the in-memory default, and a shared-cache
 * implementation that needs I/O is better written as a read-through wrapper
 * than as an interface everybody pays for.
 */
export interface StatusListCache {
  /**
   * @param uri - the credential's `status_list.uri`, verbatim.
   * @returns the entry, or `undefined` when absent or expired.
   */
  get(uri: string): CachedStatusList | undefined;
  /**
   * @param uri - the credential's `status_list.uri`, verbatim.
   * @param entry - the verified list and its expiry.
   */
  set(uri: string, entry: CachedStatusList): void;
}

/** Options for {@link createInMemoryStatusListCache}. */
export interface InMemoryStatusListCacheOptions {
  /**
   * Hard cap on distinct URIs held.
   *
   * REQUIRED to be bounded, because the key is attacker-influenced: every
   * credential names its own status list URI, so an unbounded map is a memory
   * exhaustion primitive reachable by anyone who can present credentials. Least
   * recently used is evicted.
   */
  readonly maxEntries?: number;
  /** Epoch-millisecond clock; injectable so expiry is testable without waiting. */
  readonly now?: () => number;
}

/** Default cap on cached status lists. */
const DEFAULT_MAX_ENTRIES = 256;

/**
 * Build the default in-process status list cache (#297).
 *
 * A `Map` with insertion-order eviction, which is an LRU because a hit
 * re-inserts. Small and dependency-free on purpose: the alternative is either a
 * cache library (a new dependency) or `infra-cache` (a forbidden layer
 * dependency), and the working set here is a few hundred URIs.
 *
 * @param options - see {@link InMemoryStatusListCacheOptions}.
 * @returns a cache honouring per-entry expiry and a bounded size.
 */
export function createInMemoryStatusListCache(
  options: InMemoryStatusListCacheOptions = {}
): StatusListCache {
  const maxEntries =
    options.maxEntries !== undefined &&
    Number.isSafeInteger(options.maxEntries) &&
    options.maxEntries > 0
      ? options.maxEntries
      : DEFAULT_MAX_ENTRIES;
  const now = options.now ?? ((): number => Date.now());
  const entries = new Map<string, CachedStatusList>();

  return {
    get(uri: string): CachedStatusList | undefined {
      const entry = entries.get(uri);
      if (entry === undefined) return undefined;

      if (entry.expiresAtMs <= now()) {
        entries.delete(uri);
        return undefined;
      }

      // Re-insert so recency ordering reflects reads, not just writes.
      entries.delete(uri);
      entries.set(uri, entry);
      return entry;
    },

    set(uri: string, entry: CachedStatusList): void {
      // An entry that is already expired is never stored: it would occupy a
      // slot and evict a live one, which is a cache-poisoning primitive for a
      // status issuer that publishes `ttl: 1`.
      if (entry.expiresAtMs <= now()) return;

      entries.delete(uri);
      entries.set(uri, entry);

      while (entries.size > maxEntries) {
        const oldest = entries.keys().next();
        if (oldest.done === true) break;
        entries.delete(oldest.value);
      }
    },
  };
}

/**
 * A cache that never stores and never hits.
 *
 * For deployments that supply their own caching at the HTTP layer, and for
 * tests that need every call to go to the network seam.
 */
export const NO_STATUS_LIST_CACHE: StatusListCache = Object.freeze({
  get: (): undefined => undefined,
  set: (): void => undefined,
});
