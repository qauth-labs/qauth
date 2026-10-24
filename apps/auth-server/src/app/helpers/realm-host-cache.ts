import type { FastifyInstance } from 'fastify';

/** A realm and the `realm_hosts` row that named it, as `realms.findByHost` returns them. */
export type RealmHostMatch = NonNullable<
  Awaited<ReturnType<FastifyInstance['repositories']['realms']['findByHost']>>
>;

/** Looks a normalised host up in `realm_hosts`. */
export type RealmHostLookup = (host: string) => Promise<RealmHostMatch | undefined>;

/** How long a host that names a realm is cached, by default. */
export const REALM_HOST_CACHE_TTL_MS = 30_000;

/** The longest a host that names no realm is cached. */
export const REALM_HOST_MISS_TTL_MS = 5_000;

/**
 * How many hosts each half of the cache holds. A request can name any host, so
 * the misses would otherwise grow without bound; the hits are kept apart so a
 * flood of unknown hosts cannot push the real ones out.
 */
export const REALM_HOST_CACHE_MAX_ENTRIES = 1_000;

/** Options for {@link createRealmHostCache}. */
export interface RealmHostCacheOptions {
  /** The database lookup. */
  readonly lookup: RealmHostLookup;
  /** How long a hit is kept, in milliseconds. Defaults to {@link REALM_HOST_CACHE_TTL_MS}. */
  readonly ttlMs?: number;
  /** The clock, in milliseconds. Defaults to `Date.now`. */
  readonly now?: () => number;
  /** Entries per half. Defaults to {@link REALM_HOST_CACHE_MAX_ENTRIES}. */
  readonly maxEntries?: number;
}

/** The in-process cache in front of the realm host lookup. */
export interface RealmHostCache {
  /**
   * The realm that owns `host`, or `undefined` when none does. `host` must
   * already be normalised (`normaliseRealmHost`), since it is the cache key.
   * A lookup that fails is not cached and rejects.
   */
  resolve(host: string): Promise<RealmHostMatch | undefined>;
  /** Forget every entry. A lookup still running when this is called is not stored. */
  clear(): void;
}

/** Set `key` in `map`, dropping the oldest entry first when the map is full. */
function setBounded<V>(map: Map<string, V>, key: string, value: V, maxEntries: number): void {
  map.delete(key);
  if (map.size >= maxEntries) {
    const oldest = map.keys().next();
    if (!oldest.done) map.delete(oldest.value);
  }
  map.set(key, value);
}

/**
 * Create the cache the realm resolver reads hosts through (ADR-019 Decision 1,
 * issue #486).
 *
 * A host that names a realm is kept for `ttlMs` (30 s by default), so a change
 * to the realm row, such as disabling it, reaches requests within that time. A
 * host that names no realm is kept for at most {@link REALM_HOST_MISS_TTL_MS},
 * and never longer than a hit, so a new host answers within 5 s of being
 * added. Concurrent requests for a host that is not cached share one lookup.
 *
 * A host the cache has not seen costs one primary-key query on `realm_hosts`,
 * and the resolver asks before the rate limiter runs, so a caller that sends a
 * new made-up host on every request costs one query per request. A reverse
 * proxy that forwards only the deployment's own host names keeps that off the
 * database.
 */
export function createRealmHostCache(options: RealmHostCacheOptions): RealmHostCache {
  const ttlMs = options.ttlMs ?? REALM_HOST_CACHE_TTL_MS;
  const missTtlMs = Math.min(ttlMs, REALM_HOST_MISS_TTL_MS);
  const now = options.now ?? Date.now;
  const maxEntries = options.maxEntries ?? REALM_HOST_CACHE_MAX_ENTRIES;

  const hits = new Map<string, { readonly match: RealmHostMatch; readonly expiresAt: number }>();
  const misses = new Map<string, number>();
  const pending = new Map<string, Promise<RealmHostMatch | undefined>>();
  /** Bumped by `clear()`, so a lookup that started before it stores nothing. */
  let generation = 0;

  /** Remember what the lookup found, unless the cache was cleared meanwhile. */
  function store(
    host: string,
    match: RealmHostMatch | undefined,
    startedIn: number
  ): RealmHostMatch | undefined {
    if (startedIn !== generation) return match;
    if (match === undefined) {
      hits.delete(host);
      setBounded(misses, host, now() + missTtlMs, maxEntries);
    } else {
      misses.delete(host);
      setBounded(hits, host, { match, expiresAt: now() + ttlMs }, maxEntries);
    }
    return match;
  }

  return {
    resolve(host: string): Promise<RealmHostMatch | undefined> {
      const at = now();
      const hit = hits.get(host);
      if (hit !== undefined) {
        if (hit.expiresAt > at) return Promise.resolve(hit.match);
        hits.delete(host);
      }
      const missExpiresAt = misses.get(host);
      if (missExpiresAt !== undefined) {
        if (missExpiresAt > at) return Promise.resolve(undefined);
        misses.delete(host);
      }

      let lookup = pending.get(host);
      if (lookup === undefined) {
        const startedIn = generation;
        // Started on a later tick, so `finally` always runs after `set` and a
        // lookup that throws at once does not stay pending for ever.
        const started: Promise<RealmHostMatch | undefined> = Promise.resolve()
          .then(() => options.lookup(host))
          .then((match) => store(host, match, startedIn))
          .finally(() => {
            if (pending.get(host) === started) pending.delete(host);
          });
        lookup = started;
        pending.set(host, lookup);
      }
      return lookup;
    },

    clear(): void {
      generation += 1;
      hits.clear();
      misses.clear();
      pending.clear();
    },
  };
}
