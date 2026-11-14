/**
 * THE `kid` DENYLIST OF EMERGENCY RETIREMENT (ADR-019 Decision 9, #551).
 *
 * An emergency retirement marks a key `compromised` and puts its `kid` on the
 * realm's denylist (`realm_key_denylist`) in the same transaction. Every
 * verify site checks the `kid` of a token whose signature it verified against
 * this node's copy of the list, and refuses a denied one: the key readers
 * cache a realm's keys for up to a minute, the denylist reaches a running
 * node within seconds.
 *
 * This module is the copy a node holds: it reads the whole list through the
 * `load` it is given (the shared cache, then the database, in the wiring),
 * again every {@link DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS}, and answers
 * from memory. It fails closed: a copy that has not been read for
 * {@link KID_DENYLIST_MAX_STALENESS_MS}, or never was, is not current, and a
 * verify site refuses every token while it is not.
 *
 * The copy only grows: a `kid` once denied stays denied on the node, as the
 * table never removes one (a realm's deletion takes its rows, and its keys,
 * with it). So a read of the shared cache that lacks a `kid` the node knows,
 * whether stale or tampered with, never lets that key back in.
 *
 * The key readers (the in-process signer, the published-key reader) watch the
 * copy's {@link KidDenylistView.revision}: when it changes, they drop the key
 * lists they cached, so a compromised key leaves the JWKS, the verification
 * set and signing on the node's next call, not a refresh interval later.
 *
 * Nothing here touches key material.
 */

/** How often a node reads the denylist again, in ms. */
export const DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS = 2_000;

/**
 * How long a copy of the denylist is trusted after the read it came from
 * began, in ms. Past it, the node refuses every token until a read succeeds.
 */
export const KID_DENYLIST_MAX_STALENESS_MS = 30_000;

/** One denied key: its realm and `kid`. */
export interface DeniedKid {
  readonly realmId: string;
  readonly kid: string;
}

/** What a key reader reads of the denylist: the denied keys, and when the list changed. */
export interface KidDenylistView {
  /** Whether the copy holds `kid` of the realm. A `kid` is compared byte for byte. */
  isDenied(realmId: string, kid: string): boolean;
  /**
   * A number that changes each time the copy's set of denied keys changes. A
   * cache of key lists compares it with the one it read under.
   */
  revision(): number;
}

/** A node's copy of the denylist. See {@link createKidDenylist}. */
export interface KidDenylist extends KidDenylistView {
  /**
   * Whether the copy may be trusted now: a read succeeded, and began at most
   * the staleness bound ago. A verify site refuses every token otherwise.
   */
  isCurrent(): boolean;
  /**
   * Read the list now. The read begins after the call, so a caller that just
   * changed the list sees the change once it resolves; a read already running
   * is waited for first. Rejects when the read fails, and keeps the copy.
   */
  refresh(): Promise<void>;
  /**
   * Deny `entries` on this copy now, without a read: the node that retired
   * the keys knows their `kid`s once its transaction committed, before any
   * read could return them.
   */
  add(entries: readonly DeniedKid[]): void;
  /** Read the list every refresh interval, on a timer that keeps no process alive. */
  start(): void;
  /** Stop reading. */
  stop(): void;
}

/** Options of {@link createKidDenylist}. */
export interface KidDenylistOptions {
  /**
   * Read the whole denylist. The wiring reads the shared cache's snapshot,
   * and the database when the cache misses or fails.
   */
  readonly load: () => Promise<readonly DeniedKid[]>;
  /** {@link DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS} by default. */
  readonly refreshIntervalMs?: number;
  /** {@link KID_DENYLIST_MAX_STALENESS_MS} by default. */
  readonly maxStalenessMs?: number;
  /** The clock, in epoch ms. Defaults to `Date.now`. */
  readonly now?: () => number;
  /** Told of each timed read that fails. The copy is kept until it is stale. */
  readonly onError?: (error: unknown) => void;
}

/** The set's key of one denied `kid`: a realm id holds no NUL, so the pair is one string. */
function entryOf(realmId: string, kid: string): string {
  return `${realmId.toLowerCase()}\u0000${kid}`;
}

function isDeniedKid(value: unknown): value is DeniedKid {
  if (typeof value !== 'object' || value === null) return false;
  const { realmId, kid } = value as Record<string, unknown>;
  return typeof realmId === 'string' && realmId !== '' && typeof kid === 'string' && kid !== '';
}

/**
 * A node's copy of the `kid` denylist, read through `load`.
 *
 * @throws TypeError for an interval or bound that is not a positive whole
 *   number of ms, or a refresh interval no shorter than the bound
 */
export function createKidDenylist(options: KidDenylistOptions): KidDenylist {
  const { load, onError } = options;
  const now = options.now ?? Date.now;
  const refreshIntervalMs = options.refreshIntervalMs ?? DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS;
  const maxStalenessMs = options.maxStalenessMs ?? KID_DENYLIST_MAX_STALENESS_MS;
  if (typeof load !== 'function') throw new TypeError('A denylist needs its loader');
  for (const value of [refreshIntervalMs, maxStalenessMs]) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new TypeError('A denylist interval is a positive whole number of ms');
    }
  }
  if (refreshIntervalMs >= maxStalenessMs) {
    throw new TypeError('The denylist is read more often than it goes stale');
  }

  let denied: ReadonlySet<string> = new Set();
  let currentRevision = 0;
  /** When the read the copy came from began; `null` until one succeeds. */
  let readAt: number | null = null;
  let inFlight: Promise<void> | undefined;
  let queued: Promise<void> | undefined;
  let timer: ReturnType<typeof setInterval> | undefined;

  function read(): Promise<void> {
    const startedAt = now();
    const running = (async () => {
      const rows = await load();
      if (!Array.isArray(rows) || !rows.every(isDeniedKid)) {
        throw new TypeError('The denylist read is not a list of denied keys');
      }
      const next = new Set(denied);
      for (const row of rows) next.add(entryOf(row.realmId, row.kid));
      if (next.size !== denied.size) {
        denied = next;
        currentRevision += 1;
      }
      // A read that began before an earlier one succeeded never moves the time back.
      if (readAt === null || startedAt > readAt) readAt = startedAt;
    })();
    // What a later caller waits on: it settles with the read and never
    // rejects, so a failed read no one else awaits raises no unhandled
    // rejection.
    const settled = running.then(
      () => undefined,
      () => undefined
    );
    inFlight = settled;
    void settled.then(() => {
      if (inFlight === settled) inFlight = undefined;
    });
    return running;
  }

  function refresh(): Promise<void> {
    if (queued !== undefined) return queued;
    if (inFlight === undefined) return read();
    // A read is running, and may have begun before the caller's change: one
    // more read follows it, shared by everyone who asks meanwhile.
    const after = inFlight.then(() => {
      queued = undefined;
      return read();
    });
    queued = after;
    return after;
  }

  return Object.freeze({
    isDenied(realmId: string, kid: string): boolean {
      return denied.has(entryOf(realmId, kid));
    },
    revision(): number {
      return currentRevision;
    },
    isCurrent(): boolean {
      return readAt !== null && now() - readAt <= maxStalenessMs;
    },
    refresh,
    add(entries: readonly DeniedKid[]): void {
      if (!Array.isArray(entries) || !entries.every(isDeniedKid)) {
        throw new TypeError('A denied key names its realm and kid');
      }
      const next = new Set(denied);
      for (const entry of entries) next.add(entryOf(entry.realmId, entry.kid));
      if (next.size !== denied.size) {
        denied = next;
        currentRevision += 1;
      }
    },
    start(): void {
      if (timer !== undefined) return;
      timer = setInterval(() => {
        // A slow read is not stacked on: the next tick asks again.
        if (inFlight !== undefined) return;
        read().catch((error: unknown) => onError?.(error));
      }, refreshIntervalMs);
      timer.unref?.();
    },
    stop(): void {
      if (timer !== undefined) clearInterval(timer);
      timer = undefined;
    },
  });
}
