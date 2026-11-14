import {
  createKidDenylist,
  type DeniedKid,
  KID_DENYLIST_MAX_STALENESS_MS,
  type KidDenylist,
  type KidDenylistRead,
} from '@qauth-labs/fastify-plugin-signer';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

/**
 * THE `kid` DENYLIST OF EMERGENCY KEY RETIREMENT, as each node of the auth
 * server holds it (ADR-019 Decision 9, issue #551).
 *
 * An emergency retirement puts the retired keys' `kid`s on
 * `realm_key_denylist` in the transaction that marks them compromised. Every
 * node keeps a copy in memory (`createKidDenylist`), which every token
 * verification checks after the signature, and which the signer and the
 * published-key reader watch, so a compromised key stops verifying, signing
 * and being published on the node's next call.
 *
 * The copy is read every 2 s (the key library's
 * `DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS`). Most reads take a snapshot in
 * Redis that lives {@link KEY_DENYLIST_SNAPSHOT_TTL_SECONDS}, so the database
 * answers about once per snapshot for the whole deployment; a snapshot only
 * adds to the copy. The node reads the database itself at least every
 * {@link KEY_DENYLIST_STORE_READ_INTERVAL_MS}, and whenever Redis has no
 * snapshot, cannot be reached within {@link KEY_DENYLIST_CACHE_TIMEOUT_MS}, or
 * holds one this release cannot read; that read replaces the copy, so neither
 * a stale snapshot nor one written into Redis by someone else holds a node's
 * copy for longer. A node stores what it read only when no snapshot is
 * stored (`SET NX`): a node whose read began before a retirement committed
 * never overwrites the snapshot the retiring side wrote after it.
 *
 * The side that retires a key reads the database after the commit and stores
 * that list as the snapshot, overwriting the one before (or deletes it, when
 * it cannot), and denies the `kid`s on its own copy at once. Another node
 * sees the change at its next read: within one refresh interval, and within
 * one database read interval when Redis cannot be written. Under 10 s.
 *
 * The database is the truth; Redis only spares it reads. A node that reads
 * neither for {@link KID_DENYLIST_MAX_STALENESS_MS} refuses every token until
 * it can again.
 */

/** The snapshot's Redis key: one list for the whole deployment. */
export const KEY_DENYLIST_SNAPSHOT_KEY = 'qauth:key-denylist';

/** How long a snapshot lives in Redis, in seconds. */
export const KEY_DENYLIST_SNAPSHOT_TTL_SECONDS = 5;

/**
 * How long a node waits on Redis for the snapshot, in ms, before it reads the
 * database instead. A Redis that is gone can hold a command for seconds.
 */
export const KEY_DENYLIST_CACHE_TIMEOUT_MS = 250;

/**
 * How often a node reads the denylist from the database at the least, in ms,
 * whatever Redis answers.
 */
export const KEY_DENYLIST_STORE_READ_INTERVAL_MS = 8_000;

/**
 * How long a node waits on the database for the denylist, in ms. A read that
 * does not answer in time fails: the next refresh reads again.
 */
export const KEY_DENYLIST_STORE_TIMEOUT_MS = 5_000;

/** The Redis commands the denylist uses. */
export type KeyDenylistRedis = Pick<FastifyInstance['redis'], 'get' | 'set' | 'del'>;

/** Where a node reads the denylist. */
export interface KeyDenylistSources {
  /** The Redis client, looked up at each call: the cache plugin registers after the signer. */
  readonly redis: () => KeyDenylistRedis;
  /** Every denied `kid`: `realmPublicKeys.listDenied` of the repositories. */
  readonly listDenied: () => Promise<readonly DeniedKid[]>;
}

/** Test support: shorter windows for a suite that watches the denylist go stale. */
export interface KeyDenylistTiming {
  readonly refreshIntervalMs?: number;
  readonly maxStalenessMs?: number;
  /** {@link KEY_DENYLIST_STORE_READ_INTERVAL_MS}, or a third of the bound when that is shorter. */
  readonly storeReadIntervalMs?: number;
}

/** A call, given up after `timeoutMs`; its late failure is ignored. */
function bounded<T>(call: () => Promise<T>, timeoutMs: number, what: string): Promise<T> {
  let started: Promise<T>;
  try {
    started = call();
  } catch (error) {
    return Promise.reject(error);
  }
  started.catch(() => undefined);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not answer in time`)), timeoutMs);
    timer.unref?.();
  });
  return Promise.race([started, timeout]).finally(() => clearTimeout(timer));
}

/** A Redis call on the snapshot, given up after {@link KEY_DENYLIST_CACHE_TIMEOUT_MS}. */
function cacheCall<T>(call: () => Promise<T>): Promise<T> {
  return bounded(call, KEY_DENYLIST_CACHE_TIMEOUT_MS, 'The key denylist snapshot');
}

/** The windows a node reads under: the bound, and how often and how long it reads the database. */
function windowsOf(timing: KeyDenylistTiming): {
  readonly storeReadIntervalMs: number;
  readonly storeTimeoutMs: number;
} {
  const third = Math.max(
    1,
    Math.floor((timing.maxStalenessMs ?? KID_DENYLIST_MAX_STALENESS_MS) / 3)
  );
  return {
    storeReadIntervalMs:
      timing.storeReadIntervalMs ?? Math.min(KEY_DENYLIST_STORE_READ_INTERVAL_MS, third),
    storeTimeoutMs: Math.min(KEY_DENYLIST_STORE_TIMEOUT_MS, third),
  };
}

/** The database's list, in time, keeping only each row's realm and `kid`. */
async function readStore(sources: KeyDenylistSources, timeoutMs: number): Promise<DeniedKid[]> {
  const rows = await bounded(sources.listDenied, timeoutMs, 'The key denylist table');
  return rows.map(({ realmId, kid }) => ({ realmId, kid }));
}

/** The snapshot's list, or `undefined` when there is none, Redis fails, or it cannot be read. */
async function readSnapshot(sources: KeyDenylistSources): Promise<DeniedKid[] | undefined> {
  try {
    const cached = await cacheCall(() => sources.redis().get(KEY_DENYLIST_SNAPSHOT_KEY));
    return typeof cached === 'string' ? parseKeyDenylistSnapshot(cached) : undefined;
  } catch {
    // Redis is a cache here: the database answers.
    return undefined;
  }
}

function isDeniedKid(value: unknown): value is DeniedKid {
  if (typeof value !== 'object' || value === null) return false;
  const { realmId, kid } = value as Record<string, unknown>;
  return typeof realmId === 'string' && realmId !== '' && typeof kid === 'string' && kid !== '';
}

/** A snapshot's list, or `undefined` for one this release cannot read. */
export function parseKeyDenylistSnapshot(text: string): DeniedKid[] | undefined {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!Array.isArray(value) || !value.every(isDeniedKid)) return undefined;
  return value.map(({ realmId, kid }) => ({ realmId, kid }));
}

/**
 * The loader of a node's copy: the Redis snapshot, which only adds to the
 * copy; else, and at least every `storeReadIntervalMs`, the database, whose
 * answer replaces the copy and is stored as the snapshot when none is. When
 * the database fails, a snapshot still answers.
 *
 * @throws the database's error when it cannot answer in time and Redis holds
 *   no snapshot: the copy then keeps what it had, until it goes stale
 */
export function keyDenylistLoader(
  sources: KeyDenylistSources,
  timing: KeyDenylistTiming = {},
  now: () => number = Date.now
): () => Promise<KidDenylistRead> {
  const { storeReadIntervalMs, storeTimeoutMs } = windowsOf(timing);
  /** When the last database read that succeeded began. */
  let storeReadAt = -Infinity;
  return async () => {
    const startedAt = now();
    if (startedAt - storeReadAt < storeReadIntervalMs) {
      const cached = await readSnapshot(sources);
      if (cached !== undefined) return { entries: cached, complete: false };
    }
    let rows: DeniedKid[];
    try {
      rows = await readStore(sources, storeTimeoutMs);
    } catch (error) {
      const cached = await readSnapshot(sources);
      if (cached !== undefined) return { entries: cached, complete: false };
      throw error;
    }
    storeReadAt = Math.max(storeReadAt, startedAt);
    try {
      await cacheCall(() =>
        sources
          .redis()
          .set(
            KEY_DENYLIST_SNAPSHOT_KEY,
            JSON.stringify(rows),
            'EX',
            KEY_DENYLIST_SNAPSHOT_TTL_SECONDS,
            'NX'
          )
      );
    } catch {
      // The next read asks the database again.
    }
    return { entries: rows, complete: true };
  };
}

/**
 * A node's copy of the denylist, read through Redis and the database. A
 * failed timed read is logged once, and again only after a read succeeded.
 */
export function createAppKeyDenylist(
  sources: KeyDenylistSources,
  log: FastifyBaseLogger,
  timing: KeyDenylistTiming = {}
): KidDenylist {
  let failing = false;
  const load = keyDenylistLoader(sources, timing);
  const staleAfterSeconds = (timing.maxStalenessMs ?? KID_DENYLIST_MAX_STALENESS_MS) / 1000;
  return createKidDenylist({
    load: async () => {
      const read = await load();
      if (failing) log.info('The key denylist is read again');
      failing = false;
      return read;
    },
    ...(timing.refreshIntervalMs === undefined
      ? {}
      : { refreshIntervalMs: timing.refreshIntervalMs }),
    ...(timing.maxStalenessMs === undefined ? {} : { maxStalenessMs: timing.maxStalenessMs }),
    onError: (error) => {
      if (failing) return;
      failing = true;
      log.warn(
        { err: error },
        `The key denylist cannot be read; every token is refused once it is ${staleAfterSeconds} s old`
      );
    },
  });
}

/**
 * After a retirement committed: deny its `kid`s on this node's copy at once;
 * read the database and store its list as the Redis snapshot, overwriting the
 * one before, so every node sees the change at its next read (or delete the
 * snapshot, when that fails, so every node reads the database); and read this
 * node's copy again. Each step is bounded in time, and a failure is logged,
 * never thrown: the other nodes still see the change at their next database
 * read.
 */
export async function invalidateKeyDenylist(
  denylist: Pick<KidDenylist, 'add' | 'refresh'> | null,
  sources: KeyDenylistSources,
  log: FastifyBaseLogger,
  retired: readonly DeniedKid[] = []
): Promise<void> {
  denylist?.add(retired);
  const { storeTimeoutMs } = windowsOf({});
  try {
    const rows = await readStore(sources, storeTimeoutMs);
    const known = new Set(rows.map(({ realmId, kid }) => `${realmId}\u0000${kid}`));
    for (const { realmId, kid } of retired) {
      if (!known.has(`${realmId}\u0000${kid}`)) rows.push({ realmId, kid });
    }
    await cacheCall(() =>
      sources
        .redis()
        .set(
          KEY_DENYLIST_SNAPSHOT_KEY,
          JSON.stringify(rows),
          'EX',
          KEY_DENYLIST_SNAPSHOT_TTL_SECONDS
        )
    );
  } catch (error) {
    try {
      await cacheCall(() => sources.redis().del(KEY_DENYLIST_SNAPSHOT_KEY));
    } catch {
      log.warn(
        { err: error },
        `The key denylist snapshot could not be replaced; other nodes see the retirement at their next database read, within ${KEY_DENYLIST_STORE_READ_INTERVAL_MS / 1000} s`
      );
    }
  }
  if (denylist === null) return;
  try {
    await bounded(() => denylist.refresh(), storeTimeoutMs, 'The key denylist');
  } catch (error) {
    log.warn({ err: error }, 'The key denylist could not be read again after a retirement');
  }
}
