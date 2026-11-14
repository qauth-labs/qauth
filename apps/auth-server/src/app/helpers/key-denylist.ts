import {
  createKidDenylist,
  type DeniedKid,
  KID_DENYLIST_MAX_STALENESS_MS,
  type KidDenylist,
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
 * `DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS`):
 * from a snapshot in Redis that lives {@link KEY_DENYLIST_SNAPSHOT_TTL_SECONDS},
 * so the database answers about once per snapshot for the whole deployment,
 * and from the database itself when Redis has no snapshot, cannot be reached
 * within {@link KEY_DENYLIST_CACHE_TIMEOUT_MS}, or holds one this release
 * cannot read. The node that retires a key deletes the snapshot after the
 * commit and reads its copy again at once. Another node sees the change
 * within one refresh interval plus one snapshot life: under 10 s.
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

/** The Redis commands the denylist uses. */
export type KeyDenylistRedis = Pick<FastifyInstance['redis'], 'get' | 'set' | 'del'>;

/** Where a node reads the denylist. */
export interface KeyDenylistSources {
  /** The Redis client, looked up at each call: the cache plugin registers after the signer. */
  readonly redis: () => KeyDenylistRedis;
  /** Every denied `kid`: `realmPublicKeys.listDenied` of the repositories. */
  readonly listDenied: () => Promise<readonly DeniedKid[]>;
}

/** A Redis call, given up after {@link KEY_DENYLIST_CACHE_TIMEOUT_MS}; its late failure is ignored. */
function bounded<T>(call: () => Promise<T>): Promise<T> {
  let started: Promise<T>;
  try {
    started = call();
  } catch (error) {
    return Promise.reject(error);
  }
  started.catch(() => undefined);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error('The key denylist snapshot did not answer in time')),
      KEY_DENYLIST_CACHE_TIMEOUT_MS
    );
    timer.unref?.();
  });
  return Promise.race([started, timeout]).finally(() => clearTimeout(timer));
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
 * The loader of a node's copy: the Redis snapshot, else the database, whose
 * answer it then stores as the snapshot.
 *
 * @throws the database's error when Redis has no snapshot and the database
 *   cannot answer: the copy then keeps what it had, until it goes stale
 */
export function keyDenylistLoader(
  sources: KeyDenylistSources
): () => Promise<readonly DeniedKid[]> {
  return async () => {
    try {
      const cached = await bounded(() => sources.redis().get(KEY_DENYLIST_SNAPSHOT_KEY));
      if (typeof cached === 'string') {
        const parsed = parseKeyDenylistSnapshot(cached);
        if (parsed !== undefined) return parsed;
      }
    } catch {
      // Redis is a cache here: the database answers.
    }
    const rows = (await sources.listDenied()).map(({ realmId, kid }) => ({ realmId, kid }));
    try {
      await bounded(() =>
        sources
          .redis()
          .set(
            KEY_DENYLIST_SNAPSHOT_KEY,
            JSON.stringify(rows),
            'EX',
            KEY_DENYLIST_SNAPSHOT_TTL_SECONDS
          )
      );
    } catch {
      // The next read asks the database again.
    }
    return rows;
  };
}

/** Test support: shorter windows for a suite that watches the denylist go stale. */
export interface KeyDenylistTiming {
  readonly refreshIntervalMs?: number;
  readonly maxStalenessMs?: number;
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
  const load = keyDenylistLoader(sources);
  const staleAfterSeconds = (timing.maxStalenessMs ?? KID_DENYLIST_MAX_STALENESS_MS) / 1000;
  return createKidDenylist({
    load: async () => {
      const rows = await load();
      if (failing) log.info('The key denylist is read again');
      failing = false;
      return rows;
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
 * After a retirement committed: deny its `kid`s on this node's copy at once,
 * delete the Redis snapshot, so every node reads the database at its next
 * refresh, and read this node's copy again. A failure of either is logged:
 * the other nodes still see the change once the snapshot expires.
 */
export async function invalidateKeyDenylist(
  denylist: Pick<KidDenylist, 'add' | 'refresh'> | null,
  redis: KeyDenylistRedis,
  log: FastifyBaseLogger,
  retired: readonly DeniedKid[] = []
): Promise<void> {
  denylist?.add(retired);
  try {
    await bounded(() => redis.del(KEY_DENYLIST_SNAPSHOT_KEY));
  } catch (error) {
    log.warn(
      { err: error },
      `The key denylist snapshot could not be deleted; other nodes see the retirement within ${KEY_DENYLIST_SNAPSHOT_TTL_SECONDS} s more`
    );
  }
  if (denylist === null) return;
  try {
    await denylist.refresh();
  } catch (error) {
    log.warn({ err: error }, 'The key denylist could not be read again after a retirement');
  }
}
