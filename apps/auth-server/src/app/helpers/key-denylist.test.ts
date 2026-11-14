import type { DeniedKid } from '@qauth-labs/fastify-plugin-signer';
import type { FastifyBaseLogger } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createAppKeyDenylist,
  invalidateKeyDenylist,
  KEY_DENYLIST_CACHE_TIMEOUT_MS,
  KEY_DENYLIST_SNAPSHOT_KEY,
  KEY_DENYLIST_SNAPSHOT_TTL_SECONDS,
  keyDenylistLoader,
  type KeyDenylistRedis,
  parseKeyDenylistSnapshot,
} from './key-denylist';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const DENIED: DeniedKid[] = [{ realmId: REALM, kid: 'k1' }];

/** A Redis that answers from `store`, or as a test overrides each command. */
function fakeRedis(overrides: Partial<Record<'get' | 'set' | 'del', () => Promise<unknown>>> = {}) {
  const store = new Map<string, string>();
  const redis = {
    get: vi.fn(overrides.get ?? (async (key: string) => store.get(key) ?? null)),
    set: vi.fn(
      overrides.set ??
        (async (key: string, value: string) => {
          store.set(key, value);
          return 'OK';
        })
    ),
    del: vi.fn(overrides.del ?? (async (key: string) => (store.delete(key) ? 1 : 0))),
  };
  return { store, redis: redis as unknown as KeyDenylistRedis & typeof redis };
}

function fakeLog() {
  return {
    warn: vi.fn(),
    info: vi.fn(),
  } as unknown as FastifyBaseLogger & {
    warn: ReturnType<typeof vi.fn>;
    info: ReturnType<typeof vi.fn>;
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('parseKeyDenylistSnapshot', () => {
  it('reads a list of denied keys, keeping only their realm and kid', () => {
    expect(parseKeyDenylistSnapshot(JSON.stringify([{ realmId: REALM, kid: 'k1', x: 1 }]))).toEqual(
      DENIED
    );
    expect(parseKeyDenylistSnapshot('[]')).toEqual([]);
  });

  it.each(['', 'not json', '{}', 'null', '[{"realmId":"r"}]', '[{"realmId":"r","kid":""}]'])(
    'cannot read %j',
    (text) => {
      expect(parseKeyDenylistSnapshot(text)).toBeUndefined();
    }
  );
});

describe('keyDenylistLoader', () => {
  it('answers from the Redis snapshot without asking the database', async () => {
    const { store, redis } = fakeRedis();
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, JSON.stringify(DENIED));
    const listDenied = vi.fn(async () => []);
    await expect(keyDenylistLoader({ redis: () => redis, listDenied })()).resolves.toEqual(DENIED);
    expect(listDenied).not.toHaveBeenCalled();
  });

  it('reads the database when no snapshot is stored, and stores its answer for a few seconds', async () => {
    const { redis } = fakeRedis();
    const listDenied = vi.fn(async () => [{ ...DENIED[0], deniedAt: 1 }]);
    await expect(keyDenylistLoader({ redis: () => redis, listDenied })()).resolves.toEqual(DENIED);
    expect(listDenied).toHaveBeenCalledTimes(1);
    expect(redis.set).toHaveBeenCalledWith(
      KEY_DENYLIST_SNAPSHOT_KEY,
      JSON.stringify(DENIED),
      'EX',
      KEY_DENYLIST_SNAPSHOT_TTL_SECONDS
    );
  });

  it('reads the database when the snapshot cannot be read', async () => {
    const { store, redis } = fakeRedis();
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, '{"tampered":true}');
    const listDenied = vi.fn(async () => DENIED);
    await expect(keyDenylistLoader({ redis: () => redis, listDenied })()).resolves.toEqual(DENIED);
    expect(listDenied).toHaveBeenCalledTimes(1);
  });

  it('works with Redis down: a failing command, or none at all, falls back to the database', async () => {
    const down = fakeRedis({
      get: async () => {
        throw new Error('ECONNREFUSED');
      },
      set: async () => {
        throw new Error('ECONNREFUSED');
      },
    }).redis;
    const listDenied = vi.fn(async () => DENIED);
    await expect(keyDenylistLoader({ redis: () => down, listDenied })()).resolves.toEqual(DENIED);
    const missing = () => {
      throw new Error('fastify.redis is not decorated');
    };
    await expect(keyDenylistLoader({ redis: missing, listDenied })()).resolves.toEqual(DENIED);
  });

  it('gives up on a Redis that does not answer, and reads the database in time', async () => {
    vi.useFakeTimers();
    const hung = fakeRedis({
      get: () => new Promise(() => undefined),
      set: () => new Promise(() => undefined),
    }).redis;
    const listDenied = vi.fn(async () => DENIED);
    const loading = keyDenylistLoader({ redis: () => hung, listDenied })();
    await vi.advanceTimersByTimeAsync(KEY_DENYLIST_CACHE_TIMEOUT_MS);
    expect(listDenied).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(KEY_DENYLIST_CACHE_TIMEOUT_MS);
    await expect(loading).resolves.toEqual(DENIED);
  });

  it("rejects with the database's error when Redis has no snapshot and the database fails", async () => {
    const { redis } = fakeRedis();
    const listDenied = vi.fn(async (): Promise<DeniedKid[]> => {
      throw new Error('database down');
    });
    await expect(keyDenylistLoader({ redis: () => redis, listDenied })()).rejects.toThrow(
      'database down'
    );
  });
});

describe('createAppKeyDenylist', () => {
  it('logs a failing read once, and again only after a read succeeded', async () => {
    vi.useFakeTimers();
    const log = fakeLog();
    const { redis } = fakeRedis();
    const listDenied = vi.fn(async () => DENIED);
    const denylist = createAppKeyDenylist({ redis: () => redis, listDenied }, log, {
      refreshIntervalMs: 100,
      maxStalenessMs: 1_000,
    });
    await denylist.refresh();
    expect(denylist.isDenied(REALM, 'k1')).toBe(true);

    redis.get.mockRejectedValue(new Error('redis down'));
    listDenied.mockRejectedValue(new Error('database down'));
    denylist.start();
    await vi.advanceTimersByTimeAsync(500);
    expect(log.warn).toHaveBeenCalledTimes(1);
    expect(log.warn.mock.calls[0]?.[1]).toBe(
      'The key denylist cannot be read; every token is refused once it is 1 s old'
    );
    // Past the bound, the copy is not current: the verify sites refuse every token.
    await vi.advanceTimersByTimeAsync(1_000);
    expect(denylist.isCurrent()).toBe(false);
    expect(log.warn).toHaveBeenCalledTimes(1);

    listDenied.mockResolvedValue(DENIED);
    await vi.advanceTimersByTimeAsync(100);
    expect(denylist.isCurrent()).toBe(true);
    expect(log.info).toHaveBeenCalledWith('The key denylist is read again');
    denylist.stop();
  });
});

describe('invalidateKeyDenylist', () => {
  it('denies the retired kids on the copy at once, deletes the snapshot, and reads the copy again', async () => {
    const { store, redis } = fakeRedis();
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, '[]');
    const denylist = { add: vi.fn(), refresh: vi.fn(async () => undefined) };
    await invalidateKeyDenylist(denylist, redis, fakeLog(), DENIED);
    expect(denylist.add).toHaveBeenCalledWith(DENIED);
    expect(store.has(KEY_DENYLIST_SNAPSHOT_KEY)).toBe(false);
    expect(denylist.refresh).toHaveBeenCalledTimes(1);
    expect(denylist.add.mock.invocationCallOrder[0]).toBeLessThan(
      redis.del.mock.invocationCallOrder[0] ?? 0
    );
  });

  it('logs, and does not throw, when Redis or the read fails', async () => {
    const log = fakeLog();
    const { redis } = fakeRedis({
      del: async () => {
        throw new Error('redis down');
      },
    });
    const denylist = {
      add: vi.fn(),
      refresh: vi.fn(async () => {
        throw new Error('database down');
      }),
    };
    await expect(invalidateKeyDenylist(denylist, redis, log, DENIED)).resolves.toBeUndefined();
    expect(denylist.add).toHaveBeenCalledWith(DENIED);
    expect(log.warn).toHaveBeenCalledTimes(2);
  });

  it('only deletes the snapshot on a process that holds no copy', async () => {
    const { store, redis } = fakeRedis();
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, '[]');
    await invalidateKeyDenylist(null, redis, fakeLog(), DENIED);
    expect(store.has(KEY_DENYLIST_SNAPSHOT_KEY)).toBe(false);
  });
});
