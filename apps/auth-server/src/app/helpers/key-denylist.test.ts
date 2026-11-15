import type { DeniedKid } from '@qauth-labs/fastify-plugin-signer';
import type { FastifyBaseLogger } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createAppKeyDenylist,
  invalidateKeyDenylist,
  KEY_DENYLIST_CACHE_TIMEOUT_MS,
  KEY_DENYLIST_SNAPSHOT_KEY,
  KEY_DENYLIST_SNAPSHOT_TTL_SECONDS,
  KEY_DENYLIST_STORE_READ_INTERVAL_MS,
  KEY_DENYLIST_STORE_TIMEOUT_MS,
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
  it('reads the database first, as the whole list, and stores it as the snapshot when none is', async () => {
    const { redis } = fakeRedis();
    const listDenied = vi.fn(async () => [{ ...DENIED[0], deniedAt: 1 }]);
    await expect(keyDenylistLoader({ redis: () => redis, listDenied })()).resolves.toEqual({
      entries: DENIED,
      complete: true,
    });
    expect(listDenied).toHaveBeenCalledTimes(1);
    expect(redis.set).toHaveBeenCalledWith(
      KEY_DENYLIST_SNAPSHOT_KEY,
      JSON.stringify(DENIED),
      'EX',
      KEY_DENYLIST_SNAPSHOT_TTL_SECONDS,
      'NX'
    );
  });

  it('answers from the snapshot between database reads, as a read that only adds', async () => {
    const clock = { now: 1_000_000 };
    const { store, redis } = fakeRedis();
    const listDenied = vi.fn(async () => []);
    const load = keyDenylistLoader({ redis: () => redis, listDenied }, {}, () => clock.now);
    await load();
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, JSON.stringify(DENIED));
    clock.now += KEY_DENYLIST_STORE_READ_INTERVAL_MS - 1;
    await expect(load()).resolves.toEqual({ entries: DENIED, complete: false });
    expect(listDenied).toHaveBeenCalledTimes(1);
  });

  it('reads the database again once the interval passed, whatever the snapshot holds', async () => {
    const clock = { now: 1_000_000 };
    const { store, redis } = fakeRedis();
    const listDenied = vi.fn(async () => DENIED);
    const load = keyDenylistLoader({ redis: () => redis, listDenied }, {}, () => clock.now);
    await load();
    // A snapshot that never expires, and lacks the kid.
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, '[]');
    clock.now += KEY_DENYLIST_STORE_READ_INTERVAL_MS;
    await expect(load()).resolves.toEqual({ entries: DENIED, complete: true });
    expect(listDenied).toHaveBeenCalledTimes(2);
  });

  it('reads the database a third of the bound apart at most, for a shorter bound', async () => {
    const clock = { now: 1_000_000 };
    const { store, redis } = fakeRedis();
    const listDenied = vi.fn(async () => DENIED);
    const load = keyDenylistLoader(
      { redis: () => redis, listDenied },
      { refreshIntervalMs: 100, maxStalenessMs: 900 },
      () => clock.now
    );
    await load();
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, '[]');
    clock.now += 299;
    await expect(load()).resolves.toMatchObject({ complete: false });
    clock.now += 1;
    await expect(load()).resolves.toMatchObject({ complete: true });
  });

  it('reads the database when the snapshot is missing or cannot be read', async () => {
    const clock = { now: 1_000_000 };
    const { store, redis } = fakeRedis();
    const listDenied = vi.fn(async () => DENIED);
    const load = keyDenylistLoader({ redis: () => redis, listDenied }, {}, () => clock.now);
    await load();
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, '{"tampered":true}');
    await expect(load()).resolves.toEqual({ entries: DENIED, complete: true });
    store.delete(KEY_DENYLIST_SNAPSHOT_KEY);
    await expect(load()).resolves.toEqual({ entries: DENIED, complete: true });
    expect(listDenied).toHaveBeenCalledTimes(3);
  });

  it('works with Redis down: a failing command, or none at all, leaves the database', async () => {
    const down = fakeRedis({
      get: async () => {
        throw new Error('ECONNREFUSED');
      },
      set: async () => {
        throw new Error('ECONNREFUSED');
      },
    }).redis;
    const listDenied = vi.fn(async () => DENIED);
    const read = { entries: DENIED, complete: true };
    await expect(keyDenylistLoader({ redis: () => down, listDenied })()).resolves.toEqual(read);
    const missing = () => {
      throw new Error('fastify.redis is not decorated');
    };
    await expect(keyDenylistLoader({ redis: missing, listDenied })()).resolves.toEqual(read);
  });

  it('gives up on a Redis that does not answer, and reads the database in time', async () => {
    vi.useFakeTimers();
    const clock = { now: 1_000_000 };
    const hung = fakeRedis({
      get: () => new Promise(() => undefined),
      set: () => new Promise(() => undefined),
    }).redis;
    const listDenied = vi.fn(async () => DENIED);
    const load = keyDenylistLoader({ redis: () => hung, listDenied }, {}, () => clock.now);
    const first = load();
    await vi.advanceTimersByTimeAsync(KEY_DENYLIST_CACHE_TIMEOUT_MS);
    await expect(first).resolves.toMatchObject({ complete: true });
    const second = load();
    await vi.advanceTimersByTimeAsync(KEY_DENYLIST_CACHE_TIMEOUT_MS);
    expect(listDenied).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(KEY_DENYLIST_CACHE_TIMEOUT_MS);
    await expect(second).resolves.toEqual({ entries: DENIED, complete: true });
  });

  it('gives up on a database that does not answer, and answers from the snapshot if there is one', async () => {
    vi.useFakeTimers();
    const { store, redis } = fakeRedis();
    const listDenied = vi.fn((): Promise<DeniedKid[]> => new Promise(() => undefined));
    const load = keyDenylistLoader({ redis: () => redis, listDenied });
    const bare = load();
    const refused = expect(bare).rejects.toThrow('The key denylist table did not answer in time');
    await vi.advanceTimersByTimeAsync(KEY_DENYLIST_STORE_TIMEOUT_MS);
    await refused;
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, JSON.stringify(DENIED));
    const cached = load();
    await vi.advanceTimersByTimeAsync(KEY_DENYLIST_STORE_TIMEOUT_MS);
    await expect(cached).resolves.toEqual({ entries: DENIED, complete: false });
  });

  it('runs one database query at a time, and starts another once one hung twice the timeout', async () => {
    vi.useFakeTimers();
    const { redis } = fakeRedis();
    const listDenied = vi.fn((): Promise<DeniedKid[]> => new Promise(() => undefined));
    const load = keyDenylistLoader({ redis: () => redis, listDenied });
    for (let round = 0; round < 2; round += 1) {
      const refused = expect(load()).rejects.toThrow('did not answer in time');
      await vi.advanceTimersByTimeAsync(KEY_DENYLIST_STORE_TIMEOUT_MS);
      await refused;
    }
    // The second read waited for the first query, which still holds its connection.
    expect(listDenied).toHaveBeenCalledTimes(1);
    const third = expect(load()).rejects.toThrow('did not answer in time');
    await vi.advanceTimersByTimeAsync(KEY_DENYLIST_STORE_TIMEOUT_MS);
    await third;
    expect(listDenied).toHaveBeenCalledTimes(2);
  });

  it('shares a running database query, and queries again once it answered', async () => {
    let answer: (rows: DeniedKid[]) => void = () => undefined;
    const listDenied = vi.fn(
      () =>
        new Promise<DeniedKid[]>((resolve) => {
          answer = resolve;
        })
    );
    const { redis } = fakeRedis({ get: async () => null });
    // A clock that stands still: both calls begin when the query does.
    const load = keyDenylistLoader({ redis: () => redis, listDenied }, {}, () => 0);
    const first = load();
    const second = load();
    await vi.waitFor(() => expect(listDenied).toHaveBeenCalledTimes(1));
    answer(DENIED);
    await expect(first).resolves.toEqual({ entries: DENIED, complete: true });
    await expect(second).resolves.toEqual({ entries: DENIED, complete: true });
    expect(listDenied).toHaveBeenCalledTimes(1);
    const third = load();
    await vi.waitFor(() => expect(listDenied).toHaveBeenCalledTimes(2));
    answer([]);
    await expect(third).resolves.toEqual({ entries: [], complete: true });
  });

  it('answers a query it waited for with its age, stores it as no snapshot, and does not put the next query off', async () => {
    vi.useFakeTimers();
    let answer: (rows: DeniedKid[]) => void = () => undefined;
    const listDenied = vi.fn(
      () =>
        new Promise<DeniedKid[]>((resolve) => {
          answer = resolve;
        })
    );
    const { store, redis } = fakeRedis();
    const load = keyDenylistLoader({ redis: () => redis, listDenied });
    // The first call gives up on its query, which runs on.
    const first = expect(load()).rejects.toThrow('did not answer in time');
    await vi.advanceTimersByTimeAsync(KEY_DENYLIST_STORE_TIMEOUT_MS);
    await first;
    await vi.advanceTimersByTimeAsync(1_000);
    // The next waits for it: what it answers is as old as the first call, so
    // it may lack a kid denied since.
    const second = load();
    expect(listDenied).toHaveBeenCalledTimes(1);
    answer([]);
    await expect(second).resolves.toEqual({
      entries: [],
      complete: true,
      ageMs: KEY_DENYLIST_STORE_TIMEOUT_MS + 1_000,
    });
    expect(store.has(KEY_DENYLIST_SNAPSHOT_KEY)).toBe(false);
    // The database is due a read interval after the query began, whatever
    // the snapshot holds, not a read interval after the call that waited.
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, JSON.stringify([]));
    await vi.advanceTimersByTimeAsync(
      KEY_DENYLIST_STORE_READ_INTERVAL_MS - KEY_DENYLIST_STORE_TIMEOUT_MS - 1_000
    );
    const third = load();
    expect(listDenied).toHaveBeenCalledTimes(2);
    answer(DENIED);
    await expect(third).resolves.toEqual({ entries: DENIED, complete: true });
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
  it('denies the retired kids on the copy at once, stores the database list as the snapshot over the old one, and reads the copy again', async () => {
    const { store, redis } = fakeRedis();
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, '[]');
    const listDenied = vi.fn(async () => DENIED);
    const denylist = { add: vi.fn(), refresh: vi.fn(async () => undefined) };
    await invalidateKeyDenylist(denylist, { redis: () => redis, listDenied }, fakeLog(), DENIED);
    expect(denylist.add).toHaveBeenCalledWith(DENIED);
    expect(store.get(KEY_DENYLIST_SNAPSHOT_KEY)).toBe(JSON.stringify(DENIED));
    expect(redis.set).toHaveBeenCalledWith(
      KEY_DENYLIST_SNAPSHOT_KEY,
      JSON.stringify(DENIED),
      'EX',
      KEY_DENYLIST_SNAPSHOT_TTL_SECONDS
    );
    expect(denylist.refresh).toHaveBeenCalledTimes(1);
    expect(denylist.add.mock.invocationCallOrder[0]).toBeLessThan(
      listDenied.mock.invocationCallOrder[0] ?? 0
    );
  });

  it('keeps the retired kids in the snapshot even if the read missed them', async () => {
    const { store, redis } = fakeRedis();
    const listDenied = vi.fn(async () => []);
    await invalidateKeyDenylist(null, { redis: () => redis, listDenied }, fakeLog(), DENIED);
    expect(store.get(KEY_DENYLIST_SNAPSHOT_KEY)).toBe(JSON.stringify(DENIED));
  });

  it('deletes the snapshot when the database cannot be read', async () => {
    const { store, redis } = fakeRedis();
    store.set(KEY_DENYLIST_SNAPSHOT_KEY, '[]');
    const listDenied = vi.fn(async (): Promise<DeniedKid[]> => {
      throw new Error('database down');
    });
    const log = fakeLog();
    await invalidateKeyDenylist(null, { redis: () => redis, listDenied }, log, DENIED);
    expect(store.has(KEY_DENYLIST_SNAPSHOT_KEY)).toBe(false);
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('logs, and does not throw, when Redis or the read fails', async () => {
    const log = fakeLog();
    const { redis } = fakeRedis({
      set: async () => {
        throw new Error('redis down');
      },
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
    await expect(
      invalidateKeyDenylist(
        denylist,
        { redis: () => redis, listDenied: async () => DENIED },
        log,
        DENIED
      )
    ).resolves.toBeUndefined();
    expect(denylist.add).toHaveBeenCalledWith(DENIED);
    expect(log.warn).toHaveBeenCalledTimes(2);
  });

  it('gives up on a read of the copy that does not end, so the session sweep runs', async () => {
    vi.useFakeTimers();
    const { redis } = fakeRedis();
    const denylist = { add: vi.fn(), refresh: vi.fn(() => new Promise<void>(() => undefined)) };
    const log = fakeLog();
    const done = invalidateKeyDenylist(
      denylist,
      { redis: () => redis, listDenied: async () => DENIED },
      log,
      DENIED
    );
    await vi.advanceTimersByTimeAsync(KEY_DENYLIST_STORE_TIMEOUT_MS);
    await expect(done).resolves.toBeUndefined();
    expect(log.warn).toHaveBeenCalledTimes(1);
  });
});
