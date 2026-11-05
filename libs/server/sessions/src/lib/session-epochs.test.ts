import { describe, expect, it, vi } from 'vitest';

import {
  createSessionEpochs,
  sessionEpochCacheKey,
  type SessionEpochRedisClient,
  type SessionEpochStore,
} from './session-epochs';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const OWNER = { realmId: REALM, userId: USER };
const KEY = sessionEpochCacheKey(REALM, USER);

/** A Redis of plain strings that keeps every SET it was sent, NX included; TTLs are recorded, not kept. */
function memoryRedis() {
  const values = new Map<string, string>();
  const sets: { key: string; value: string; ttlMs: number; nx: boolean }[] = [];
  const redis = {
    get: vi.fn(async (key: string) => values.get(key) ?? null),
    set: vi.fn(async (key: string, value: string, _mode: 'PX', ttlMs: number, nx?: 'NX') => {
      sets.push({ key, value, ttlMs, nx: nx === 'NX' });
      if (nx === 'NX' && values.has(key)) return null;
      values.set(key, value);
      return 'OK';
    }),
  };
  return { redis: redis as SessionEpochRedisClient & typeof redis, values, sets };
}

function storeOf(rows: Map<string, number>) {
  const store = {
    find: vi.fn(async (realmId: string, userId: string) => {
      expect(realmId).toBe(REALM);
      const advancedAt = rows.get(userId);
      return advancedAt === undefined ? undefined : { advancedAt };
    }),
  };
  return store satisfies SessionEpochStore;
}

const logger = () => ({ warn: vi.fn() });

describe('createSessionEpochs', () => {
  it('reads Postgres on a miss, fills the cache only where it is empty, then answers from it', async () => {
    const { redis, sets } = memoryRedis();
    const store = storeOf(new Map([[USER, 1_000]]));
    const epochs = createSessionEpochs({ store, redis, logger: logger() });

    await expect(epochs.lastReset(OWNER)).resolves.toBe(1_000);
    await expect(epochs.lastReset(OWNER)).resolves.toBe(1_000);

    expect(store.find).toHaveBeenCalledTimes(1);
    expect(sets).toEqual([
      { key: KEY, value: JSON.stringify({ v: 1, advancedAt: 1_000 }), ttlMs: 60_000, nx: true },
    ]);
  });

  it('caches a user never reset as null', async () => {
    const { redis, values } = memoryRedis();
    const store = storeOf(new Map());
    const epochs = createSessionEpochs({ store, redis, logger: logger(), cacheTtlSeconds: 5 });

    await expect(epochs.lastReset(OWNER)).resolves.toBeNull();
    await expect(epochs.lastReset(OWNER)).resolves.toBeNull();

    expect(store.find).toHaveBeenCalledTimes(1);
    expect(values.get(KEY)).toBe(JSON.stringify({ v: 1, advancedAt: null }));
  });

  it('publishes a reset over a cached value, and a late fill does not take it back', async () => {
    const { redis } = memoryRedis();
    const rows = new Map<string, number>();
    const store = storeOf(rows);
    const epochs = createSessionEpochs({ store, redis, logger: logger() });
    await epochs.lastReset(OWNER);

    rows.set(USER, 2_000);
    await epochs.publish({ ...OWNER, advancedAt: 2_000 });
    await expect(epochs.lastReset(OWNER)).resolves.toBe(2_000);

    // A fill that read Postgres before the reset committed writes after the publish.
    await redis.set(KEY, JSON.stringify({ v: 1, advancedAt: null }), 'PX', 60_000, 'NX');
    await expect(epochs.lastReset(OWNER)).resolves.toBe(2_000);
  });

  it('reads Postgres when the cache fails or hangs, and when its value is not an epoch', async () => {
    for (const fault of ['fails', 'hangs', 'garbage'] as const) {
      const { redis, values } = memoryRedis();
      if (fault === 'fails') redis.get.mockRejectedValueOnce(new Error('redis down'));
      if (fault === 'hangs') redis.get.mockReturnValueOnce(new Promise(() => undefined));
      if (fault === 'garbage') values.set(KEY, JSON.stringify({ v: 1, advancedAt: 'soon' }));
      const store = storeOf(new Map([[USER, 3_000]]));
      const log = logger();
      const epochs = createSessionEpochs({ store, redis, logger: log, cacheTimeoutMs: 5 });

      await expect(epochs.lastReset(OWNER), fault).resolves.toBe(3_000);
      expect(store.find, fault).toHaveBeenCalledTimes(1);
      expect(log.warn.mock.calls.length > 0, fault).toBe(fault !== 'garbage');
    }
  });

  it('answers from Postgres when the fill fails', async () => {
    const { redis } = memoryRedis();
    redis.set.mockRejectedValueOnce(new Error('redis down'));
    const log = logger();
    const epochs = createSessionEpochs({
      store: storeOf(new Map([[USER, 4_000]])),
      redis,
      logger: log,
    });

    await expect(epochs.lastReset(OWNER)).resolves.toBe(4_000);
    expect(log.warn).toHaveBeenCalledWith(expect.anything(), 'Session epoch cache fill failed');
  });

  it('throws when Postgres fails or holds no time: never a session it could not check', async () => {
    const { redis } = memoryRedis();
    const failing = { find: vi.fn(async () => Promise.reject(new Error('postgres down'))) };
    await expect(
      createSessionEpochs({ store: failing, redis, logger: logger() }).lastReset(OWNER)
    ).rejects.toThrow('postgres down');
    const corrupt = storeOf(new Map([[USER, Number.NaN]]));
    await expect(
      createSessionEpochs({ store: corrupt, redis, logger: logger() }).lastReset(OWNER)
    ).rejects.toThrow(/not a time/);
  });

  it('refuses to publish what is not a time, and rejects when Redis fails', async () => {
    const { redis } = memoryRedis();
    const epochs = createSessionEpochs({ store: storeOf(new Map()), redis, logger: logger() });
    await expect(epochs.publish({ ...OWNER, advancedAt: 0 })).rejects.toThrow(/positive time/);
    redis.set.mockRejectedValueOnce(new Error('redis down'));
    await expect(epochs.publish({ ...OWNER, advancedAt: 5_000 })).rejects.toThrow('redis down');
  });

  it('keys the cache by realm and user, with the user as the hash tag', () => {
    expect(sessionEpochCacheKey(REALM, USER)).toBe(`session-epoch:${REALM}:{${USER}}`);
  });
});
