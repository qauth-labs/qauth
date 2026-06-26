import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    FAILED_LOGIN_TRACKING_ENABLED: true,
    FAILED_LOGIN_MAX_ATTEMPTS: 3,
    FAILED_LOGIN_WINDOW: 900,
    FAILED_LOGIN_LOCKOUT_DURATION: 900,
  },
}));

import { checkLockout, recordFailedAttempt, resetFailedAttempts } from './failed-login';

/**
 * Minimal in-memory Redis stub covering the ioredis surface the helper uses:
 * incr, expire, ttl, set (with EX), del.
 */
function createRedisStub() {
  const store = new Map<string, string>();
  const ttls = new Map<string, number>();
  return {
    async incr(key: string): Promise<number> {
      const next = Number(store.get(key) ?? '0') + 1;
      store.set(key, String(next));
      return next;
    },
    async expire(key: string, seconds: number): Promise<number> {
      if (!store.has(key)) return 0;
      ttls.set(key, seconds);
      return 1;
    },
    async ttl(key: string): Promise<number> {
      return ttls.get(key) ?? -2;
    },
    async set(key: string, value: string, _ex: 'EX', seconds: number): Promise<'OK'> {
      store.set(key, value);
      ttls.set(key, seconds);
      return 'OK';
    },
    async del(...keys: string[]): Promise<number> {
      let count = 0;
      for (const key of keys) {
        if (store.delete(key)) count++;
        ttls.delete(key);
      }
      return count;
    },
    // Inspection helpers for assertions.
    _store: store,
    _ttls: ttls,
  };
}

type RedisStub = ReturnType<typeof createRedisStub>;
// The helper only calls the methods above; cast through unknown for the test.
const asClient = (r: RedisStub) => r as unknown as Parameters<typeof checkLockout>[0];

describe('failed-login helper', () => {
  let redis: RedisStub;
  const ids = ['email:abc', 'ip:127.0.0.1'];

  beforeEach(() => {
    redis = createRedisStub();
  });

  it('is not locked out initially', async () => {
    const status = await checkLockout(asClient(redis), ids);
    expect(status.locked).toBe(false);
  });

  it('locks out after reaching the max attempts and reports retry-after', async () => {
    // 2 failures: below threshold (max=3).
    expect((await recordFailedAttempt(asClient(redis), ids)).lockedOut).toBe(false);
    expect((await recordFailedAttempt(asClient(redis), ids)).lockedOut).toBe(false);
    expect((await checkLockout(asClient(redis), ids)).locked).toBe(false);

    // 3rd failure trips the lockout.
    expect((await recordFailedAttempt(asClient(redis), ids)).lockedOut).toBe(true);

    const status = await checkLockout(asClient(redis), ids);
    expect(status.locked).toBe(true);
    expect(status.retryAfterSeconds).toBe(900);
  });

  it('sets the window TTL on the first failure', async () => {
    await recordFailedAttempt(asClient(redis), ['email:only']);
    expect(redis._ttls.get('failed-login:attempts:email:only')).toBe(900);
  });

  it('resets counters and lockout on success', async () => {
    for (let i = 0; i < 3; i++) {
      await recordFailedAttempt(asClient(redis), ids);
    }
    expect((await checkLockout(asClient(redis), ids)).locked).toBe(true);

    await resetFailedAttempts(asClient(redis), ids);

    expect((await checkLockout(asClient(redis), ids)).locked).toBe(false);
    // Counter keys are cleared.
    expect(redis._store.get('failed-login:attempts:email:abc')).toBeUndefined();
  });

  it('fails open when Redis throws', async () => {
    const broken = {
      async ttl() {
        throw new Error('redis down');
      },
    } as unknown as Parameters<typeof checkLockout>[0];
    const status = await checkLockout(broken, ids);
    expect(status.locked).toBe(false);
  });
});
