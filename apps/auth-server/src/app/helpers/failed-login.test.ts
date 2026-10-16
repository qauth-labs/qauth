import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    FAILED_LOGIN_TRACKING_ENABLED: true,
    FAILED_LOGIN_MAX_ATTEMPTS: 3,
    FAILED_LOGIN_WINDOW: 900,
    FAILED_LOGIN_LOCKOUT_DURATION: 900,
  },
}));

import { registerLoginAttempt, resetFailedAttempts } from './failed-login';

/**
 * Minimal in-memory Redis stub covering the ioredis surface the helper uses:
 * incr, decr, expire, ttl, set (with EX and optional NX), del.
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
    async decr(key: string): Promise<number> {
      const next = Number(store.get(key) ?? '0') - 1;
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
    async set(
      key: string,
      value: string,
      _ex: 'EX',
      seconds: number,
      nx?: 'NX'
    ): Promise<'OK' | null> {
      if (nx === 'NX' && store.has(key)) return null;
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
const asClient = (r: RedisStub) => r as unknown as Parameters<typeof registerLoginAttempt>[0];

describe('failed-login helper', () => {
  let redis: RedisStub;
  const ids = ['email:abc', 'ip:127.0.0.1'];

  beforeEach(() => {
    redis = createRedisStub();
  });

  it('is not locked out initially', async () => {
    const status = await registerLoginAttempt(asClient(redis), ids);
    expect(status.locked).toBe(false);
  });

  it('lets the max attempts through, then refuses with retry-after', async () => {
    // max=3: three attempts are let through; the third arms the lockout on its
    // way in, so a fourth is refused before any password is looked at.
    for (let i = 0; i < 3; i++) {
      expect((await registerLoginAttempt(asClient(redis), ids)).locked).toBe(false);
    }

    const status = await registerLoginAttempt(asClient(redis), ids);
    expect(status.locked).toBe(true);
    expect(status.retryAfterSeconds).toBe(900);
  });

  it('lets no more than the max attempts through when they arrive concurrently', async () => {
    // ROIQJSAT: the lockout was check-then-act — every guess that arrived
    // before the threshold failure had been recorded got verified. With the
    // atomic INCR as the gate, exactly max attempts get through, whatever the
    // interleaving.
    const statuses = await Promise.all(
      Array.from({ length: 30 }, () => registerLoginAttempt(asClient(redis), ids))
    );

    expect(statuses.filter((status) => !status.locked)).toHaveLength(3);
    for (const status of statuses.filter((status) => status.locked)) {
      expect(status.retryAfterSeconds).toBe(900);
    }
    // Refused attempts are not counted: the counters hold the three that ran.
    expect(redis._store.get('failed-login:attempts:email:abc')).toBe('3');
    expect(redis._store.get('failed-login:attempts:ip:127.0.0.1')).toBe('3');
  });

  it('caps one address across many accounts, and leaves no count on the refused accounts', async () => {
    const statuses = await Promise.all(
      Array.from({ length: 30 }, (_, i) =>
        registerLoginAttempt(asClient(redis), [`email:user-${i}`, 'ip:127.0.0.1'])
      )
    );

    const passed = statuses.flatMap((status, i) => (status.locked ? [] : [i]));
    expect(passed).toHaveLength(3);
    for (let i = 0; i < 30; i++) {
      const count = redis._store.get(`failed-login:attempts:email:user-${i}`);
      // An attempt the address refused is withdrawn from its email too.
      expect(Number(count ?? '0')).toBe(passed.includes(i) ? 1 : 0);
    }
  });

  it('does not count an attempt that a locked-out identifier refuses', async () => {
    for (let i = 0; i < 3; i++) {
      await registerLoginAttempt(asClient(redis), ['ip:127.0.0.1']);
    }

    expect((await registerLoginAttempt(asClient(redis), ids)).locked).toBe(true);
    expect(redis._store.get('failed-login:attempts:email:abc')).toBeUndefined();
  });

  it('lets one attempt through per lockout once the lockout has expired inside the window', async () => {
    for (let i = 0; i < 3; i++) {
      await registerLoginAttempt(asClient(redis), ids);
    }
    // The lockout markers expire while the attempt counters are still alive.
    await redis.del('failed-login:lockout:email:abc', 'failed-login:lockout:ip:127.0.0.1');

    expect((await registerLoginAttempt(asClient(redis), ids)).locked).toBe(false);
    expect((await registerLoginAttempt(asClient(redis), ids)).locked).toBe(true);
  });

  it('sets the window TTL on the first attempt', async () => {
    await registerLoginAttempt(asClient(redis), ['email:only']);
    expect(redis._ttls.get('failed-login:attempts:email:only')).toBe(900);
  });

  it('resets counters and lockout on success', async () => {
    for (let i = 0; i < 3; i++) {
      await registerLoginAttempt(asClient(redis), ids);
    }
    expect(redis._store.has('failed-login:lockout:email:abc')).toBe(true);

    await resetFailedAttempts(asClient(redis), ids);

    // Counter keys are cleared.
    expect(redis._store.get('failed-login:attempts:email:abc')).toBeUndefined();
    expect((await registerLoginAttempt(asClient(redis), ids)).locked).toBe(false);
  });

  it('fails open when Redis throws', async () => {
    const broken = {
      async ttl() {
        throw new Error('redis down');
      },
    } as unknown as Parameters<typeof registerLoginAttempt>[0];
    const status = await registerLoginAttempt(broken, ids);
    expect(status.locked).toBe(false);
  });
});
