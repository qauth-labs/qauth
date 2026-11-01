import { beforeEach, describe, expect, it } from 'vitest';

import type { BruteForcePolicy } from './account-policies';
import { recordSuccessfulLogin, registerLoginAttempt, resetFailedAttempts } from './failed-login';

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

/** The realm the logins are for. */
const REALM = '0190e3c4-0000-7000-8000-00000000000a';
/** Its brute-force policy (#528): three failures in 900 s lock for 900 s. */
const POLICY: BruteForcePolicy = Object.freeze({
  enabled: true,
  maxAttempts: 3,
  windowSeconds: 900,
  lockoutSeconds: 900,
});
// The helper only calls the methods above; cast through unknown for the test.
const asClient = (r: RedisStub) => r as unknown as Parameters<typeof registerLoginAttempt>[0];

describe('failed-login helper', () => {
  let redis: RedisStub;
  const ids = ['email:abc', 'ip:127.0.0.1'];

  beforeEach(() => {
    redis = createRedisStub();
  });

  it('is not locked out initially', async () => {
    const status = await registerLoginAttempt(asClient(redis), REALM, POLICY, ids);
    expect(status.locked).toBe(false);
  });

  it('lets the max attempts through, then refuses with retry-after', async () => {
    // max=3: three attempts are let through; the third arms the lockout on its
    // way in, so a fourth is refused before any password is looked at.
    for (let i = 0; i < 3; i++) {
      expect((await registerLoginAttempt(asClient(redis), REALM, POLICY, ids)).locked).toBe(false);
    }

    const status = await registerLoginAttempt(asClient(redis), REALM, POLICY, ids);
    expect(status.locked).toBe(true);
    expect(status.retryAfterSeconds).toBe(900);
  });

  it('lets no more than the max attempts through when they arrive concurrently', async () => {
    // ROIQJSAT: the lockout was check-then-act — every guess that arrived
    // before the threshold failure had been recorded got verified. With the
    // atomic INCR as the gate, exactly max attempts get through, whatever the
    // interleaving.
    const statuses = await Promise.all(
      Array.from({ length: 30 }, () => registerLoginAttempt(asClient(redis), REALM, POLICY, ids))
    );

    expect(statuses.filter((status) => !status.locked)).toHaveLength(3);
    for (const status of statuses.filter((status) => status.locked)) {
      expect(status.retryAfterSeconds).toBe(900);
    }
    // Refused attempts are not counted: the counters hold the three that ran.
    expect(redis._store.get(`failed-login:attempts:${REALM}:email:abc`)).toBe('3');
    expect(redis._store.get(`failed-login:attempts:${REALM}:ip:127.0.0.1`)).toBe('3');
  });

  it('caps one address across many accounts, and leaves no count on the refused accounts', async () => {
    const statuses = await Promise.all(
      Array.from({ length: 30 }, (_, i) =>
        registerLoginAttempt(asClient(redis), REALM, POLICY, [`email:user-${i}`, 'ip:127.0.0.1'])
      )
    );

    const passed = statuses.flatMap((status, i) => (status.locked ? [] : [i]));
    expect(passed).toHaveLength(3);
    for (let i = 0; i < 30; i++) {
      const count = redis._store.get(`failed-login:attempts:${REALM}:email:user-${i}`);
      // An attempt the address refused is withdrawn from its email too.
      expect(Number(count ?? '0')).toBe(passed.includes(i) ? 1 : 0);
    }
  });

  it('does not count an attempt that a locked-out identifier refuses', async () => {
    for (let i = 0; i < 3; i++) {
      await registerLoginAttempt(asClient(redis), REALM, POLICY, ['ip:127.0.0.1']);
    }

    expect((await registerLoginAttempt(asClient(redis), REALM, POLICY, ids)).locked).toBe(true);
    expect(redis._store.get(`failed-login:attempts:${REALM}:email:abc`)).toBeUndefined();
  });

  it('lets one attempt through per lockout once the lockout has expired inside the window', async () => {
    for (let i = 0; i < 3; i++) {
      await registerLoginAttempt(asClient(redis), REALM, POLICY, ids);
    }
    // The lockout markers expire while the attempt counters are still alive.
    await redis.del(
      `failed-login:lockout:${REALM}:email:abc`,
      `failed-login:lockout:${REALM}:ip:127.0.0.1`
    );

    expect((await registerLoginAttempt(asClient(redis), REALM, POLICY, ids)).locked).toBe(false);
    expect((await registerLoginAttempt(asClient(redis), REALM, POLICY, ids)).locked).toBe(true);
  });

  it('sets the window TTL on the first attempt', async () => {
    await registerLoginAttempt(asClient(redis), REALM, POLICY, ['email:only']);
    expect(redis._ttls.get(`failed-login:attempts:${REALM}:email:only`)).toBe(900);
  });

  it('resets counters and lockout on success', async () => {
    for (let i = 0; i < 3; i++) {
      await registerLoginAttempt(asClient(redis), REALM, POLICY, ids);
    }
    expect(redis._store.has(`failed-login:lockout:${REALM}:email:abc`)).toBe(true);

    await resetFailedAttempts(asClient(redis), REALM, POLICY, ids);

    // Counter keys are cleared.
    expect(redis._store.get(`failed-login:attempts:${REALM}:email:abc`)).toBeUndefined();
    expect((await registerLoginAttempt(asClient(redis), REALM, POLICY, ids)).locked).toBe(false);
  });

  describe('a successful login (GPU4YL6X)', () => {
    const ip = 'ip:127.0.0.1';

    it('clears the email it proved, and gives back only its own count on the address', async () => {
      // Two wrong guesses at other people's accounts from one address (max=3).
      await registerLoginAttempt(asClient(redis), REALM, POLICY, ['email:victim-1', ip]);
      await registerLoginAttempt(asClient(redis), REALM, POLICY, ['email:victim-2', ip]);

      // A login to the caller's own account succeeds. Registration is open,
      // so anyone can produce one: it must not wipe the address's failures.
      const own = await registerLoginAttempt(asClient(redis), REALM, POLICY, ['email:me', ip]);
      expect(own.locked).toBe(false);
      await recordSuccessfulLogin(asClient(redis), REALM, POLICY, own, ['email:me']);

      expect(redis._store.get(`failed-login:attempts:${REALM}:email:me`)).toBeUndefined();
      expect(redis._store.get(`failed-login:attempts:${REALM}:ip:127.0.0.1`)).toBe('2');
      // The own login reached the threshold and armed the address lockout on
      // its way in; as it did not fail, that lockout is lifted again.
      expect(redis._store.has(`failed-login:lockout:${REALM}:ip:127.0.0.1`)).toBe(false);

      // One more guess is the third failure; the address is then locked.
      expect(
        (await registerLoginAttempt(asClient(redis), REALM, POLICY, ['email:victim-3', ip])).locked
      ).toBe(false);
      expect(
        (await registerLoginAttempt(asClient(redis), REALM, POLICY, ['email:victim-4', ip])).locked
      ).toBe(true);
    });

    it('never counts against a shared address, however many there are', async () => {
      // An office NAT: many people sign in successfully from one address.
      for (let i = 0; i < 10; i++) {
        const attempt = await registerLoginAttempt(asClient(redis), REALM, POLICY, [
          `email:user-${i}`,
          ip,
        ]);
        expect(attempt.locked).toBe(false);
        await recordSuccessfulLogin(asClient(redis), REALM, POLICY, attempt, [`email:user-${i}`]);
      }

      expect(redis._store.get(`failed-login:attempts:${REALM}:ip:127.0.0.1`)).toBe('0');
      expect(redis._store.has(`failed-login:lockout:${REALM}:ip:127.0.0.1`)).toBe(false);
    });

    it('keeps an address lockout armed by another attempt', async () => {
      // Three failures lock the address while this login was in flight.
      const own = await registerLoginAttempt(asClient(redis), REALM, POLICY, ['email:me', ip]);
      for (let i = 0; i < 2; i++) {
        await registerLoginAttempt(asClient(redis), REALM, POLICY, [`email:victim-${i}`, ip]);
      }
      expect(redis._store.has(`failed-login:lockout:${REALM}:ip:127.0.0.1`)).toBe(true);

      await recordSuccessfulLogin(asClient(redis), REALM, POLICY, own, ['email:me']);

      expect(redis._store.has(`failed-login:lockout:${REALM}:ip:127.0.0.1`)).toBe(true);
    });

    it('does not leave a counter without a TTL when the window expired meanwhile', async () => {
      const own = await registerLoginAttempt(asClient(redis), REALM, POLICY, ['email:me', ip]);
      await redis.del(`failed-login:attempts:${REALM}:ip:127.0.0.1`);

      await recordSuccessfulLogin(asClient(redis), REALM, POLICY, own, ['email:me']);

      expect(redis._store.has(`failed-login:attempts:${REALM}:ip:127.0.0.1`)).toBe(false);
    });
  });

  it('fails open when Redis throws', async () => {
    const broken = {
      async ttl() {
        throw new Error('redis down');
      },
    } as unknown as Parameters<typeof registerLoginAttempt>[0];
    const status = await registerLoginAttempt(broken, REALM, POLICY, ids);
    expect(status.locked).toBe(false);
  });

  describe('per realm (#487)', () => {
    const OTHER_REALM = '0190e3c4-0000-7000-8000-00000000000b';

    it('keys the same identifiers apart in two realms', async () => {
      await registerLoginAttempt(asClient(redis), REALM, POLICY, ids);
      await registerLoginAttempt(asClient(redis), OTHER_REALM, POLICY, ids);

      expect(redis._store.get(`failed-login:attempts:${REALM}:email:abc`)).toBe('1');
      expect(redis._store.get(`failed-login:attempts:${OTHER_REALM}:email:abc`)).toBe('1');
    });

    it('locks out an account in one realm and not the same address in another', async () => {
      for (let i = 0; i < 3; i++) {
        await registerLoginAttempt(asClient(redis), REALM, POLICY, ids);
      }

      expect((await registerLoginAttempt(asClient(redis), REALM, POLICY, ids)).locked).toBe(true);
      expect((await registerLoginAttempt(asClient(redis), OTHER_REALM, POLICY, ids)).locked).toBe(
        false
      );
    });

    it('settles a success in its own realm only', async () => {
      await registerLoginAttempt(asClient(redis), OTHER_REALM, POLICY, ['email:me']);
      const own = await registerLoginAttempt(asClient(redis), REALM, POLICY, ['email:me']);

      await recordSuccessfulLogin(asClient(redis), REALM, POLICY, own, ['email:me']);

      expect(redis._store.has(`failed-login:attempts:${REALM}:email:me`)).toBe(false);
      expect(redis._store.get(`failed-login:attempts:${OTHER_REALM}:email:me`)).toBe('1');
    });
  });

  describe("the realm's brute-force policy (#528)", () => {
    const OTHER_REALM = '0190e3c4-0000-7000-8000-00000000000b';
    const OFF: BruteForcePolicy = Object.freeze({ ...POLICY, enabled: false });

    it("counts with the policy's window, threshold and lockout time", async () => {
      const policy: BruteForcePolicy = {
        enabled: true,
        maxAttempts: 2,
        windowSeconds: 60,
        lockoutSeconds: 30,
      };

      await registerLoginAttempt(asClient(redis), REALM, policy, ids);
      expect(redis._ttls.get(`failed-login:attempts:${REALM}:email:abc`)).toBe(60);
      expect((await registerLoginAttempt(asClient(redis), REALM, policy, ids)).locked).toBe(false);
      expect(redis._ttls.get(`failed-login:lockout:${REALM}:email:abc`)).toBe(30);

      expect(await registerLoginAttempt(asClient(redis), REALM, policy, ids)).toEqual({
        locked: true,
        retryAfterSeconds: 30,
      });
    });

    it('never locks, nor counts, in a realm whose policy is off', async () => {
      for (let i = 0; i < 50; i++) {
        expect(await registerLoginAttempt(asClient(redis), REALM, OFF, ids)).toEqual({
          locked: false,
        });
      }

      expect(redis._store.size).toBe(0);
    });

    it('stops reading a lockout armed before the realm switched its policy off', async () => {
      for (let i = 0; i < 3; i++) {
        await registerLoginAttempt(asClient(redis), REALM, POLICY, ids);
      }
      expect((await registerLoginAttempt(asClient(redis), REALM, POLICY, ids)).locked).toBe(true);

      expect((await registerLoginAttempt(asClient(redis), REALM, OFF, ids)).locked).toBe(false);
    });

    it('clears nothing on a success in a realm whose policy is off', async () => {
      for (let i = 0; i < 2; i++) {
        await registerLoginAttempt(asClient(redis), REALM, POLICY, ids);
      }

      await recordSuccessfulLogin(asClient(redis), REALM, OFF, { locked: false }, ['email:abc']);
      await resetFailedAttempts(asClient(redis), REALM, OFF, ids);

      expect(redis._store.get(`failed-login:attempts:${REALM}:email:abc`)).toBe('2');
    });

    it("locks each realm by its own policy: one realm's failures never lock the same identifier in another", async () => {
      const strict: BruteForcePolicy = { ...POLICY, maxAttempts: 1 };
      const lax: BruteForcePolicy = { ...POLICY, maxAttempts: 10 };

      expect((await registerLoginAttempt(asClient(redis), REALM, strict, ids)).locked).toBe(false);
      expect((await registerLoginAttempt(asClient(redis), REALM, strict, ids)).locked).toBe(true);
      for (let i = 0; i < 10; i++) {
        expect((await registerLoginAttempt(asClient(redis), OTHER_REALM, lax, ids)).locked).toBe(
          false
        );
      }
      expect((await registerLoginAttempt(asClient(redis), OTHER_REALM, lax, ids)).locked).toBe(
        true
      );
    });
  });
});
