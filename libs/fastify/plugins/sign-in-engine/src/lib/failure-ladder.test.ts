import { createHash, createHmac } from 'node:crypto';

import {
  type LadderPolicy,
  type LadderReservation,
  type LadderVerdict,
  PASSWORD_LADDER_POLICY,
} from '@qauth-labs/server-sign-in-engine';
import { describe, expect, it, vi } from 'vitest';

import {
  createRedisFailureLadder,
  LADDER_MAX_KNOWN_IPS,
  ladderCounterKey,
  ladderKnownIpsKey,
  type LadderRedis,
  RESERVE_SCRIPT,
  RESERVE_SCRIPT_SHA,
  SETTLE_SUCCESS_SCRIPT,
  SETTLE_SUCCESS_SCRIPT_SHA,
} from './failure-ladder';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const IDENTIFIER = 'alice@example.com';
const IP = '203.0.113.7';
const OTHER_IP = '198.51.100.9';

/** A keyed HMAC as the digests make it: base64url, never the input. */
const hmacOf = (label: string, value: string) =>
  createHmac('sha256', `key:${label}`).update(`${REALM}\u0000${value}`).digest('base64url');
const IDENTIFIER_HMAC = hmacOf('identifier', IDENTIFIER);
const ipDigest = vi.fn(async ({ identifier }: { realmId: string; identifier: string }) =>
  hmacOf('ip', identifier)
);

/**
 * Redis in memory, for the two scripts and the two plain commands the ladder
 * sends. The scripts are modelled on their Lua (Redis runs Lua 5.1): every
 * value is stored as a string, every number a script returns is an integer
 * reply. The container suite runs the Lua itself.
 */
class FakeRedis implements LadderRedis {
  readonly hashes = new Map<string, Map<string, string>>();
  readonly sets = new Map<string, Map<string, number>>();
  readonly expiries = new Map<string, number>();
  /** Every key and argument the ladder sent, in order. */
  readonly sent: string[] = [];
  readonly loaded = new Set<string>();

  constructor(private readonly now: () => number) {}

  /** Drop `key` once its expiry passed, as Redis does on access. */
  expire(key: string) {
    const at = this.expiries.get(key);
    if (at !== undefined && at <= this.now()) {
      this.hashes.delete(key);
      this.sets.delete(key);
      this.expiries.delete(key);
    }
  }

  private record(args: readonly (string | number)[]) {
    for (const arg of args) this.sent.push(String(arg));
  }

  async evalsha(sha: string, numKeys: number, ...args: (string | number)[]): Promise<unknown> {
    this.record(args);
    if (!this.loaded.has(sha)) throw new Error('NOSCRIPT No matching script. Please use EVAL.');
    return this.run(sha, args.slice(0, numKeys).map(String), args.slice(numKeys).map(String));
  }

  async eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown> {
    this.record(args);
    const sha = createHash('sha1').update(script).digest('hex');
    this.loaded.add(sha);
    return this.run(sha, args.slice(0, numKeys).map(String), args.slice(numKeys).map(String));
  }

  async hget(key: string, field: string): Promise<string | null> {
    this.record([key, field]);
    this.expire(key);
    return this.hashes.get(key)?.get(field) ?? null;
  }

  async del(...keys: string[]): Promise<number> {
    this.record(keys);
    let removed = 0;
    for (const key of keys) {
      this.expire(key);
      if (this.hashes.delete(key) || this.sets.delete(key)) removed += 1;
      this.expiries.delete(key);
    }
    return removed;
  }

  private run(sha: string, keys: string[], argv: string[]): unknown {
    for (const key of keys) this.expire(key);
    if (sha === RESERVE_SCRIPT_SHA) return this.reserve(keys, argv);
    if (sha === SETTLE_SUCCESS_SCRIPT_SHA) return this.settleSuccess(keys, argv);
    throw new Error('ERR unknown script');
  }

  private reserve([counter, known]: string[], argv: string[]): unknown {
    const [now, free, first, longest, retention, knownMs] = argv.slice(0, 6).map(Number);
    const ip = argv[6];
    let exempt = false;
    if (knownMs > 0 && ip !== '') {
      const seen = this.sets.get(known)?.get(ip);
      if (seen !== undefined && now - seen < knownMs) exempt = true;
    }
    const state = this.hashes.get(counter);
    let n = Number(state?.get('n') ?? 0);
    const waitUntil = Number(state?.get('until') ?? 0);
    const run = state?.get('run') ?? argv[7];
    if (!exempt && waitUntil > now) return [0, Math.trunc(waitUntil - now)];
    n += 1;
    let wait = 0;
    if (n >= free) {
      const doublings = n - free;
      wait = doublings >= 40 ? longest : Math.min(first * 2 ** doublings, longest);
    }
    const nextUntil = Math.max(now + wait, waitUntil);
    this.hashes.set(
      counter,
      new Map([
        ['n', String(n)],
        ['until', String(nextUntil)],
        ['run', run],
      ])
    );
    this.expiries.set(counter, now + retention);
    return [1, n, run];
  }

  private settleSuccess([counter, known]: string[], argv: string[]): unknown {
    const now = Number(argv[0]);
    if (argv[1] === 'clear') {
      this.hashes.delete(counter);
      this.expiries.delete(counter);
    } else if (this.hashes.get(counter)?.get('run') === argv[2]) {
      const state = this.hashes.get(counter) as Map<string, string>;
      const n = Number(state.get('n')) - 1;
      state.set('n', String(n));
      if (n <= 0) {
        this.hashes.delete(counter);
        this.expiries.delete(counter);
      }
    }
    const knownMs = Number(argv[3]);
    if (knownMs > 0 && argv[4] !== '') {
      const set = this.sets.get(known) ?? new Map<string, number>();
      set.set(argv[4], now);
      for (const [member, score] of set) if (score <= now - knownMs) set.delete(member);
      const excess = set.size - Number(argv[5]);
      if (excess > 0) {
        const oldest = [...set].sort((a, b) => a[1] - b[1]).slice(0, excess);
        for (const [member] of oldest) set.delete(member);
      }
      this.sets.set(known, set);
      this.expiries.set(known, now + knownMs);
    }
    return 1;
  }
}

function setup(policy: LadderPolicy = PASSWORD_LADDER_POLICY) {
  let clock = Date.UTC(2026, 10, 1);
  const now = () => clock;
  const redis = new FakeRedis(now);
  const ladder = createRedisFailureLadder(redis, {
    ipDigest,
    now,
    policies: { password: policy },
  });
  const attempt = (endUserIp: string | undefined = IP): Promise<LadderVerdict> =>
    ladder.reserve({
      realmId: REALM,
      identifierHmac: IDENTIFIER_HMAC,
      factor: 'password',
      ...(endUserIp === undefined ? {} : { endUserIp }),
    });
  const reserved = async (endUserIp?: string): Promise<LadderReservation> => {
    const verdict = await attempt(endUserIp);
    if (verdict.kind !== 'reserved') throw new Error(`expected a reservation, got ${verdict.kind}`);
    return verdict;
  };
  const fail = async (times: number, endUserIp?: string) => {
    const settled = [];
    for (let i = 0; i < times; i += 1) {
      settled.push(await (await reserved(endUserIp)).settle('failure'));
    }
    return settled;
  };
  const counter = () => {
    const key = ladderCounterKey(REALM, IDENTIFIER_HMAC, 'password');
    redis.expire(key);
    return redis.hashes.get(key);
  };
  return {
    redis,
    ladder,
    attempt,
    reserved,
    fail,
    counter,
    advance: (ms: number) => {
      clock += ms;
    },
    now,
  };
}

describe('the Redis failure ladder', () => {
  it('lets 5 consecutive failures through, then makes the next attempt wait 2^(n-5) seconds', async () => {
    const { attempt, fail, advance, counter } = setup();
    await fail(4);
    expect(await attempt()).toMatchObject({ kind: 'reserved' });
    // The 5th failure set a 1 s wait: the 6th attempt is refused, and not counted.
    expect(await attempt()).toEqual({ kind: 'wait', retryAfterSeconds: 1 });
    expect(counter()?.get('n')).toBe('5');
    advance(1_000);
    await fail(1);
    expect(await attempt()).toEqual({ kind: 'wait', retryAfterSeconds: 2 });
    advance(2_000);
    await fail(1);
    expect(await attempt()).toEqual({ kind: 'wait', retryAfterSeconds: 4 });
    expect(counter()?.get('n')).toBe('7');
  });

  it('caps the wait at 15 minutes', async () => {
    const { attempt, fail, advance } = setup();
    for (let n = 1; n <= 20; n += 1) {
      await fail(1);
      advance(15 * 60_000);
    }
    await fail(1);
    expect(await attempt()).toEqual({ kind: 'wait', retryAfterSeconds: 15 * 60 });
  });

  it('counts parallel attempts one at a time: past the free failures every one waits', async () => {
    const { attempt } = setup();
    const verdicts = await Promise.all(Array.from({ length: 50 }, () => attempt()));
    expect(verdicts.filter((verdict) => verdict.kind === 'reserved')).toHaveLength(5);
  });

  it('clears the password counter on a success and touches no other key', async () => {
    const { redis, fail, reserved, counter } = setup();
    const otp = ladderCounterKey(REALM, IDENTIFIER_HMAC, 'totp');
    redis.hashes.set(otp, new Map([['n', '3']]));
    await fail(3);
    const success = await reserved();
    await success.settle('success');
    expect(counter()).toBeUndefined();
    expect(redis.hashes.get(otp)?.get('n')).toBe('3');
    expect([...redis.sets.keys()]).toEqual([ladderKnownIpsKey(REALM, IDENTIFIER_HMAC)]);
  });

  it('lets a known IP skip the wait while every attempt still counts toward the ceiling', async () => {
    const { attempt, fail, reserved, counter } = setup();
    await (await reserved(IP)).settle('success');
    const settled = await fail(99, IP);
    expect(counter()?.get('n')).toBe('99');
    expect(settled.every((result) => !result.ceilingReached)).toBe(true);
    // Another IP still waits.
    expect(await attempt(OTHER_IP)).toMatchObject({ kind: 'wait' });
    const [hundredth] = await fail(1, IP);
    expect(hundredth).toEqual({ ceilingReached: true });
  });

  it('forgets a known IP after 30 days', async () => {
    const { attempt, fail, reserved, advance } = setup();
    await (await reserved(IP)).settle('success');
    advance(30 * 86_400_000);
    await fail(5, IP);
    expect(await attempt(IP)).toMatchObject({ kind: 'wait' });
  });

  it('keeps at most 16 known IPs, the most recent', async () => {
    const { redis, reserved, advance } = setup();
    for (let i = 0; i < LADDER_MAX_KNOWN_IPS + 4; i += 1) {
      await (await reserved(`192.0.2.${i}`)).settle('success');
      advance(1_000);
    }
    const known = redis.sets.get(ladderKnownIpsKey(REALM, IDENTIFIER_HMAC));
    expect(known?.size).toBe(LADDER_MAX_KNOWN_IPS);
    expect(known?.has(hmacOf('ip', '192.0.2.0'))).toBe(false);
    expect(known?.has(hmacOf('ip', `192.0.2.${LADDER_MAX_KNOWN_IPS + 3}`))).toBe(true);
  });

  it('says the hard action is due at the 100th counted failure and every one after it', async () => {
    const { fail, advance } = setup();
    const settled: { ceilingReached: boolean }[] = [];
    for (let n = 1; n <= 101; n += 1) {
      settled.push(...(await fail(1)));
      advance(15 * 60_000);
    }
    expect(settled.slice(0, 99).every((result) => !result.ceilingReached)).toBe(true);
    expect(settled[99]).toEqual({ ceilingReached: true });
    expect(settled[100]).toEqual({ ceilingReached: true });
  });

  it('says nothing is due for a failure whose run a success ended meanwhile', async () => {
    const { fail, reserved } = setup();
    // From a known IP, so no wait holds the attempts back.
    await (await reserved(IP)).settle('success');
    await fail(99, IP);
    const hundredth = await reserved(IP);
    // The owner signs in before the 100th attempt settles: the run ends.
    await (await reserved(IP)).settle('success');
    expect(await hundredth.settle('failure')).toEqual({ ceilingReached: false });
  });

  it('takes the attempt back on a success for a counter of failures alone', async () => {
    const { fail, reserved, counter } = setup({ ...PASSWORD_LADDER_POLICY, onSuccess: 'withdraw' });
    await fail(3);
    await (await reserved()).settle('success');
    expect(counter()?.get('n')).toBe('3');
  });

  it('ends a run 30 days after its last counted failure', async () => {
    const { attempt, fail, advance, counter } = setup();
    await fail(5);
    advance(30 * 86_400_000);
    expect(counter()).toBeUndefined();
    expect(await attempt()).toMatchObject({ kind: 'reserved' });
  });

  it('keeps no address in a key or an argument, nor its unkeyed SHA-256', async () => {
    const { redis, fail, reserved, attempt, ladder } = setup();
    await (await reserved(IP)).settle('success');
    await fail(5, OTHER_IP);
    expect(await attempt(OTHER_IP)).toMatchObject({ kind: 'wait' });
    await ladder.reset({ realmId: REALM, identifierHmac: IDENTIFIER_HMAC, factor: 'password' });
    const forbidden = [IDENTIFIER, 'alice', IP, OTHER_IP].flatMap((value) => [
      value,
      createHash('sha256').update(value).digest('hex'),
      createHash('sha256').update(value).digest('base64url'),
    ]);
    const stored = [
      ...redis.hashes.keys(),
      ...redis.sets.keys(),
      ...[...redis.sets.values()].flatMap((set) => [...set.keys()]),
      ...[...redis.hashes.values()].flatMap((hash) => [...hash.values()]),
    ];
    expect(redis.sent.length).toBeGreaterThan(0);
    for (const text of [...redis.sent, ...stored]) {
      for (const value of forbidden) expect(text).not.toContain(value);
    }
    // Keys are the realm and the HMAC, in one hash slot per account.
    expect(ladderCounterKey(REALM, IDENTIFIER_HMAC, 'password')).toBe(
      `sign-in-ladder:{${REALM}:${IDENTIFIER_HMAC}}:password`
    );
  });

  it('loads a script Redis does not hold with the call itself', async () => {
    const { redis, attempt } = setup();
    const evalSpy = vi.spyOn(redis, 'eval');
    await attempt();
    await attempt();
    expect(evalSpy).toHaveBeenCalledTimes(1);
    expect(evalSpy.mock.calls[0][0]).toBe(RESERVE_SCRIPT);
    expect(SETTLE_SUCCESS_SCRIPT).toContain("redis.call('ZADD'");
  });

  it('fails closed: an error, a timeout or an answer out of shape rejects the reservation', async () => {
    const stuck: LadderRedis = {
      evalsha: () => new Promise(() => undefined),
      eval: () => new Promise(() => undefined),
      hget: async () => null,
      del: async () => 0,
    };
    const input = { realmId: REALM, identifierHmac: IDENTIFIER_HMAC, factor: 'password' } as const;
    await expect(
      createRedisFailureLadder(stuck, { ipDigest, timeoutMs: 10 }).reserve(input)
    ).rejects.toThrow(/timed out/);
    const broken: LadderRedis = {
      ...stuck,
      evalsha: async () => {
        throw new Error('ECONNREFUSED');
      },
    };
    await expect(createRedisFailureLadder(broken, { ipDigest }).reserve(input)).rejects.toThrow(
      'ECONNREFUSED'
    );
    const odd: LadderRedis = { ...stuck, evalsha: async () => 'OK' };
    await expect(createRedisFailureLadder(odd, { ipDigest }).reserve(input)).rejects.toThrow(
      /no list/
    );
    const failingDigest = createRedisFailureLadder(new FakeRedis(() => 0), {
      ipDigest: async () => {
        throw new Error('signer down');
      },
    });
    await expect(failingDigest.reserve({ ...input, endUserIp: IP })).rejects.toThrow('signer down');
  });

  it('refuses a factor without a ladder and key parts out of shape', async () => {
    const { ladder } = setup();
    await expect(
      ladder.reserve({ realmId: REALM, identifierHmac: IDENTIFIER_HMAC, factor: 'totp' })
    ).rejects.toThrow(/no ladder for totp/);
    await expect(
      ladder.reserve({ realmId: REALM, identifierHmac: 'a}:b', factor: 'password' })
    ).rejects.toThrow(/out of shape/);
    await expect(
      ladder.reserve({ realmId: `${REALM}:x`, identifierHmac: IDENTIFIER_HMAC, factor: 'password' })
    ).rejects.toThrow(/out of shape/);
  });

  it('settles a reservation once', async () => {
    const { reserved } = setup();
    const reservation = await reserved();
    await reservation.settle('failure');
    await expect(reservation.settle('success')).rejects.toThrow(/settled twice/);
  });

  it('resets a factor’s run for the owner’s reset', async () => {
    const { ladder, fail, attempt, counter } = setup();
    await fail(5);
    await ladder.reset({ realmId: REALM, identifierHmac: IDENTIFIER_HMAC, factor: 'password' });
    expect(counter()).toBeUndefined();
    expect(await attempt()).toMatchObject({ kind: 'reserved' });
  });
});
