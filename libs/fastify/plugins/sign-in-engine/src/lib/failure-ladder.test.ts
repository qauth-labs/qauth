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
const DAY = 86_400_000;
/** The password ladder's retention of a run that has not reached a wait: 2 days. */
const FREE = PASSWORD_LADDER_POLICY.freeRetentionMs;

/** A keyed HMAC as the digests make it: base64url, never the input. */
const hmacOf = (label: string, value: string) =>
  createHmac('sha256', `key:${label}`).update(`${REALM}\u0000${value}`).digest('base64url');
const IDENTIFIER_HMAC = hmacOf('identifier', IDENTIFIER);
const COUNTER = ladderCounterKey(REALM, IDENTIFIER_HMAC, 'password');
const KNOWN_IPS = ladderKnownIpsKey(REALM, IDENTIFIER_HMAC);
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
    const [now, free, first, longest, retention, freeRetention, knownMs, knownFree] = argv
      .slice(0, 8)
      .map(Number);
    const ip = argv[8];
    let knownIp = false;
    if (knownMs > 0 && ip !== '') {
      const seen = this.sets.get(known)?.get(ip);
      if (seen !== undefined && now - seen < knownMs) knownIp = true;
    }
    const state = this.hashes.get(counter);
    let n = Number(state?.get('n') ?? 0);
    const waitUntil = Number(state?.get('until') ?? 0);
    const run = state?.get('run') ?? argv[9];
    const k = Number(state?.get('k') ?? 0);
    if (waitUntil > now && !(knownIp && k < knownFree)) return [0, Math.trunc(waitUntil - now)];
    n += 1;
    let wait = 0;
    if (n >= free) {
      const doublings = n - free;
      wait = doublings >= 40 ? longest : Math.min(first * 2 ** doublings, longest);
    }
    const nextUntil = Math.max(now + wait, waitUntil);
    const hash = new Map([
      ['n', String(n)],
      ['until', String(nextUntil)],
      ['run', run],
    ]);
    // HSET leaves `k` as it was; HINCRBY adds this attempt when its IP is known.
    if (state?.has('k') || knownIp) hash.set('k', String(k + (knownIp ? 1 : 0)));
    this.hashes.set(counter, hash);
    this.expiries.set(counter, now + (n >= free ? retention : freeRetention));
    return [1, n, run];
  }

  private settleSuccess([counter, known]: string[], argv: string[]): unknown {
    const now = Number(argv[0]);
    if (this.hashes.get(counter)?.get('run') !== argv[2]) {
      // Another run: nothing to settle on it.
    } else if (argv[1] === 'clear') {
      this.hashes.delete(counter);
      this.expiries.delete(counter);
    } else {
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
  /** `times` failures a quarter of an hour apart, so no wait holds one back. */
  const failSpaced = async (times: number, endUserIp?: string) => {
    const settled = [];
    for (let i = 0; i < times; i += 1) {
      settled.push(...(await fail(1, endUserIp)));
      clock += 15 * 60_000;
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
    failSpaced,
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

  it('lets a known IP skip the wait below 20 counted failures, every one counted (#968)', async () => {
    const { attempt, fail, reserved, counter } = setup();
    await (await reserved(IP)).settle('success');
    expect(PASSWORD_LADDER_POLICY.knownIpFreeFailures).toBe(20);
    const settled = await fail(20, IP);
    expect(counter()?.get('n')).toBe('20');
    expect(settled.every((result) => !result.ceilingReached)).toBe(true);
    // Another IP has been waiting since the 5th failure.
    expect(await attempt(OTHER_IP)).toMatchObject({ kind: 'wait' });
  });

  it('makes a known IP wait from its 20th counted failure on, as any other address (#968)', async () => {
    const { attempt, fail, reserved, counter, advance } = setup();
    await (await reserved(IP)).settle('success');
    await fail(20, IP);
    for (let n = 20; n < 23; n += 1) {
      const fromKnown = await attempt(IP);
      expect(fromKnown).toEqual({ kind: 'wait', retryAfterSeconds: 15 * 60 });
      expect(await attempt(OTHER_IP)).toEqual(fromKnown);
      // Refused, so not counted.
      expect(counter()?.get('n')).toBe(String(n));
      advance(15 * 60_000 - 1);
      expect(await attempt(IP)).toEqual({ kind: 'wait', retryAfterSeconds: 1 });
      advance(1);
      await fail(1, IP);
    }
  });

  it('lets a known IP reach the hard ceiling only through the waits (#968)', async () => {
    const { attempt, reserved, advance } = setup();
    await (await reserved(IP)).settle('success');
    let waited = 0;
    const settled: { ceilingReached: boolean }[] = [];
    while (settled.length < 100) {
      const verdict = await attempt(IP);
      if (verdict.kind === 'wait') {
        advance(verdict.retryAfterSeconds * 1000);
        waited += verdict.retryAfterSeconds * 1000;
        continue;
      }
      settled.push(await verdict.settle('failure'));
    }
    expect(settled.slice(0, 99).every((result) => !result.ceilingReached)).toBe(true);
    expect(settled[99]).toEqual({ ceilingReached: true });
    // The waits the 20th to the 99th failures set, 15 minutes each: 20 hours.
    expect(waited).toBe(80 * 15 * 60_000);
  });

  it('counts parallel attempts from a known IP one at a time: past 20 every one waits (#968)', async () => {
    const { attempt, reserved, counter } = setup();
    await (await reserved(IP)).settle('success');
    const verdicts = await Promise.all(Array.from({ length: 50 }, () => attempt(IP)));
    expect(verdicts.filter((verdict) => verdict.kind === 'reserved')).toHaveLength(20);
    expect(counter()?.get('n')).toBe('20');
  });

  it('counts only known IPs’ failures toward the bound, in `k` (#968)', async () => {
    const { attempt, fail, failSpaced, reserved, counter } = setup();
    await (await reserved(IP)).settle('success');
    // A guesser elsewhere: no `k` is written.
    await failSpaced(29, OTHER_IP);
    await fail(1, OTHER_IP);
    expect(counter()?.has('k')).toBe(false);
    expect(await attempt(OTHER_IP)).toMatchObject({ kind: 'wait' });
    // The owner's known IP still skips the wait for its 20.
    await fail(20, IP);
    expect(counter()?.get('n')).toBe('50');
    expect(counter()?.get('k')).toBe('20');
    expect(await attempt(IP)).toMatchObject({ kind: 'wait' });
    expect(counter()?.get('k')).toBe('20');
  });

  it('still clears the run on a success from a known IP, which then skips the wait again (#968)', async () => {
    const { attempt, fail, reserved, counter, advance } = setup();
    await (await reserved(IP)).settle('success');
    await fail(20, IP);
    expect(await attempt(IP)).toMatchObject({ kind: 'wait' });
    advance(15 * 60_000);
    await (await reserved(IP)).settle('success');
    expect(counter()).toBeUndefined();
    await fail(20, IP);
    expect(counter()?.get('n')).toBe('20');
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
    const { failSpaced, reserved, advance } = setup();
    await failSpaced(99);
    const hundredth = await reserved();
    // The owner signs in, once the wait the 100th set is over, before the 100th settles: the run ends.
    advance(15 * 60_000);
    await (await reserved(IP)).settle('success');
    expect(await hundredth.settle('failure')).toEqual({ ceilingReached: false });
  });

  it('leaves a run begun after it alone when a success settles late', async () => {
    const { fail, reserved, counter } = setup();
    const late = await reserved();
    // Another success of the owner ends the run; a new run starts.
    await (await reserved()).settle('success');
    await fail(4);
    await late.settle('success');
    expect(counter()?.get('n')).toBe('4');
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

  it('ends a run that never reached a wait 2 days after its last counted failure (#969)', async () => {
    const { redis, attempt, fail, advance, counter, now } = setup();
    expect(FREE).toBe(2 * DAY);
    await fail(3);
    advance(FREE - 1);
    await fail(1);
    const run = counter()?.get('run');
    expect(redis.expiries.get(COUNTER)).toBe(now() + FREE);
    advance(FREE - 1);
    expect(counter()?.get('n')).toBe('4');
    advance(1);
    expect(counter()).toBeUndefined();
    // The next failure starts another run, from the first free failure.
    expect(await attempt()).toMatchObject({ kind: 'reserved' });
    expect(counter()?.get('n')).toBe('1');
    expect(counter()?.get('run')).not.toBe(run);
  });

  it('keeps a run 30 days from the failure that sets its first wait, in the same run (#969)', async () => {
    const { redis, attempt, fail, advance, counter, now } = setup();
    await fail(4);
    const run = counter()?.get('run');
    advance(FREE - 1);
    await fail(1);
    expect(counter()).toEqual(
      new Map([
        ['n', '5'],
        ['until', String(now() + 1_000)],
        ['run', run],
      ])
    );
    expect(redis.expiries.get(COUNTER)).toBe(now() + 30 * DAY);
    advance(30 * DAY - 1);
    expect(counter()?.get('n')).toBe('5');
    // A later failure keeps it 30 days more; an attempt refused inside the wait leaves it.
    await fail(1);
    expect(await attempt()).toMatchObject({ kind: 'wait' });
    expect(redis.expiries.get(COUNTER)).toBe(now() + 30 * DAY);
    advance(30 * DAY);
    expect(counter()).toBeUndefined();
  });

  it('keeps a known IP 30 days from its last successful sign-in, whatever the counter’s retention', async () => {
    const { redis, reserved, fail, now } = setup();
    await fail(2, IP);
    await (await reserved(IP)).settle('success');
    expect(redis.expiries.get(KNOWN_IPS)).toBe(now() + 30 * DAY);
    await fail(1, IP);
    expect(redis.expiries.get(COUNTER)).toBe(now() + FREE);
    expect(redis.expiries.get(KNOWN_IPS)).toBe(now() + 30 * DAY);
  });

  it('sends both retentions and the known-IP bound to the script, in its argument order', async () => {
    // Every time and count a distinct value, so no two arguments can trade places unseen.
    const { redis, attempt, now } = setup({
      ...PASSWORD_LADDER_POLICY,
      knownIpMs: 7 * DAY,
      knownIpFreeFailures: 17,
    });
    await attempt();
    const sent = redis.sent.slice(-12);
    expect(sent).toEqual([
      COUNTER,
      KNOWN_IPS,
      String(now()),
      '5',
      '1000',
      String(15 * 60_000),
      String(30 * DAY),
      String(2 * DAY),
      String(7 * DAY),
      '17',
      hmacOf('ip', IP),
      expect.stringMatching(/^[A-Za-z0-9_-]{16}$/),
    ]);
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
