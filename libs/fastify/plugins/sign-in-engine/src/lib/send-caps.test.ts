import { SEND_CAP_POLICY } from '@qauth-labs/server-sign-in-engine';
import { describe, expect, it, vi } from 'vitest';

import {
  CLAIM_MARK_SCRIPT,
  createRedisSendCaps,
  mailPassHash,
  RELEASE_MARK_SCRIPT_SHA,
  RESERVE_SEND_SCRIPT,
  RESERVE_SEND_SCRIPT_SHA,
  sendCapKey,
  type SendCapsRedis,
} from './send-caps';

const REALM = '9a1f6a1e-5a5b-4c1a-9a7e-3d1c1c2b0a01';
const NOW = Date.UTC(2026, 10, 4);

/** A Redis double: `reply` answers every script call; every call is recorded. */
function fakeRedis(reply: unknown = ['send', 0]) {
  const calls: { sha: string; keys: string[]; args: (string | number)[] }[] = [];
  const values = new Map<string, string>();
  const redis: SendCapsRedis & { calls: typeof calls; values: typeof values } = {
    calls,
    values,
    evalsha: vi.fn(async (sha: string, numKeys: number, ...rest: (string | number)[]) => {
      calls.push({
        sha,
        keys: rest.slice(0, numKeys) as string[],
        args: rest.slice(numKeys),
      });
      return reply;
    }),
    eval: vi.fn(async () => reply),
    get: vi.fn(async (key: string) => values.get(key) ?? null),
    set: vi.fn(async (key: string, value: string) => {
      if (values.has(key)) return null;
      values.set(key, value);
      return 'OK' as const;
    }),
  };
  return redis;
}

const request = {
  realmId: REALM,
  addressHmac: 'address-hmac',
  knownIp: false,
  afterFirstFactor: false,
};

describe('createRedisSendCaps (#637)', () => {
  it('reads each decision the script returns', async () => {
    const cases: [unknown, unknown][] = [
      [['send', 0], { kind: 'send', passSpent: false }],
      [['send', 1], { kind: 'send', passSpent: true }],
      [['quiet'], { kind: 'quiet' }],
      [
        ['refused', 'ceiling', 3_600_000, 1],
        { kind: 'refused', tier: 'ceiling', retryAfterMs: 3_600_000, alert: true },
      ],
      [
        ['refused', 'end_user_ip', 0, 0],
        { kind: 'refused', tier: 'end_user_ip', retryAfterMs: 1, alert: false },
      ],
    ];
    for (const [reply, decision] of cases) {
      const store = createRedisSendCaps(fakeRedis(reply), { now: () => NOW });
      expect(await store.reserve(request)).toEqual(decision);
    }
  });

  it.each([
    [null],
    ['send'],
    [['refused', 'nowhere', 1, 0]],
    [['refused', 'ceiling', 'x', 0]],
    [['go']],
  ])('refuses a reply out of shape (%j), so the round fails closed', async (reply) => {
    const store = createRedisSendCaps(fakeRedis(reply), { now: () => NOW });
    await expect(store.reserve(request)).rejects.toThrow(/out of shape/);
  });

  it('keys every tier under the realm’s hash tag, with no address or client id', async () => {
    const redis = fakeRedis();
    const store = createRedisSendCaps(redis, { now: () => NOW });
    await store.reserve({
      ...request,
      endUserIpHmac: 'ip-hmac',
      clientKey: 'first-party-app',
      passHash: mailPassHash('p'.repeat(43)),
    });

    const [{ keys, args }] = redis.calls;
    expect(keys).toHaveLength(8);
    for (const key of keys) expect(key.startsWith(`send-caps:{${REALM}}:`)).toBe(true);
    expect(keys.join(' ')).not.toContain('first-party-app');
    expect(keys[0]).toBe(sendCapKey(REALM, 'ip', 'ip-hmac'));
    expect(keys[2]).toBe(sendCapKey(REALM, 'address-ip', 'address-hmac', 'ip-hmac'));
    expect(keys[4]).toBe(sendCapKey(REALM, 'ceiling', 'address-hmac'));
    expect(keys[6]).toBe(sendCapKey(REALM, 'pass', mailPassHash('p'.repeat(43))));
    expect(args[0]).toBe(NOW);
    expect(args[2]).toBe('11001');
    expect(args.slice(3)).toEqual([
      SEND_CAP_POLICY.endUserIp.limit,
      SEND_CAP_POLICY.endUserIp.windowMs,
      SEND_CAP_POLICY.client.limit,
      SEND_CAP_POLICY.client.windowMs,
      SEND_CAP_POLICY.addressIpShort.limit,
      SEND_CAP_POLICY.addressIpShort.windowMs,
      SEND_CAP_POLICY.addressIpLong.limit,
      SEND_CAP_POLICY.addressIpLong.windowMs,
      SEND_CAP_POLICY.addressClient.limit,
      SEND_CAP_POLICY.addressClient.windowMs,
      SEND_CAP_POLICY.ceiling.limit,
      SEND_CAP_POLICY.ceiling.windowMs,
      SEND_CAP_POLICY.afterFirstFactor.limit,
      SEND_CAP_POLICY.afterFirstFactor.windowMs,
      'address-hmac',
      SEND_CAP_POLICY.noticeIntervalMs,
    ]);
  });

  it('sets the flags of a known IP after a first factor', async () => {
    const redis = fakeRedis();
    await createRedisSendCaps(redis).reserve({ ...request, knownIp: true, afterFirstFactor: true });

    expect(redis.calls[0]?.args[2]).toBe('00110');
  });

  it('refuses a key part that could splice another key', async () => {
    const store = createRedisSendCaps(fakeRedis());
    await expect(store.reserve({ ...request, addressHmac: 'a:b' })).rejects.toThrow(/out of shape/);
    await expect(store.reserve({ ...request, realmId: 'r}x' })).rejects.toThrow(/out of shape/);
    await expect(store.reserve({ ...request, endUserIpHmac: '' })).rejects.toThrow(/out of shape/);
  });

  it('loads the script again after a Redis restart', async () => {
    const redis = fakeRedis();
    redis.evalsha = vi.fn(async () => {
      throw new Error('NOSCRIPT No matching script');
    });
    redis.eval = vi.fn(async () => ['quiet']);

    expect(await createRedisSendCaps(redis).reserve(request)).toEqual({ kind: 'quiet' });
    expect(vi.mocked(redis.eval).mock.calls[0]?.slice(0, 2)).toEqual([RESERVE_SEND_SCRIPT, 8]);
  });

  it('rejects when Redis does not answer in time', async () => {
    const redis = fakeRedis();
    redis.evalsha = vi.fn(() => new Promise<never>(() => undefined));
    const store = createRedisSendCaps(redis, { timeoutMs: 5 });

    await expect(store.reserve(request)).rejects.toThrow(/timed out/);
  });

  it('rejects any other Redis error', async () => {
    const redis = fakeRedis();
    redis.evalsha = vi.fn(async () => {
      throw new Error('READONLY');
    });

    await expect(createRedisSendCaps(redis).reserve(request)).rejects.toThrow('READONLY');
  });

  it('stores only a pass’s hash, bound to its address, with its expiry', async () => {
    const redis = fakeRedis();
    let now = NOW;
    const store = createRedisSendCaps(redis, { now: () => now });
    const pass = await store.mintPass({
      realmId: REALM,
      addressHmac: 'address-hmac',
      flow: 'reset',
    });

    expect(pass).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const key = sendCapKey(REALM, 'pass', mailPassHash(pass));
    expect(redis.values.get(key)).toBe(`address-hmac:reset:${NOW + SEND_CAP_POLICY.passTtlMs}`);
    expect(redis.set).toHaveBeenCalledWith(
      key,
      expect.any(String),
      'PX',
      SEND_CAP_POLICY.passTtlMs,
      'NX'
    );
    expect([...redis.values.keys(), ...redis.values.values()].join(' ')).not.toContain(pass);

    expect(await store.peekPass(REALM, pass)).toEqual({
      passHash: mailPassHash(pass),
      addressHmac: 'address-hmac',
      flow: 'reset',
    });
    now += SEND_CAP_POLICY.passTtlMs;
    expect(await store.peekPass(REALM, pass)).toBeUndefined();
  });

  it('reads no pass out of shape', async () => {
    const redis = fakeRedis();
    const store = createRedisSendCaps(redis, { now: () => NOW });

    expect(await store.peekPass(REALM, 'short')).toBeUndefined();
    expect(redis.get).not.toHaveBeenCalled();
    redis.values.set(
      sendCapKey(REALM, 'pass', mailPassHash('q'.repeat(43))),
      'x:login:9999999999999'
    );
    expect(await store.peekPass(REALM, 'q'.repeat(43))).toBeUndefined();
  });

  it('claims a notice through its own script, per kind and address', async () => {
    const redis = fakeRedis(1);
    const store = createRedisSendCaps(redis, { now: () => NOW });

    expect(
      await store.claimNotice({ realmId: REALM, addressHmac: 'address-hmac', kind: 'send_ceiling' })
    ).toBe(true);
    expect(redis.calls[0]?.keys).toEqual([
      sendCapKey(REALM, 'notice', 'send_ceiling', 'address-hmac'),
    ]);
    expect(redis.calls[0]?.args).toEqual([NOW, SEND_CAP_POLICY.noticeIntervalMs]);
    expect(RESERVE_SEND_SCRIPT_SHA).toMatch(/^[0-9a-f]{40}$/);
    expect(CLAIM_MARK_SCRIPT).not.toMatch(/\buntil\b/);
    expect(RESERVE_SEND_SCRIPT).not.toMatch(/\blocal until\b/);
  });

  it('claims the recovery codes’ 100-failures notice on a key of its own (#649)', async () => {
    const redis = fakeRedis(1);
    const store = createRedisSendCaps(redis, { now: () => NOW });

    expect(
      await store.claimNotice({
        realmId: REALM,
        addressHmac: 'account-hmac',
        kind: 'recovery_codes_failed',
      })
    ).toBe(true);
    expect(redis.calls[0]?.keys).toEqual([
      sendCapKey(REALM, 'notice', 'recovery_codes_failed', 'account-hmac'),
    ]);
    await expect(
      store.claimNotice({
        realmId: REALM,
        addressHmac: 'account-hmac',
        kind: 'recovery_code_used' as never,
      })
    ).rejects.toThrow('not a once-a-day notice');
  });

  it('releases a notice through its own script, on the claim’s key', async () => {
    const redis = fakeRedis(1);
    const store = createRedisSendCaps(redis, { now: () => NOW });

    await store.releaseNotice({
      realmId: REALM,
      addressHmac: 'address-hmac',
      kind: 'password_disabled',
    });
    expect(redis.calls[0]?.sha).toBe(RELEASE_MARK_SCRIPT_SHA);
    expect(redis.calls[0]?.keys).toEqual([
      sendCapKey(REALM, 'notice', 'password_disabled', 'address-hmac'),
    ]);
    expect(redis.calls[0]?.args).toEqual([]);
    await expect(
      store.releaseNotice({ realmId: REALM, addressHmac: 'a:b', kind: 'send_ceiling' })
    ).rejects.toThrow('out of shape');
  });
});
