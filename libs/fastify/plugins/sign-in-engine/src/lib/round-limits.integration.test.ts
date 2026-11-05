/**
 * The round limits (#636, ADR-017 Decision 7) over real Redis: the Lua
 * scripts themselves, held to the same contract the memory store keeps
 * (`@qauth-labs/server-sign-in-engine`'s `round-limit-store-contract.ts`),
 * and the engine's rounds on top, as the auth server builds the limiter.
 *
 * Each case works in a realm of its own, so the cases share the container
 * and no counter. The store runs on a clock the case moves; the engine's
 * response-time floor sleeps for nothing.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { randomUUID } from 'node:crypto';

import { type CacheClient, createRedisConnection } from '@qauth-labs/infra-cache';
import {
  type BotChallengeProvider,
  createCaptchaStep,
  createProofOfWorkProvider,
  createRoundLimiter,
  createSignInEngine,
  ROUND_LIMIT_POLICY,
  type RoundContext,
  type RoundLimitAlertEvent,
  type RoundLimitStore,
  type RoundResult,
  type SignInEngine,
  solvesProofOfWork,
} from '@qauth-labs/server-sign-in-engine';
import {
  FakeDirectory,
  FakePasswords,
  FakePolicy,
} from '@qauth-labs/server-sign-in-engine/src/testing/fakes';
import { describeRoundLimitStore } from '@qauth-labs/server-sign-in-engine/src/testing/round-limit-store-contract';
import { STEP_NAMES, STEP_URNS, type StepParams } from '@qauth-labs/server-step-grammar';
import {
  requireDockerOrSkip,
  type StartedRedis,
  startRedisContainer,
} from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createCookieSecretIdentifierDigest, END_USER_IP_HMAC_LABEL } from './identifier-digest';
import { createRedisRoundLimits, ROUND_LIMITS_KEY_PREFIX } from './round-limits';

const COOKIE_SECRET = 'the realm cookie secret, 32 byte';
const CLIENT = 'native-app';
const MINUTE = 60_000;

/** A signer that hands out the realm's cookie secret, a fresh copy each time (the digest zeroes it). */
const signer = {
  getCookieSecrets: async () => ({
    current: { kid: 'cookie-1', secret: Buffer.from(COOKIE_SECRET) },
    previous: null,
  }),
};
const identifierDigest = createCookieSecretIdentifierDigest(signer, 'local');
const ipDigest = createCookieSecretIdentifierDigest(signer, 'local', END_USER_IP_HMAC_LABEL);

const silent = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

let dockerUp = false;
let container: StartedRedis | undefined;
let redis: CacheClient | undefined;

beforeAll(async () => {
  dockerUp = await requireDockerOrSkip();
  if (!dockerUp) return;
  container = await startRedisContainer();
  redis = createRedisConnection({ url: container.connectionUrl, logger: silent });
}, 180_000);

afterAll(async () => {
  redis?.disconnect();
  await container?.stop();
});

describeRoundLimitStore('the Redis store', async () => {
  if (!dockerUp || redis === undefined) return undefined;
  let clock = Date.UTC(2026, 10, 5);
  return {
    store: createRedisRoundLimits(redis, { now: () => clock }),
    advance: (ms: number) => {
      clock += ms;
    },
  };
});

describe('the Redis round limits’ keys', () => {
  it('hold no address, identifier, client or account id, keep a realm’s keys in one slot, and expire', async (context) => {
    if (!dockerUp || redis === undefined) return context.skip();
    const realmId = randomUUID();
    const limiter = createRoundLimiter(createRedisRoundLimits(redis), {
      ipDigest,
      perClient: true,
    });
    const round = { realmId, clientId: CLIENT, endUserIp: '203.0.113.7' } as const;
    const identifierHmac = await identifierDigest({ realmId, identifier: 'alice@example.com' });
    const failed = await limiter.reserve({ ...round, environment: 'production', identifierHmac });
    if (failed.kind !== 'reserved') throw new Error('refused');
    await failed.settle('failure');
    const proved = await limiter.reserve({ ...round, environment: 'production', identifierHmac });
    if (proved.kind !== 'reserved') throw new Error('refused');
    await proved.settle('success', { userId: 'the-user-id' });
    await limiter.round({
      ...round,
      environment: 'production',
      transaction: { v: 1, realmId, clientId: CLIENT, createdAt: Date.now(), verified: [] },
    } as Parameters<typeof limiter.round>[0]);
    await limiter.reserveRegistrationStart(round);

    const keys = await redis.keys(`${ROUND_LIMITS_KEY_PREFIX}:{${realmId}}:*`);
    const kinds = new Set(
      keys.map((key) => key.slice(`${ROUND_LIMITS_KEY_PREFIX}:{${realmId}}:`.length).split(':')[0])
    );
    expect([...kinds].sort()).toEqual(['bucket', 'client', 'ip', 'registration']);
    const stored: string[] = [...keys];
    for (const key of keys) {
      expect(await redis.pttl(key), key).toBeGreaterThan(0);
      const type = await redis.type(key);
      if (type === 'zset') stored.push(...(await redis.zrange(key, 0, -1)));
      if (type === 'hash') stored.push(...Object.keys(await redis.hgetall(key)));
    }
    const text = stored.join('\n');
    for (const forbidden of ['203.0.113', 'alice@example.com', CLIENT, 'the-user-id']) {
      expect(text).not.toContain(forbidden);
    }
  });
});

describe('the engine’s rounds over the Redis round limits', () => {
  /**
   * An engine whose every round meets the limiter, and the limiter's alerts;
   * with `captcha`, it serves the bot challenge through that provider.
   */
  const engineOver = (store: RoundLimitStore, captcha?: BotChallengeProvider) => {
    const alerts: RoundLimitAlertEvent[] = [];
    const limiter = createRoundLimiter(store, {
      ipDigest,
      perClient: false,
      onAlert: (alert) => alerts.push(alert),
    });
    const passwords = new FakePasswords();
    const engine: SignInEngine = createSignInEngine({
      // No account holds any identifier: each round is a wrong password.
      accounts: new FakeDirectory(),
      passwords,
      policy: new FakePolicy(),
      identifierDigest,
      requireVerifiedAccount: true,
      hooks: { limits: limiter },
      ...(captcha === undefined ? {} : { steps: [createCaptchaStep(captcha)] }),
      clock: { now: () => Date.now(), sleep: async () => undefined },
    });
    return { engine, limiter, alerts, passwords };
  };
  /**
   * A round of the IP. Unless `challenge` says otherwise, through a transport
   * that does not serve the bot challenge (#643), so a soft threshold meets
   * the delay and the 429 alone.
   */
  const context = (realmId: string, endUserIp: string, challenge = false): RoundContext => ({
    realm: { id: realmId },
    client: { id: CLIENT },
    endUserIp,
    ...(challenge ? {} : { serves: STEP_NAMES.filter((name) => name !== 'captcha') }),
    audit: async () => undefined,
  });
  const guess = (engine: SignInEngine, realmId: string, endUserIp: string, identifier: string) =>
    engine.advance(
      null,
      {
        step: STEP_URNS.password,
        fields: { password: 'not it', login_hint: identifier },
      },
      context(realmId, endUserIp)
    );
  const isRefusedCredential = (result: RoundResult) =>
    result.kind === 'step' && result.offer.current.error === 'invalid_credentials';

  /** The proof of work at a difficulty a test solves at once. */
  const easyProofOfWork = () => createProofOfWorkProvider({ difficulty: () => 4 });
  const solve = (params: StepParams<'captcha'>, solves = true): string => {
    for (let nonce = 0; ; nonce += 1) {
      if (solvesProofOfWork(params, String(nonce)) === solves) return String(nonce);
    }
  };
  const challengeOf = (result: RoundResult): StepParams<'captcha'> => {
    if (result.kind !== 'step' || result.offer.current.step !== 'captcha') {
      throw new Error(`expected the captcha step, got ${result.kind}`);
    }
    return result.offer.current.params as StepParams<'captcha'>;
  };

  it('offers the bot challenge once an IP’s soft threshold holds, and counts a wrong answer as a failed round (#643)', async (testCtx) => {
    if (!dockerUp || redis === undefined) return testCtx.skip();
    const realmId = randomUUID();
    let now = Date.UTC(2026, 10, 5);
    const { engine, passwords } = engineOver(
      createRedisRoundLimits(redis, { now: () => now }),
      easyProofOfWork()
    );
    const ip = '203.0.113.7';
    const soft = ROUND_LIMIT_POLICY.endUserIp.softFailures;
    for (let i = 0; i < soft; i += 1) {
      expect(isRefusedCredential(await guess(engine, realmId, ip, `guess-${i}@example.com`))).toBe(
        true
      );
      now += 30_000;
    }
    const verified = passwords.verifications;
    // The next round of a transport that serves it is the challenge, and the
    // password it brought is not checked.
    let result = await engine.advance(
      null,
      { step: STEP_URNS.password, fields: { password: 'not it', login_hint: 'x@example.com' } },
      context(realmId, ip, true)
    );
    challengeOf(result);
    expect(passwords.verifications).toBe(verified);
    // A right answer resumes the pending step.
    const passed = await engine.advance(
      result.transaction,
      { step: STEP_URNS.captcha, fields: { captcha_token: solve(challengeOf(result)) } },
      context(realmId, ip, true)
    );
    expect(passed.kind).toBe('step');
    expect(passed.kind === 'step' && passed.offer.current.step).not.toBe('captcha');
    // Each wrong answer is refused with captcha_failed and counted on the IP,
    // until its hard limit blocks every round.
    result = await engine.advance(null, null, context(realmId, ip, true));
    for (let i = soft; i < ROUND_LIMIT_POLICY.endUserIp.hardFailures; i += 1) {
      result = await engine.advance(
        result.transaction,
        { step: STEP_URNS.captcha, fields: { captcha_token: solve(challengeOf(result), false) } },
        context(realmId, ip, true)
      );
      expect(result, `round ${i}`).toMatchObject({
        kind: 'step',
        offer: { current: { step: 'captcha', error: 'captcha_failed' } },
      });
      now += 30_000;
    }
    expect(await engine.advance(null, null, context(realmId, ip, true))).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
    });
    expect(passwords.verifications).toBe(verified);
  });

  it('refuses a round whose challenge is due when no provider serves it, or the provider is down (#643)', async (testCtx) => {
    if (!dockerUp || redis === undefined) return testCtx.skip();
    const down: BotChallengeProvider = {
      params: easyProofOfWork().params,
      verify: async () => {
        throw new Error('the provider is down');
      },
    };
    for (const provider of [undefined, down]) {
      const realmId = randomUUID();
      let now = Date.UTC(2026, 10, 5);
      const { engine, passwords } = engineOver(
        createRedisRoundLimits(redis, { now: () => now }),
        provider
      );
      const ip = '203.0.113.7';
      for (let i = 0; i < ROUND_LIMIT_POLICY.endUserIp.softFailures; i += 1) {
        await guess(engine, realmId, ip, `guess-${i}@example.com`);
        now += 30_000;
      }
      const verified = passwords.verifications;
      let result = await engine.advance(null, null, context(realmId, ip, true));
      if (provider !== undefined) {
        result = await engine.advance(
          result.transaction,
          { step: STEP_URNS.captcha, fields: { captcha_token: solve(challengeOf(result)) } },
          context(realmId, ip, true)
        );
      }
      expect(result).toMatchObject({ kind: 'refused', reason: 'unavailable' });
      expect(passwords.verifications).toBe(verified);
    }
  });

  it('refuses every round from an IP for 15 minutes once 30 of its rounds failed', async (testCtx) => {
    if (!dockerUp || redis === undefined) return testCtx.skip();
    const realmId = randomUUID();
    let now = Date.UTC(2026, 10, 5);
    const { engine, alerts, passwords } = engineOver(
      createRedisRoundLimits(redis, { now: () => now })
    );
    const ip = '203.0.113.7';
    // 30 s apart: the delay from the 10th failure never holds one back.
    for (let i = 0; i < 30; i += 1) {
      const result = await guess(engine, realmId, ip, `guess-${i}@example.com`);
      expect(isRefusedCredential(result), `round ${i}`).toBe(true);
      now += 30_000;
    }
    const verified = passwords.verifications;
    expect(await guess(engine, realmId, ip, 'next@example.com')).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
      retryAfterSeconds: 15 * 60 - 30,
    });
    // Any round of the IP, a first one included, meets the block.
    expect(await engine.advance(null, null, context(realmId, ip))).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
    });
    expect(passwords.verifications).toBe(verified);
    expect(alerts.map((alert) => alert.alert)).toContain('end_user_ip_blocked');
    // Another IP is not held back.
    expect(isRefusedCredential(await guess(engine, realmId, '198.51.100.9', 'x@example.com'))).toBe(
      true
    );
    now += 15 * MINUTE;
    expect(isRefusedCredential(await guess(engine, realmId, ip, 'later@example.com'))).toBe(true);
  });

  it('delays each IP of a bucket, and alerts, once its rounds failed for more than 20 distinct identifiers', async (testCtx) => {
    if (!dockerUp || redis === undefined) return testCtx.skip();
    const realmId = randomUUID();
    let now = Date.UTC(2026, 10, 5);
    const { engine, alerts } = engineOver(createRedisRoundLimits(redis, { now: () => now }));
    // One IP of the /24 an identifier: no IP is near its own limits.
    for (let i = 1; i <= 21; i += 1) {
      const result = await guess(engine, realmId, `203.0.113.${i}`, `user-${i}@example.com`);
      expect(isRefusedCredential(result), `identifier ${i}`).toBe(true);
      now += 1_000;
    }
    expect(alerts).toEqual([
      {
        realmId,
        alert: 'ip_bucket_identifiers',
        ipBucketHmac: await ipDigest({ realmId, identifier: '203.0.113.0/24' }),
      },
    ]);
    // The IP that crossed waits.
    expect(await guess(engine, realmId, '203.0.113.21', 'user-22@example.com')).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
    });
    // Any other IP of the bucket gets one round, then waits 30 s.
    expect(
      isRefusedCredential(await guess(engine, realmId, '203.0.113.200', 'user-23@example.com'))
    ).toBe(true);
    expect(await guess(engine, realmId, '203.0.113.200', 'user-24@example.com')).toMatchObject({
      kind: 'refused',
      reason: 'throttled',
      retryAfterSeconds: 30,
    });
    // Another bucket does not wait.
    for (let i = 0; i < 2; i += 1) {
      expect(
        isRefusedCredential(await guess(engine, realmId, '198.51.100.9', `other-${i}@example.com`))
      ).toBe(true);
    }
    now += 30_000;
    expect(
      isRefusedCredential(await guess(engine, realmId, '203.0.113.21', 'user-25@example.com'))
    ).toBe(true);
    // Alerted once per window.
    expect(alerts).toHaveLength(1);
  });

  it('refuses the fourth registration start from one IP in an hour', async (testCtx) => {
    if (!dockerUp || redis === undefined) return testCtx.skip();
    const realmId = randomUUID();
    let now = Date.UTC(2026, 10, 5);
    const { limiter } = engineOver(createRedisRoundLimits(redis, { now: () => now }));
    const start = { realmId, clientId: CLIENT, endUserIp: '203.0.113.7' };
    for (let i = 0; i < 3; i += 1) {
      expect(await limiter.reserveRegistrationStart(start)).toEqual({ kind: 'continue' });
      now += MINUTE;
    }
    expect(await limiter.reserveRegistrationStart(start)).toEqual({
      kind: 'throttled',
      retryAfterSeconds: 57 * 60,
    });
    expect(await limiter.reserveRegistrationStart({ ...start, endUserIp: '198.51.100.9' })).toEqual(
      { kind: 'continue' }
    );
    now += 57 * MINUTE;
    expect(await limiter.reserveRegistrationStart(start)).toEqual({ kind: 'continue' });
  });

  it('refuses rounds before any credential is checked when Redis is stopped', async (testCtx) => {
    if (!dockerUp) return testCtx.skip();
    // A container of the case's own: on the run's shared server, `stop()`
    // only empties the suite's logical databases and the server keeps
    // answering, so the store would never go down.
    const stopped = await startRedisContainer({ privateContainer: true });
    const client = createRedisConnection({
      url: stopped.connectionUrl,
      logger: silent,
      maxRetriesPerRequest: 0,
    });
    try {
      // Reachable once, so the failure is the stop and not a bad address.
      expect(await client.ping()).toBe('PONG');
      await stopped.stop();
      const realmId = randomUUID();
      const { engine, limiter, passwords } = engineOver(
        createRedisRoundLimits(client, { timeoutMs: 1_000 })
      );
      expect(await engine.advance(null, null, context(realmId, '203.0.113.7'))).toMatchObject({
        kind: 'refused',
        reason: 'unavailable',
      });
      expect(await guess(engine, realmId, '203.0.113.7', 'down@example.com')).toMatchObject({
        kind: 'refused',
        reason: 'unavailable',
      });
      expect(passwords.verifications).toBe(0);
      await expect(
        limiter.reserveRegistrationStart({ realmId, clientId: CLIENT, endUserIp: '203.0.113.7' })
      ).rejects.toThrow();
    } finally {
      client.disconnect();
    }
  });
});
