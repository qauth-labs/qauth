/**
 * The per-account failure ladder (#615, ADR-017 Decision 7) over real Redis
 * and the migrated schema in real Postgres: the Lua scripts themselves, the
 * account directory and the hard action over the real repositories, and the
 * engine's password step on top, as the auth server builds them.
 *
 * Each case signs in to an account of its own, so the cases share the
 * containers and no counter. The ladder runs on a clock the test moves; the
 * engine's response-time floor sleeps for nothing.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { type CacheClient, createRedisConnection } from '@qauth-labs/infra-cache';
import {
  createAdminGrantsRepository,
  createDatabase,
  createRealmsRepository,
  createUserCredentialsRepository,
  createUsersRepository,
  type DatabaseInstance,
} from '@qauth-labs/infra-db';
import { buildPasswordCredentialData } from '@qauth-labs/server-federation';
import { createPasswordHasher } from '@qauth-labs/server-password';
import {
  createSignInEngine,
  PASSWORD_LADDER_POLICY,
  type PasswordVerifier,
  type RoundContext,
  type RoundResult,
  type SignInEngine,
  SignInStoreUnavailableError,
} from '@qauth-labs/server-sign-in-engine';
import { STEP_URNS } from '@qauth-labs/server-step-grammar';
import {
  applyQauthMigrations,
  requireDockerOrSkip,
  type StartedPostgres,
  type StartedRedis,
  startPostgresContainer,
  startRedisContainer,
} from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { createRepositoryAccountDirectory } from './account-directory';
import { createRedisFailureLadder, ladderCounterKey, type LadderRedis } from './failure-ladder';
import { createCookieSecretIdentifierDigest, END_USER_IP_HMAC_LABEL } from './identifier-digest';
import { createPasswordAttempts } from './password-attempts';
import { createHardActionArming, createPasswordHardAction } from './password-hard-action';
import { createArgon2PasswordVerifier } from './password-verifier';

const PASSWORD = 'a long passphrase nobody guesses 2026';
const COOKIE_SECRET = 'the realm cookie secret, 32 byte';
const KNOWN_IP = '203.0.113.7';
const OTHER_IP = '198.51.100.9';
const QUARTER_HOUR = 15 * 60_000;

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

describe('the failure ladder over real Redis and Postgres', () => {
  let dockerUp = false;
  let postgres: StartedPostgres | undefined;
  let redisContainer: StartedRedis | undefined;
  let database: DatabaseInstance | undefined;
  let redis: CacheClient | undefined;
  let engine: SignInEngine;
  let realmId: string;
  let seed: (identifier: string) => Promise<string>;
  let userCredentials: ReturnType<typeof createUserCredentialsRepository>;
  let buildEngine: (ladderRedis: LadderRedis, timeoutMs?: number) => SignInEngine;
  let ladderRedis: LadderRedis;
  /** Every verification the engine ran, the dummy one included. */
  const verified = { count: 0 };
  /** The ladder's clock. */
  let now = Date.UTC(2026, 10, 1);
  /** Whether the hosted reset is on: with the notice below, it arms the hard action. */
  let hostedReset = false;
  const notices = { canSend: async () => true, passwordDisabled: vi.fn(async () => undefined) };

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    [postgres, redisContainer] = await Promise.all([
      startPostgresContainer(),
      startRedisContainer(),
    ]);
    await applyQauthMigrations(postgres.connectionString);
    database = createDatabase({ connectionString: postgres.connectionString });
    redis = createRedisConnection({ url: redisContainer.connectionUrl, logger: silent });
    ladderRedis = redis;
    const { db } = database;
    // Cheap Argon2id: the cases run a few hundred verifications.
    const hasher = createPasswordHasher({ memoryCost: 1024, timeCost: 1, parallelism: 1 });
    const users = createUsersRepository(db);
    userCredentials = createUserCredentialsRepository(db);
    realmId = (await createRealmsRepository(db).create({ name: 'failure-ladder' })).id;
    const hash = await hasher.hashPassword(PASSWORD);
    seed = async (identifier) => {
      const user = await users.create({ realmId, enabled: true });
      await userCredentials.create({
        userId: user.id,
        realmId,
        providerType: 'password',
        externalSub: identifier,
        credentialData: buildPasswordCredentialData(hash, true),
      });
      return user.id;
    };

    const inner = createArgon2PasswordVerifier(hasher, silent);
    const passwords: PasswordVerifier = {
      verify: async (stored, presented) => {
        verified.count += 1;
        return inner.verify(stored, presented);
      },
      verifyDecoy: async (presented) => {
        verified.count += 1;
        return inner.verifyDecoy(presented);
      },
    };
    const arming = { hostedReset: () => hostedReset, notices };
    const armed = createHardActionArming(arming);
    buildEngine = (store, timeoutMs) =>
      createSignInEngine({
        accounts: createRepositoryAccountDirectory(
          { users, userCredentials, adminGrants: createAdminGrantsRepository(db) },
          silent,
          { hardActionArmed: armed }
        ),
        passwords,
        policy: { read: async () => ({ realm: 'off', client: 'off' }) },
        identifierDigest,
        requireVerifiedAccount: true,
        hooks: {
          ladder: createRedisFailureLadder(store, {
            ipDigest,
            now: () => now,
            ...(timeoutMs === undefined ? {} : { timeoutMs }),
          }),
        },
        passwordHardAction: createPasswordHardAction({
          credentials: userCredentials,
          arming,
          log: silent,
        }),
        clock: { now: () => Date.now(), sleep: async () => undefined },
      });
    engine = buildEngine(redis);
  }, 180_000);

  afterAll(async () => {
    redis?.disconnect();
    await database?.close();
    await Promise.all([postgres?.stop(), redisContainer?.stop()]);
  });

  const context = (endUserIp?: string): RoundContext => ({
    realm: { id: realmId },
    client: { id: 'native-app' },
    ...(endUserIp === undefined ? {} : { endUserIp }),
    audit: async () => undefined,
  });

  /** One round of its own transaction: the identifier and the password at once. */
  const attempt = (identifier: string, password: string, endUserIp?: string) =>
    engine.advance(
      null,
      { step: STEP_URNS.password, fields: { password, login_hint: identifier } },
      context(endUserIp)
    );

  const isThrottled = (result: RoundResult) =>
    result.kind === 'refused' && result.reason === 'throttled';
  const isRefusedCredential = (result: RoundResult) =>
    result.kind === 'step' && result.offer.current.error === 'invalid_credentials';

  const disabledAt = async (identifier: string) =>
    (await userCredentials.findByRealmProviderSub(realmId, 'password', identifier))?.disabledAt ??
    null;

  /** The ladder's counter of the identifier's password, as Redis holds it. */
  const counter = async (identifier: string) => {
    const hmac = await identifierDigest({ realmId, identifier });
    return redis?.hgetall(ladderCounterKey(realmId, hmac, 'password'));
  };

  /** `count` wrong passwords, a quarter of an hour apart, so no wait holds one back. */
  const failSpaced = async (identifier: string, count: number, endUserIp?: string) => {
    for (let i = 0; i < count; i += 1) {
      expect(isRefusedCredential(await attempt(identifier, 'wrong', endUserIp))).toBe(true);
      now += QUARTER_HOUR;
    }
  };

  it('lets 200 parallel wrong passwords, each in its own transaction, reach the verifier no more often than 200 sent one at a time', async (testCtx) => {
    if (!dockerUp) return testCtx.skip();
    await seed('parallel@example.com');
    await seed('sequential@example.com');

    const beforeParallel = verified.count;
    const parallel = await Promise.all(
      Array.from({ length: 200 }, () => attempt('parallel@example.com', 'wrong'))
    );
    const parallelVerified = verified.count - beforeParallel;

    const beforeSequential = verified.count;
    for (let i = 0; i < 200; i += 1) await attempt('sequential@example.com', 'wrong');
    const sequentialVerified = verified.count - beforeSequential;

    expect(parallelVerified).toBeLessThanOrEqual(sequentialVerified);
    // On a clock that does not move, both stop at the free failures.
    expect(sequentialVerified).toBe(PASSWORD_LADDER_POLICY.freeFailures);
    expect(parallel.filter(isThrottled)).toHaveLength(200 - parallelVerified);
  });

  it('refuses an attempt inside the wait without verifying or counting it, the right password included', async (testCtx) => {
    if (!dockerUp) return testCtx.skip();
    await seed('wait@example.com');
    for (let i = 0; i < PASSWORD_LADDER_POLICY.freeFailures; i += 1) {
      expect(isRefusedCredential(await attempt('wait@example.com', 'wrong'))).toBe(true);
    }
    const before = verified.count;
    const refused = await attempt('wait@example.com', PASSWORD);
    expect(refused).toMatchObject({ kind: 'refused', reason: 'throttled', retryAfterSeconds: 1 });
    expect(verified.count).toBe(before);
    expect(await counter('wait@example.com')).toMatchObject({ n: '5' });

    // Once the wait is over the right password signs in, and clears the counter.
    now += 1_000;
    expect(await attempt('wait@example.com', PASSWORD)).toMatchObject({ kind: 'complete' });
    expect(await counter('wait@example.com')).toEqual({});
  });

  it('disables the password at the 100th counted failure only while the hard action is armed', async (testCtx) => {
    if (!dockerUp) return testCtx.skip();
    await seed('armed@example.com');
    await seed('unarmed@example.com');
    notices.passwordDisabled.mockClear();

    hostedReset = true;
    try {
      await failSpaced('armed@example.com', 99);
      expect(await disabledAt('armed@example.com')).toBeNull();
      await failSpaced('armed@example.com', 1);
      expect(await disabledAt('armed@example.com')).toEqual(expect.any(Number));
      expect(notices.passwordDisabled).toHaveBeenCalledTimes(1);
      // Disabled: the right password is refused like a wrong one.
      expect(isRefusedCredential(await attempt('armed@example.com', PASSWORD))).toBe(true);
    } finally {
      hostedReset = false;
    }

    await failSpaced('unarmed@example.com', 100);
    expect(await disabledAt('unarmed@example.com')).toBeNull();
    expect(notices.passwordDisabled).toHaveBeenCalledTimes(1);
    now += QUARTER_HOUR;
    expect(await attempt('unarmed@example.com', PASSWORD)).toMatchObject({ kind: 'complete' });
  });

  it('ignores a disabled mark while the hard action is unarmed: the user signs in, and the mark is cleared', async (testCtx) => {
    if (!dockerUp) return testCtx.skip();
    await seed('marked@example.com');
    await userCredentials.setDisabledAt(realmId, 'password', 'marked@example.com', Date.now());

    // Armed, the mark holds: the right password is refused.
    hostedReset = true;
    try {
      expect(isRefusedCredential(await attempt('marked@example.com', PASSWORD))).toBe(true);
    } finally {
      hostedReset = false;
    }
    expect(await disabledAt('marked@example.com')).toEqual(expect.any(Number));

    // Unarmed, it is ignored, and the sign-in clears it.
    expect(await attempt('marked@example.com', PASSWORD)).toMatchObject({ kind: 'complete' });
    expect(await disabledAt('marked@example.com')).toBeNull();
  });

  it('lets a known IP skip the wait while every attempt still counts toward the 100th', async (testCtx) => {
    if (!dockerUp) return testCtx.skip();
    await seed('known@example.com');
    expect(await attempt('known@example.com', PASSWORD, KNOWN_IP)).toMatchObject({
      kind: 'complete',
    });

    hostedReset = true;
    try {
      // The clock stands still: only the exemption lets these through.
      for (let i = 0; i < 99; i += 1) {
        expect(isRefusedCredential(await attempt('known@example.com', 'wrong', KNOWN_IP))).toBe(
          true
        );
      }
      expect(await counter('known@example.com')).toMatchObject({ n: '99' });
      expect(isThrottled(await attempt('known@example.com', 'wrong', OTHER_IP))).toBe(true);
      expect(await disabledAt('known@example.com')).toBeNull();
      await attempt('known@example.com', 'wrong', KNOWN_IP);
      expect(await disabledAt('known@example.com')).toEqual(expect.any(Number));
    } finally {
      hostedReset = false;
    }
  });

  it('counts the legacy login routes’ attempts on the same ladder as the engine’s', async (testCtx) => {
    if (!dockerUp || redis === undefined) return testCtx.skip();
    await seed('shared@example.com');
    const gate = createPasswordAttempts({
      identifierDigest,
      ladder: createRedisFailureLadder(redis, { ipDigest, now: () => now }),
      hardAction: createPasswordHardAction({
        credentials: userCredentials,
        arming: { hostedReset: () => false },
        log: silent,
      }),
      hardActionArmed: async () => false,
      log: silent,
    });
    for (let i = 0; i < 3; i += 1) await attempt('shared@example.com', 'wrong');
    for (let i = 0; i < 2; i += 1) {
      const reserved = await gate.reserve({ realmId, identifier: 'shared@example.com' });
      if (reserved.kind !== 'reserved') throw new Error('expected a reservation');
      await reserved.failed(async () => null);
    }
    expect(isThrottled(await attempt('shared@example.com', PASSWORD))).toBe(true);
    expect(await gate.reserve({ realmId, identifier: 'shared@example.com' })).toMatchObject({
      kind: 'wait',
    });
  });

  it('keeps no address in any Redis key or value', async (testCtx) => {
    if (!dockerUp || redis === undefined) return testCtx.skip();
    const keys = await redis.keys('*');
    expect(keys.length).toBeGreaterThan(0);
    const stored: string[] = [...keys];
    for (const key of keys) {
      const type = await redis.type(key);
      if (type === 'hash') stored.push(...Object.values(await redis.hgetall(key)));
      if (type === 'zset') stored.push(...(await redis.zrange(key, 0, -1)));
    }
    const text = stored.join('\n');
    for (const forbidden of ['@example.com', KNOWN_IP, OTHER_IP]) {
      expect(text).not.toContain(forbidden);
    }
  });

  it('refuses the round before any credential is checked when Redis is stopped', async (testCtx) => {
    if (!dockerUp) return testCtx.skip();
    await seed('down@example.com');
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
      engine = buildEngine(client, 1_000);
      const lookups = vi.spyOn(userCredentials, 'findByRealmProviderSub');
      const before = verified.count;
      const result = await attempt('down@example.com', PASSWORD);
      expect(result).toMatchObject({ kind: 'refused', reason: 'unavailable' });
      expect(verified.count).toBe(before);
      expect(lookups).not.toHaveBeenCalled();
      lookups.mockRestore();

      const gate = createPasswordAttempts({
        identifierDigest,
        ladder: createRedisFailureLadder(client, { ipDigest, timeoutMs: 1_000 }),
        hardAction: createPasswordHardAction({
          credentials: userCredentials,
          arming: { hostedReset: () => false },
          log: silent,
        }),
        hardActionArmed: async () => false,
        log: silent,
      });
      await expect(
        gate.reserve({ realmId, identifier: 'down@example.com', endUserIp: KNOWN_IP })
      ).rejects.toBeInstanceOf(SignInStoreUnavailableError);
    } finally {
      engine = buildEngine(ladderRedis);
      client.disconnect();
    }
  });
});
