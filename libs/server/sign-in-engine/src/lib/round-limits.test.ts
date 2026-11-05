import { describe, expect, it, vi } from 'vitest';

import { fakeIdentifierDigest } from '../testing/fakes';
import { createMemoryRoundLimits } from '../testing/memory-round-limits';
import {
  checkRoundLimitPolicy,
  createRoundLimiter,
  type CredentialRoundKeys,
  DEVELOPMENT_ROUND_LIMIT_FACTOR,
  endUserIpBucket,
  isCredentialAnswer,
  relaxedRoundLimitPolicy,
  ROUND_LIMIT_POLICY,
  roundEnvironmentOf,
  type RoundLimitAlertEvent,
  roundLimitPolicies,
  roundLimitPolicy,
  roundLimitPolicyFor,
  type RoundLimitStore,
} from './round-limits';
import type { SignInTransaction } from './transaction';

/**
 * The round limits' rules (PRO-13, #636; ADR-017 Decision 7): the numbers,
 * development's relaxation (ADR-008 §5), the IP bucket, what counts as a
 * credential round, and the limiter between the engine and a store. The
 * stores' own behaviour is the contract of `round-limit-store-contract.ts`.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const CLIENT = 'native-app';
const T0 = 1_800_000_000_000;
const MINUTE = 60_000;
const TRANSACTION = {
  v: 1,
  realmId: REALM,
  clientId: CLIENT,
  createdAt: T0,
  verified: [],
} as unknown as SignInTransaction;

describe('the round limit policy', () => {
  it('holds the numbers of ADR-017 Decision 7 by default', () => {
    expect(ROUND_LIMIT_POLICY).toEqual({
      endUserIp: {
        windowMs: 15 * MINUTE,
        softFailures: 10,
        hardFailures: 30,
        blockMs: 15 * MINUTE,
        delayMs: 30_000,
      },
      ipBucket: { windowMs: 15 * MINUTE, maxIdentifiers: 20, delayMs: 30_000 },
      client: {
        windowMs: 5 * MINUTE,
        ratioMinRounds: 200,
        ratioPercent: 50,
        // A tenth of 600 rounds a minute over 5 minutes.
        failureBudget: 300,
        delayMs: 1_000,
        maxRounds: 600,
        maxRoundsWindowMs: MINUTE,
      },
      registrationStarts: {
        endUserIp: { limit: 3, windowMs: 60 * MINUTE },
        client: { limit: 1_000, windowMs: 60 * MINUTE },
      },
    });
  });

  it('derives the client’s failure budget and its delay from FIRST_PARTY_CLIENT_MAX_ROUNDS', () => {
    const policy = roundLimitPolicy({ clientMaxRounds: 1_200 });
    expect(policy.client).toMatchObject({ maxRounds: 1_200, failureBudget: 600, delayMs: 500 });
    expect(roundLimitPolicy({ clientMaxRounds: 1 }).client.failureBudget).toBe(1);
  });

  it('takes the per-IP registration cap from REGISTRATION_RATE_LIMIT and its window', () => {
    const policy = roundLimitPolicy({ registrationPerIp: { limit: 5, windowMs: 10 * MINUTE } });
    expect(policy.registrationStarts.endUserIp).toEqual({ limit: 5, windowMs: 10 * MINUTE });
  });

  it('relaxes every count tenfold in development, and keeps production values in staging', () => {
    const policies = roundLimitPolicies(ROUND_LIMIT_POLICY);
    const development = roundLimitPolicyFor('development', policies);
    expect(roundLimitPolicyFor('staging', policies)).toBe(ROUND_LIMIT_POLICY);
    expect(roundLimitPolicyFor('production', policies)).toBe(ROUND_LIMIT_POLICY);
    expect(development).not.toEqual(ROUND_LIMIT_POLICY);
    const f = DEVELOPMENT_ROUND_LIMIT_FACTOR;
    expect(development.endUserIp).toMatchObject({
      softFailures: 10 * f,
      hardFailures: 30 * f,
      delayMs: 3_000,
      windowMs: 15 * MINUTE,
      blockMs: 15 * MINUTE,
    });
    expect(development.ipBucket.maxIdentifiers).toBe(20 * f);
    expect(development.client).toMatchObject({
      ratioMinRounds: 200 * f,
      ratioPercent: 50,
      failureBudget: 300 * f,
      maxRounds: 600 * f,
    });
    expect(development.registrationStarts.endUserIp.limit).toBe(3 * f);
    expect(relaxedRoundLimitPolicy(ROUND_LIMIT_POLICY)).toEqual(development);
  });

  it('reads anything but development, staging and production as production', () => {
    expect(roundEnvironmentOf('development')).toBe('development');
    expect(roundEnvironmentOf('staging')).toBe('staging');
    for (const value of ['Development', 'dev', '', undefined, null, 1, {}]) {
      expect(roundEnvironmentOf(value)).toBe('production');
    }
  });

  it('refuses a policy whose limits cannot hold', () => {
    const p = ROUND_LIMIT_POLICY;
    const broken = [
      { ...p, endUserIp: { ...p.endUserIp, softFailures: 31 } },
      { ...p, endUserIp: { ...p.endUserIp, hardFailures: 0 } },
      { ...p, endUserIp: { ...p.endUserIp, windowMs: 999 } },
      { ...p, endUserIp: { ...p.endUserIp, delayMs: p.endUserIp.windowMs + 1 } },
      { ...p, ipBucket: { ...p.ipBucket, maxIdentifiers: 0.5 } },
      { ...p, client: { ...p.client, ratioPercent: 100 } },
      { ...p, client: { ...p.client, ratioPercent: 0 } },
      { ...p, client: { ...p.client, failureBudget: Number.NaN } },
      { ...p, client: { ...p.client, delayMs: 0 } },
      {
        ...p,
        registrationStarts: { ...p.registrationStarts, client: { limit: 0, windowMs: MINUTE } },
      },
    ];
    for (const policy of broken) expect(() => checkRoundLimitPolicy(policy)).toThrow();
    expect(checkRoundLimitPolicy(p)).toBe(p);
  });
});

describe('a credential round', () => {
  it('carries a password, an otp, a recovery code or a WebAuthn response', () => {
    for (const member of ['password', 'otp', 'recovery_code', 'webauthn_response']) {
      expect(isCredentialAnswer({ [member]: 'x' }), member).toBe(true);
    }
  });

  it('is not an answer of an identifier, a choice, a bot challenge or nothing', () => {
    expect(isCredentialAnswer({ login_hint: 'alice@example.com' })).toBe(false);
    expect(isCredentialAnswer({ choice: 'password' })).toBe(false);
    expect(isCredentialAnswer({ challenge_response: 'token' })).toBe(false);
    expect(isCredentialAnswer({ password: undefined })).toBe(false);
    expect(isCredentialAnswer(Object.create({ password: 'inherited' }))).toBe(false);
    expect(isCredentialAnswer(null)).toBe(false);
    expect(isCredentialAnswer('password')).toBe(false);
  });
});

describe('the end-user IP’s bucket', () => {
  it('is an IPv4 address’s /24 and an IPv6 address’s /48', () => {
    expect(endUserIpBucket('203.0.113.7')).toBe('203.0.113.0/24');
    expect(endUserIpBucket('2001:db8:1:2::')).toBe('2001:db8:1::/48');
    expect(endUserIpBucket('2001:DB8:1:2:3:4:5:6')).toBe('2001:db8:1::/48');
    expect(endUserIpBucket('2001:db8::1')).toBe('2001:db8:0::/48');
  });

  it('buckets every /64 of one /48 together, and two /48s apart', () => {
    expect(endUserIpBucket('2001:db8:1:2::')).toBe(endUserIpBucket('2001:db8:1:ffff::'));
    expect(endUserIpBucket('2001:db8:1::')).not.toBe(endUserIpBucket('2001:db8:2::'));
  });

  it('buckets a translated or IPv4-mapped address by its IPv4 client’s /24', () => {
    expect(endUserIpBucket('64:ff9b::203.0.113.7')).toBe('203.0.113.0/24');
    expect(endUserIpBucket('64:ff9b::cb00:7107')).toBe('203.0.113.0/24');
    expect(endUserIpBucket('::ffff:203.0.113.7')).toBe('203.0.113.0/24');
    // Not every IPv4 address behind one shared bucket.
    expect(endUserIpBucket('::ffff:198.51.100.1')).not.toBe(endUserIpBucket('::ffff:203.0.113.7'));
  });

  it('keeps a value that is no address as its own bucket', () => {
    expect(endUserIpBucket('unix-socket')).toBe('unix-socket');
  });
});

describe('the round limiter', () => {
  const ipDigest = fakeIdentifierDigest;
  const memory = (now = () => T0) => createMemoryRoundLimits(now);

  it('keys a round by the HMACs of its end-user IP and its bucket, and its client only where the client row applies', async () => {
    const store = memory();
    const reserve = vi.spyOn(store, 'reserveCredential');
    const admit = vi.spyOn(store, 'admitRound');
    const interaction = createRoundLimiter(store, { ipDigest, perClient: false });
    await interaction.round({
      realmId: REALM,
      clientId: CLIENT,
      transaction: TRANSACTION,
      endUserIp: '203.0.113.7',
      environment: 'production',
    });
    expect(admit).toHaveBeenCalledWith({
      realmId: REALM,
      environment: 'production',
      endUserIpHmac: await ipDigest({ realmId: REALM, identifier: '203.0.113.7' }),
      ipBucketHmac: await ipDigest({ realmId: REALM, identifier: '203.0.113.0/24' }),
    });

    const fipa = createRoundLimiter(store, { ipDigest, perClient: true });
    const verdict = await fipa.reserve({
      realmId: REALM,
      clientId: CLIENT,
      environment: 'staging',
      identifierHmac: 'identifier-hmac',
    });
    expect(verdict.kind).toBe('reserved');
    const keys = reserve.mock.calls[0]?.[0] as CredentialRoundKeys;
    expect(keys).toMatchObject({
      realmId: REALM,
      environment: 'staging',
      clientKey: CLIENT,
      identifierHmac: 'identifier-hmac',
    });
    expect(keys.reservation).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(keys).not.toHaveProperty('endUserIpHmac');
    expect(JSON.stringify(admit.mock.calls)).not.toContain('203.0.113');
  });

  it('settles a reservation once, a success with its account', async () => {
    const store = memory();
    const settle = vi.spyOn(store, 'settleCredential');
    const limiter = createRoundLimiter(store, { ipDigest, perClient: true });
    const reservation = await limiter.reserve({
      realmId: REALM,
      clientId: CLIENT,
      environment: 'production',
    });
    if (reservation.kind !== 'reserved') throw new Error('refused');
    await reservation.settle('success', { userId: 'user-1' });
    expect(settle).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: 'success', accountKey: 'user-1', clientKey: CLIENT })
    );
    await expect(reservation.settle('failure')).rejects.toThrow(/twice/);
    expect(settle).toHaveBeenCalledTimes(1);
  });

  it('turns a refusal into a throttled verdict of whole seconds', async () => {
    const store: RoundLimitStore = {
      ...memory(),
      admitRound: async () => ({
        kind: 'refused',
        limit: 'end_user_ip',
        retryAfterMs: 1_001,
        alerts: [],
      }),
      reserveCredential: async () => ({
        kind: 'refused',
        limit: 'end_user_ip_delay',
        retryAfterMs: 1,
        alerts: [],
      }),
    };
    const limiter = createRoundLimiter(store, { ipDigest, perClient: false });
    const round = { realmId: REALM, clientId: CLIENT, environment: 'production' } as const;
    expect(await limiter.round({ ...round, transaction: TRANSACTION })).toEqual({
      kind: 'throttled',
      retryAfterSeconds: 2,
    });
    expect(await limiter.reserve(round)).toEqual({ kind: 'throttled', retryAfterSeconds: 1 });
  });

  it('fails closed on a store that answers out of shape', async () => {
    const odd = (value: unknown) =>
      ({
        ...memory(),
        admitRound: async () => value,
        reserveCredential: async () => value,
      }) as unknown as RoundLimitStore;
    const round = { realmId: REALM, clientId: CLIENT, environment: 'production' } as const;
    for (const value of [
      undefined,
      { kind: 'maybe' },
      { kind: 'refused', limit: 'nothing', retryAfterMs: 1, alerts: [] },
      { kind: 'refused', limit: 'end_user_ip', retryAfterMs: Number.NaN, alerts: [] },
    ]) {
      const limiter = createRoundLimiter(odd(value), { ipDigest, perClient: false });
      await expect(limiter.round({ ...round, transaction: TRANSACTION })).rejects.toThrow();
      await expect(limiter.reserve(round)).rejects.toThrow();
    }
  });

  it('tells the operator of each alert with the key it concerns, and no reporter changes the answer', async () => {
    let now = T0;
    const store = createMemoryRoundLimits(() => now);
    const alerts: RoundLimitAlertEvent[] = [];
    const limiter = createRoundLimiter(store, {
      ipDigest,
      perClient: false,
      onAlert: (event) => {
        alerts.push(event);
        throw new Error('the pager is down');
      },
    });
    const round = {
      realmId: REALM,
      clientId: CLIENT,
      endUserIp: '203.0.113.7',
      environment: 'production',
    } as const;
    for (let i = 0; i < 30; i += 1) {
      const reservation = await limiter.reserve(round);
      if (reservation.kind !== 'reserved') throw new Error(`round ${i} refused`);
      await reservation.settle('failure');
      now += 30_000;
    }
    expect(alerts).toEqual([
      {
        realmId: REALM,
        alert: 'end_user_ip_blocked',
        endUserIpHmac: await ipDigest({ realmId: REALM, identifier: '203.0.113.7' }),
      },
    ]);
    expect(await limiter.reserve(round)).toMatchObject({ kind: 'throttled' });
  });

  it('caps registration starts per IP and, where the client row applies, per client', async () => {
    const limiter = createRoundLimiter(memory(), { ipDigest, perClient: true });
    const start = { realmId: REALM, clientId: CLIENT, endUserIp: '203.0.113.7' };
    for (let i = 0; i < 3; i += 1) {
      expect(await limiter.reserveRegistrationStart(start)).toEqual({ kind: 'continue' });
    }
    expect(await limiter.reserveRegistrationStart(start)).toEqual({
      kind: 'throttled',
      retryAfterSeconds: 3_600,
    });
    expect(await limiter.reserveRegistrationStart({ ...start, endUserIp: '198.51.100.9' })).toEqual(
      { kind: 'continue' }
    );
    // Development relaxes the cap.
    expect(
      await limiter.reserveRegistrationStart({ ...start, environment: 'development' })
    ).toEqual({ kind: 'continue' });
  });
});
