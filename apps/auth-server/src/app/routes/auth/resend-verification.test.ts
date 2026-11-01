import { TooManyRequestsError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    DEFAULT_REALM_NAME: 'master',
    RESEND_VERIFICATION_RATE_LIMIT: 10,
    RESEND_VERIFICATION_RATE_WINDOW: 900,
    RESEND_VERIFICATION_EMAIL_LIMIT: 3,
    RESEND_VERIFICATION_EMAIL_WINDOW: 3600,
    RESEND_VERIFICATION_MIN_INTERVAL: 60,
    EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND: true,
    EMAIL_VERIFICATION_TOKEN_EXPIRY: 3600,
  },
}));

// Zero out the anti-enumeration response-time floor so tests don't sleep.
vi.mock('../../constants', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../constants')>();
  return {
    ...original,
    MIN_RESPONSE_TIME_MS: { ...original.MIN_RESPONSE_TIME_MS, RESEND_VERIFICATION: 0 },
  };
});

import { testRealm } from '../../../testing/request-realm';
import { REDIS_KEYS, SUCCESS_MESSAGES } from '../../constants';
import resendRoute from './resend-verification';

interface TestContext {
  handler?: (request: any) => Promise<unknown>;
  onClose?: () => Promise<unknown>;
}

function credentialFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 'cred-1',
    userId: 'user-1',
    realmId: 'realm-1',
    providerType: 'password',
    externalSub: 'user@example.com',
    credentialData: { password_hash: 'hash', email_verified: false },
    ...overrides,
  };
}

function createFastifyStub() {
  const ctx: TestContext = {};
  const fastify: any = {
    withTypeProvider: () => ({
      post: (_url: string, _opts: unknown, handler: any) => {
        ctx.handler = handler;
        return fastify;
      },
    }),
    addHook: (name: string, hook: () => Promise<unknown>) => {
      if (name === 'onClose') ctx.onClose = hook;
      return fastify;
    },
    repositories: {
      userCredentials: {
        findByRealmProviderSub: vi.fn(),
      },
      users: {
        findById: vi.fn().mockResolvedValue({
          id: 'user-1',
          email: 'User@Example.com',
          emailVerified: false,
          enabled: true,
        }),
      },
      emailVerificationTokens: {
        invalidateCredentialTokens: vi.fn().mockResolvedValue(1),
        create: vi.fn().mockResolvedValue({ id: 'token-2' }),
      },
    },
    emailVerificationTokenUtils: {
      generateVerificationToken: vi.fn().mockReturnValue({ token: 'plain', tokenHash: 'hashed' }),
    },
    emailService: {
      sendVerificationEmail: vi.fn().mockResolvedValue(undefined),
    },
    redis: {
      incr: vi.fn().mockResolvedValue(1),
      expire: vi.fn().mockResolvedValue(1),
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn().mockResolvedValue('OK'),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

/** The realm the realm resolver (#486) decorated the request with. */
const REALM = testRealm({ id: 'realm-1' });

const request = {
  body: { email: 'user@example.com' },
  ip: '127.0.0.1',
  headers: {},
  realm: REALM,
};

/**
 * In-memory Redis with the commands the route uses (incr, expire, get, set
 * with EX and optional NX), for the tests that need real interleaving.
 */
function createMemoryRedis() {
  const store = new Map<string, string>();
  return {
    incr: vi.fn(async (key: string) => {
      const next = Number(store.get(key) ?? '0') + 1;
      store.set(key, String(next));
      return next;
    }),
    expire: vi.fn(async () => 1),
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    set: vi.fn(async (key: string, value: string, _ex: 'EX', _seconds: number, nx?: 'NX') => {
      if (nx === 'NX' && store.has(key)) return null;
      store.set(key, value);
      return 'OK';
    }),
  };
}

describe('POST /auth/resend-verification', () => {
  it('re-sends for an unverified credential: user_id-keyed invalidation + dual-id token', async () => {
    const { fastify, ctx } = createFastifyStub();
    await resendRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());

    const result = await ctx.handler(request);

    expect(fastify.repositories.userCredentials.findByRealmProviderSub).toHaveBeenCalledWith(
      'realm-1',
      'password',
      'user@example.com'
    );
    // #230: invalidation is credential-keyed (user_id no longer exists on
    // the tokens table).
    expect(
      fastify.repositories.emailVerificationTokens.invalidateCredentialTokens
    ).toHaveBeenCalledWith('cred-1');
    expect(fastify.repositories.emailVerificationTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({ credentialId: 'cred-1', tokenHash: 'hashed' })
    );
    // #230: the outbound address is the credential's external_sub — the
    // registered normalized form (users.email no longer exists).
    expect(fastify.emailService.sendVerificationEmail).toHaveBeenCalledWith(
      REALM.id,
      'user@example.com',
      'plain',
      { baseUrl: REALM.issuer }
    );
    expect(result).toEqual({ message: SUCCESS_MESSAGES.RESEND_VERIFICATION });
  });

  it('returns the same generic success for an unknown email without any writes', async () => {
    const { fastify, ctx } = createFastifyStub();
    await resendRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(undefined);

    const result = await ctx.handler(request);

    expect(result).toEqual({ message: SUCCESS_MESSAGES.RESEND_VERIFICATION });
    expect(fastify.repositories.emailVerificationTokens.create).not.toHaveBeenCalled();
    expect(fastify.emailService.sendVerificationEmail).not.toHaveBeenCalled();
  });

  it('returns the same generic success for a disabled account without minting or sending', async () => {
    const { fastify, ctx } = createFastifyStub();
    await resendRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-1',
      enabled: false,
    });

    const result = await ctx.handler(request);

    expect(result).toEqual({ message: SUCCESS_MESSAGES.RESEND_VERIFICATION });
    // Looked up in the request's realm (#489).
    expect(fastify.repositories.users.findById).toHaveBeenCalledWith(REALM.id, 'user-1');
    expect(
      fastify.repositories.emailVerificationTokens.invalidateCredentialTokens
    ).not.toHaveBeenCalled();
    expect(fastify.repositories.emailVerificationTokens.create).not.toHaveBeenCalled();
    expect(fastify.emailService.sendVerificationEmail).not.toHaveBeenCalled();
  });

  it('returns the same generic success for an already-verified credential without sending', async () => {
    const { fastify, ctx } = createFastifyStub();
    await resendRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(
      credentialFixture({ credentialData: { password_hash: 'hash', email_verified: true } })
    );

    const result = await ctx.handler(request);

    expect(result).toEqual({ message: SUCCESS_MESSAGES.RESEND_VERIFICATION });
    expect(fastify.repositories.emailVerificationTokens.create).not.toHaveBeenCalled();
  });

  it('treats malformed credential_data like an unknown email and logs for operators', async () => {
    const { fastify, ctx } = createFastifyStub();
    await resendRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture({ credentialData: { broken: true } }));

    const result = await ctx.handler(request);

    expect(result).toEqual({ message: SUCCESS_MESSAGES.RESEND_VERIFICATION });
    expect(fastify.repositories.emailVerificationTokens.create).not.toHaveBeenCalled();
    expect(fastify.log.error).toHaveBeenCalledWith(
      expect.objectContaining({ credentialId: 'cred-1' }),
      expect.stringContaining('malformed credential_data')
    );
  });

  it('enforces the per-email rate limit with TooManyRequestsError', async () => {
    const { fastify, ctx } = createFastifyStub();
    await resendRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (fastify.redis.incr as unknown as Mock).mockResolvedValue(4);

    await expect(ctx.handler(request)).rejects.toThrow(TooManyRequestsError);
    expect(fastify.repositories.userCredentials.findByRealmProviderSub).not.toHaveBeenCalled();
  });

  describe('delivery runs off the request path (KCEQXFCA)', () => {
    /** A send the test settles by hand, like a slow mail provider. */
    function deferredSend(fastify: FastifyInstance) {
      const control: { resolve?: () => void; reject?: (error: Error) => void } = {};
      (fastify.emailService.sendVerificationEmail as unknown as Mock).mockImplementation(
        () =>
          new Promise<void>((resolve, reject) => {
            control.resolve = resolve;
            control.reject = reject;
          })
      );
      return control;
    }

    /** Settles to 'pending' if `promise` has not settled within a few ticks. */
    async function settledSoon(promise: Promise<unknown>): Promise<string> {
      return Promise.race([
        promise.then(
          () => 'settled',
          () => 'settled'
        ),
        new Promise<string>((resolve) => setTimeout(() => resolve('pending'), 50)),
      ]);
    }

    it('answers a registered, unverified address without waiting for the mail provider', async () => {
      const { fastify, ctx } = createFastifyStub();
      await resendRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');
      (
        fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
      ).mockResolvedValue(credentialFixture());
      const send = deferredSend(fastify);

      const answer = ctx.handler(request);

      // A slow delivery must not show in the response time: only this branch
      // sends, so waiting for it told registered from unknown addresses.
      expect(await settledSoon(answer)).toBe('settled');
      await expect(answer).resolves.toEqual({ message: SUCCESS_MESSAGES.RESEND_VERIFICATION });
      expect(fastify.emailService.sendVerificationEmail).toHaveBeenCalledWith(
        REALM.id,
        'user@example.com',
        'plain',
        { baseUrl: REALM.issuer }
      );
      send.resolve?.();
    });

    it('waits on server close for a delivery still in flight', async () => {
      const { fastify, ctx } = createFastifyStub();
      await resendRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');
      (
        fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
      ).mockResolvedValue(credentialFixture());
      const send = deferredSend(fastify);

      await ctx.handler(request);
      if (!ctx.onClose) throw new Error('No onClose hook registered');
      const closing = ctx.onClose();

      // The mail is not dropped on shutdown: close waits for it.
      expect(await settledSoon(closing)).toBe('pending');
      send.resolve?.();
      await expect(closing).resolves.toBeUndefined();
    });

    it('still logs a failed delivery, and close does not fail on it', async () => {
      const { fastify, ctx } = createFastifyStub();
      await resendRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');
      (
        fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
      ).mockResolvedValue(credentialFixture());
      const send = deferredSend(fastify);

      await expect(ctx.handler(request)).resolves.toEqual({
        message: SUCCESS_MESSAGES.RESEND_VERIFICATION,
      });
      if (!ctx.onClose) throw new Error('No onClose hook registered');
      const closing = ctx.onClose();
      send.reject?.(new Error('smtp down'));

      await expect(closing).resolves.toBeUndefined();
      expect(fastify.log.error).toHaveBeenCalledWith(
        expect.any(Error),
        'Failed to send verification email'
      );
    });
  });

  it('claims the minimum interval atomically: of requests sent together only one sends (F2FJ182D)', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as unknown as { redis: unknown }).redis = createMemoryRedis();
    await resendRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    // A real provider takes a while to deliver.
    (fastify.emailService.sendVerificationEmail as unknown as Mock).mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 5))
    );

    const results = await Promise.allSettled([
      ctx.handler(request),
      ctx.handler(request),
      ctx.handler(request),
    ]);

    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    for (const result of results.filter((r) => r.status === 'rejected')) {
      expect((result as PromiseRejectedResult).reason).toBeInstanceOf(TooManyRequestsError);
    }
    expect(fastify.emailService.sendVerificationEmail).toHaveBeenCalledTimes(1);
  });

  it('claims the minimum interval before the credential lookup, for every address alike (F2FJ182D)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await resendRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    const lookup = fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock;
    const set = fastify.redis.set as unknown as Mock;

    // Registered, unverified address ...
    lookup.mockResolvedValue(credentialFixture());
    await ctx.handler(request);
    // ... and an unknown one: the marker is written once, before the lookup,
    // in both cases, so a second request cannot tell them apart by status.
    lookup.mockResolvedValue(undefined);
    await ctx.handler(request);

    expect(set).toHaveBeenCalledTimes(2);
    expect(set).toHaveBeenCalledWith(
      REDIS_KEYS.LAST_EMAIL_SENT(REALM.id, 'user@example.com'),
      expect.any(String),
      'EX',
      60,
      'NX'
    );
    expect(set.mock.invocationCallOrder[0]).toBeLessThan(lookup.mock.invocationCallOrder[0]);
    expect(set.mock.invocationCallOrder[1]).toBeLessThan(lookup.mock.invocationCallOrder[1]);
  });

  it('keys its Redis counters on a digest of the address, never the address itself', async () => {
    // These keys are written for EVERY request, account or not, before any
    // lookup. Holding the address verbatim made each request an hour-long
    // Redis key as long as the caller's address: ~1.25 MiB per anonymous
    // request at 100 requests a minute.
    const { fastify, ctx } = createFastifyStub();
    await resendRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    const address = `${'a'.repeat(200)}@example.com`;
    await ctx.handler({ ...request, body: { email: address } });

    const counterKey = (fastify.redis.incr as unknown as Mock).mock.calls[0][0] as string;
    const lastSentKey = (fastify.redis.set as unknown as Mock).mock.calls[0][0] as string;
    for (const key of [counterKey, lastSentKey]) {
      expect(key).not.toContain('example.com');
      expect(key).toMatch(/:[0-9a-f]{64}$/);
    }
    // Still one counter per address, and the same one for every request.
    await ctx.handler({ ...request, body: { email: address.toUpperCase() } });
    expect((fastify.redis.incr as unknown as Mock).mock.calls[1][0]).toBe(counterKey);
  });
});
