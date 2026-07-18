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

import { SUCCESS_MESSAGES } from '../../constants';
import resendRoute from './resend-verification';

interface TestContext {
  handler?: (request: any) => Promise<unknown>;
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
    repositories: {
      realms: {
        findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'master', enabled: true }),
        create: vi.fn(),
      },
      userCredentials: {
        findByRealmProviderSub: vi.fn(),
      },
      users: {
        findById: vi
          .fn()
          .mockResolvedValue({ id: 'user-1', email: 'User@Example.com', emailVerified: false }),
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

const request = { body: { email: 'user@example.com' }, ip: '127.0.0.1', headers: {} };

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
      'user@example.com',
      'plain'
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
});
