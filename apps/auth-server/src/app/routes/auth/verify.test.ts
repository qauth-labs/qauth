import {
  EmailAlreadyVerifiedError,
  InvalidTokenError,
  NotFoundError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    VERIFICATION_RATE_LIMIT: 10,
    VERIFICATION_RATE_WINDOW: 900,
  },
}));

import verifyRoute from './verify';

interface TestContext {
  handler?: (request: any) => Promise<unknown>;
}

/** Sentinel transaction client shared by the completion write set. */
const TX = { __tx: 'verify-tx' };

function tokenFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 'token-1',
    tokenHash: 'hashed',
    userId: 'user-1',
    credentialId: 'cred-1',
    expiresAt: Date.now() + 3600_000,
    used: false,
    ...overrides,
  };
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
      get: (_url: string, _opts: unknown, handler: any) => {
        ctx.handler = handler;
        return fastify;
      },
    }),
    db: {
      transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(TX)),
    },
    repositories: {
      emailVerificationTokens: {
        findByTokenHash: vi.fn(),
        markUsed: vi.fn().mockResolvedValue({}),
      },
      userCredentials: {
        findById: vi.fn(),
        findByUserIdAndType: vi.fn(),
        setEmailVerified: vi.fn().mockResolvedValue({}),
      },
      userAttributes: {
        setVerified: vi.fn().mockResolvedValue({ id: 'attr-1' }),
      },
      users: {
        findById: vi.fn().mockResolvedValue({
          id: 'user-1',
          email: 'user@example.com',
          emailVerified: false,
        }),
        verifyEmail: vi.fn().mockResolvedValue({}),
      },
    },
    emailVerificationTokenUtils: {
      hashToken: vi.fn().mockReturnValue('hashed'),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

const request = { query: { token: 'a'.repeat(64) } };

describe('GET /auth/verify', () => {
  it('completes verification with the four-write set in one transaction and exact body', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture()
    );

    const result = await ctx.handler(request);

    expect(fastify.db.transaction).toHaveBeenCalledOnce();
    // The complete dual-write set, all on the same transaction client:
    expect(fastify.repositories.emailVerificationTokens.markUsed).toHaveBeenCalledWith(
      'token-1',
      TX
    );
    expect(fastify.repositories.userCredentials.setEmailVerified).toHaveBeenCalledWith(
      'cred-1',
      TX
    );
    expect(fastify.repositories.userAttributes.setVerified).toHaveBeenCalledWith(
      'user-1',
      'self_reported',
      'email',
      true,
      TX
    );
    // Legacy dual-write keeps REQUIRE_EMAIL_VERIFIED, current JWT claims, and
    // a rolled-back binary truthful until #230.
    expect(fastify.repositories.users.verifyEmail).toHaveBeenCalledWith('user-1', TX);

    expect(result).toEqual({
      message: 'Email verified successfully',
      email: 'user@example.com',
    });
  });

  it('falls back to the user password credential for rollback-window tokens (NULL credentialId)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture({ credentialId: null }));
    (fastify.repositories.userCredentials.findByUserIdAndType as unknown as Mock).mockResolvedValue(
      credentialFixture()
    );

    await ctx.handler(request);

    expect(fastify.repositories.userCredentials.findByUserIdAndType).toHaveBeenCalledWith(
      'user-1',
      'password'
    );
    expect(fastify.repositories.userCredentials.findById).not.toHaveBeenCalled();
    expect(fastify.repositories.userCredentials.setEmailVerified).toHaveBeenCalledWith(
      'cred-1',
      TX
    );
  });

  it('throws InvalidTokenError for an unknown/expired/used token', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(undefined);

    await expect(ctx.handler(request)).rejects.toThrow(InvalidTokenError);
    expect(fastify.db.transaction).not.toHaveBeenCalled();
  });

  it('fails closed with InvalidTokenError when no credential resolves', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture({ credentialId: null }));
    (fastify.repositories.userCredentials.findByUserIdAndType as unknown as Mock).mockResolvedValue(
      undefined
    );

    await expect(ctx.handler(request)).rejects.toThrow(InvalidTokenError);
    expect(fastify.repositories.emailVerificationTokens.markUsed).not.toHaveBeenCalled();
  });

  it('treats malformed credential_data as an invalid token and logs for operators', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture({ credentialData: { nonsense: true } })
    );

    await expect(ctx.handler(request)).rejects.toThrow(InvalidTokenError);
    expect(fastify.log.error).toHaveBeenCalledWith(
      expect.objectContaining({ credentialId: 'cred-1' }),
      expect.stringContaining('malformed credential_data')
    );
    expect(fastify.repositories.emailVerificationTokens.markUsed).not.toHaveBeenCalled();
  });

  it('rejects an already-verified email sourced from credential_data without consuming the token', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture({ credentialData: { password_hash: 'hash', email_verified: true } })
    );

    await expect(ctx.handler(request)).rejects.toThrow(EmailAlreadyVerifiedError);
    expect(fastify.repositories.emailVerificationTokens.markUsed).not.toHaveBeenCalled();
    expect(fastify.repositories.users.verifyEmail).not.toHaveBeenCalled();
  });

  it('throws NotFoundError when the credential has no users row', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture()
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(undefined);

    await expect(ctx.handler(request)).rejects.toThrow(NotFoundError);
  });
});
