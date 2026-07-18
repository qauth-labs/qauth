import { createPasswordProvider } from '@qauth-labs/fastify-plugin-federation';
import { UniqueConstraintError, WeakPasswordError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    DEFAULT_REALM_NAME: 'master',
    REGISTRATION_RATE_LIMIT: 10,
    REGISTRATION_RATE_WINDOW: 900,
    EMAIL_VERIFICATION_TOKEN_EXPIRY: 3600,
  },
}));

import registerRoute from './register';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

/** Sentinel transaction client — asserting writes carry it proves they share the tx. */
const TX = { __tx: 'register-tx' };

function createReply() {
  const state: { statusCode?: number; body?: unknown } = {};
  const reply: any = {
    state,
    code(n: number) {
      state.statusCode = n;
      return reply;
    },
    send(body: unknown) {
      state.body = body;
      return body;
    },
  };
  return reply;
}

function createFastifyStub() {
  const ctx: TestContext = {};
  const createdUser = {
    id: 'user-1',
    email: 'user@example.com',
    emailVerified: false,
    realmId: 'realm-1',
    createdAt: 1_600_000_000_000,
    updatedAt: 1_600_000_000_000,
  };

  const fastify: any = {
    withTypeProvider: () => ({
      post: (_url: string, _opts: unknown, handler: any) => {
        ctx.handler = handler;
        return fastify;
      },
    }),
    db: {
      transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(TX)),
    },
    repositories: {
      realms: {
        findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'master', enabled: true }),
        findById: vi.fn(),
        create: vi.fn(),
      },
      users: {
        create: vi.fn().mockResolvedValue(createdUser),
      },
      userCredentials: {
        create: vi.fn().mockResolvedValue({ id: 'cred-1', userId: 'user-1' }),
      },
      userAttributes: {
        upsertMany: vi.fn().mockResolvedValue([]),
      },
      emailVerificationTokens: {
        create: vi.fn().mockResolvedValue({ id: 'token-1' }),
      },
    },
    passwordValidator: {
      validatePasswordStrength: vi.fn().mockReturnValue({ valid: true, feedback: [] }),
    },
    passwordHasher: {
      hashPassword: vi.fn().mockResolvedValue('$argon2id$hashed'),
    },
    providerRegistry: {
      resolve: vi.fn().mockReturnValue(createPasswordProvider()),
      has: vi.fn().mockReturnValue(true),
      register: vi.fn(),
    },
    emailVerificationTokenUtils: {
      generateVerificationToken: vi.fn().mockReturnValue({ token: 'plain', tokenHash: 'hashed' }),
    },
    emailService: {
      sendVerificationEmail: vi.fn().mockResolvedValue(undefined),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

function requestFixture() {
  return {
    body: { email: 'User@Example.com', password: 'Str0ng-Passw0rd!' },
    ip: '127.0.0.1',
    headers: { 'user-agent': 'vitest' },
    log: { info: vi.fn(), warn: vi.fn() },
  };
}

describe('POST /auth/register', () => {
  it('writes users → credential → attributes → token in ONE transaction with exact shapes', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    const reply = createReply();
    await ctx.handler(requestFixture(), reply);

    // Single transaction wraps the whole identity write set.
    expect(fastify.db.transaction).toHaveBeenCalledOnce();

    // Identity anchor first (legacy columns dual-written until #230).
    expect(fastify.repositories.users.create).toHaveBeenCalledWith(
      {
        email: 'user@example.com',
        emailNormalized: 'user@example.com',
        passwordHash: '$argon2id$hashed',
        realmId: 'realm-1',
        emailVerified: false,
      },
      TX
    );

    // Credential row: exact snake_case credential_data shape, normalized sub.
    expect(fastify.repositories.userCredentials.create).toHaveBeenCalledWith(
      {
        userId: 'user-1',
        realmId: 'realm-1',
        providerType: 'password',
        externalSub: 'user@example.com',
        credentialData: { password_hash: '$argon2id$hashed', email_verified: false },
      },
      TX
    );

    // Attribute row from extractAttributes(): unverified self-reported email.
    expect(fastify.repositories.userAttributes.upsertMany).toHaveBeenCalledWith(
      'user-1',
      [
        {
          source: 'self_reported',
          attrKey: 'email',
          attrValue: 'user@example.com',
          verified: false,
          expiresAt: null,
        },
      ],
      TX
    );

    // Verification token targets the credential; user_id kept until #230.
    expect(fastify.repositories.emailVerificationTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        credentialId: 'cred-1',
        tokenHash: 'hashed',
        used: false,
      }),
      TX
    );

    // ORDER GUARD: users insert precedes the credentials insert so a duplicate
    // registration surfaces the users-index UniqueConstraintError (parity).
    const usersOrder = (fastify.repositories.users.create as unknown as Mock).mock
      .invocationCallOrder[0];
    const credsOrder = (fastify.repositories.userCredentials.create as unknown as Mock).mock
      .invocationCallOrder[0];
    expect(usersOrder).toBeLessThan(credsOrder);

    // Exact pre-refactor 201 body.
    expect(reply.state.statusCode).toBe(201);
    expect(reply.state.body).toEqual({
      id: 'user-1',
      email: 'user@example.com',
      emailVerified: false,
      realmId: 'realm-1',
      createdAt: 1_600_000_000_000,
      updatedAt: 1_600_000_000_000,
    });
    expect(fastify.emailService.sendVerificationEmail).toHaveBeenCalledWith(
      'user@example.com',
      'plain'
    );
  });

  it('duplicate email surfaces the users-index UniqueConstraintError before any credential write', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (fastify.repositories.users.create as unknown as Mock).mockRejectedValue(
      new UniqueConstraintError('idx_users_realm_email_normalized_unique')
    );

    await expect(ctx.handler(requestFixture(), createReply())).rejects.toThrow(
      UniqueConstraintError
    );
    expect(fastify.repositories.userCredentials.create).not.toHaveBeenCalled();
    expect(fastify.emailService.sendVerificationEmail).not.toHaveBeenCalled();
  });

  it('still returns 201 when the verification email fails to send', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (fastify.emailService.sendVerificationEmail as unknown as Mock).mockRejectedValue(
      new Error('smtp down')
    );

    const reply = createReply();
    await ctx.handler(requestFixture(), reply);
    expect(reply.state.statusCode).toBe(201);
  });

  it('rejects weak passwords before touching the database', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (fastify.passwordValidator.validatePasswordStrength as unknown as Mock).mockReturnValue({
      valid: false,
      feedback: ['too short'],
    });

    await expect(ctx.handler(requestFixture(), createReply())).rejects.toThrow(WeakPasswordError);
    expect(fastify.db.transaction).not.toHaveBeenCalled();
  });
});
