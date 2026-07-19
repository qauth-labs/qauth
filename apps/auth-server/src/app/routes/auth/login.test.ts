import { createPasswordProvider } from '@qauth-labs/fastify-plugin-federation';
import { InvalidCredentialsError, TooManyRequestsError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    LOGIN_RATE_LIMIT: 60,
    LOGIN_RATE_WINDOW: 60,
    SYSTEM_CLIENT_ID: 'system',
    // Failed-login tracking enabled; the redis stub's ttl defaults to -2 (not
    // locked), so the credential-flow tests are unaffected. The lockout path is
    // exercised by its own test below, and the helper internals in
    // failed-login.test.ts.
    FAILED_LOGIN_TRACKING_ENABLED: true,
    FAILED_LOGIN_MAX_ATTEMPTS: 5,
    FAILED_LOGIN_WINDOW: 900,
    FAILED_LOGIN_LOCKOUT_DURATION: 900,
    // Off by default (MVP posture); the gate test flips it per-case.
    REQUIRE_EMAIL_VERIFIED: false,
  },
}));

import { env } from '../../../config/env';
import loginRoute from './login';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

interface ReplyStub {
  header: (k: string, v: string) => ReplyStub;
  send: (body: unknown) => unknown;
  headers: Record<string, string>;
}

function createReply(): ReplyStub {
  const headers: Record<string, string> = {};
  const reply: ReplyStub = {
    headers,
    header(k, v) {
      headers[k] = v;
      return reply;
    },
    send(body) {
      return body;
    },
  };
  return reply;
}

function createFastifyStub() {
  const ctx: TestContext = {};

  const fastify: any = {
    withTypeProvider: () => ({
      post: (
        _url: string,
        _opts: unknown,
        handler: (request: any, reply: any) => Promise<unknown>
      ) => {
        ctx.handler = handler;
        return fastify;
      },
    }),
    repositories: {
      realms: {
        findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'default', enabled: true }),
        create: vi.fn(),
      },
      users: {
        findById: vi.fn(),
        updateLastLogin: vi.fn().mockResolvedValue(undefined),
      },
      userCredentials: {
        findByRealmProviderSub: vi.fn(),
        findById: vi.fn(),
      },
      userAttributes: {
        // #229 claim resolution default: one verified self_reported email
        // attribute matching the user fixture. Overridden per test for the
        // divergent-source and omission cases.
        findVerifiedByUserIdAndKey: vi.fn().mockResolvedValue([
          {
            id: 'attr-1',
            userId: 'user-1',
            source: 'self_reported',
            attrKey: 'email',
            attrValue: 'user@example.com',
            verified: true,
            expiresAt: null,
            createdAt: 1,
            updatedAt: 1,
          },
        ]),
      },
      oauthClients: {
        findByClientId: vi.fn(),
        create: vi.fn(),
      },
      refreshTokens: {
        create: vi.fn().mockResolvedValue(undefined),
      },
      auditLogs: {
        create: vi.fn().mockResolvedValue(undefined),
      },
    },
    passwordHasher: {
      verifyPassword: vi.fn(),
      hashPassword: vi.fn(),
    },
    // The real provider (pure, framework-free): the registry is load-bearing —
    // the route resolves 'password' through it, and one test pins that.
    providerRegistry: {
      resolve: vi.fn().mockReturnValue(createPasswordProvider()),
      has: vi.fn().mockReturnValue(true),
      register: vi.fn(),
    },
    jwtUtils: {
      signAccessToken: vi.fn(),
      // #275: classical posture — issueAccessToken takes the non-hybrid branch.
      isHybridSigningEnabled: () => false,
      generateRefreshToken: vi.fn().mockReturnValue({ token: 'rt', tokenHash: 'rth' }),
      getAccessTokenLifespan: vi.fn().mockReturnValue(900),
      getRefreshTokenLifespan: vi.fn().mockReturnValue(604800),
    },
    sessionUtils: {
      setSession: vi.fn().mockResolvedValue(undefined),
    },
    redis: {
      ttl: vi.fn().mockResolvedValue(-2),
      incr: vi.fn().mockResolvedValue(1),
      expire: vi.fn().mockResolvedValue(1),
      set: vi.fn().mockResolvedValue('OK'),
      del: vi.fn().mockResolvedValue(0),
    },
    metrics: {
      loginAttempts: { inc: vi.fn() },
      tokensIssued: { inc: vi.fn() },
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };

  return { fastify: fastify as FastifyInstance, ctx };
}

/** A request-scoped logger stub for the structured auth-event helper. */
function requestLog() {
  return { info: vi.fn(), warn: vi.fn() };
}

/** The #228 credential-row fixture the login lookup returns. */
function credentialFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 'cred-1',
    userId: 'user-1',
    realmId: 'realm-1',
    providerType: 'password',
    externalSub: 'user@example.com',
    credentialData: { password_hash: 'hash', email_verified: true },
    createdAt: 1_600_000_000_000,
    updatedAt: 1_600_000_000_000,
    ...overrides,
  };
}

function userFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 'user-1',
    email: 'user@example.com',
    emailVerified: true,
    passwordHash: 'hash',
    enabled: true,
    ...overrides,
  };
}

describe('POST /auth/login', () => {
  it('signs access token with aud resolved from the system client and sets Cache-Control: no-store', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const user = userFixture();
    const systemClient = {
      id: 'sc-uuid',
      clientId: 'system',
      audience: ['https://auth.example.com'],
    };

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(user);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      systemClient
    );
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    const request = {
      body: { email: 'user@example.com', password: 'p' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    const result = await handler(request, reply);

    // aud comes from the system client's audience (single-item array → string)
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        clientId: 'system',
        aud: 'https://auth.example.com',
      })
    );

    // RFC 6749 §5.1 — token response must not be cached
    expect(reply.headers['Cache-Control']).toBe('no-store');
    expect(reply.headers['Pragma']).toBe('no-cache');

    expect(result).toMatchObject({
      access_token: 'jwt',
      refresh_token: 'rt',
      token_type: 'Bearer',
    });
  });

  it('emits trust-resolved email claims sourced from user_attributes — BREAKING #229', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);

    // All THREE candidate sources diverge on purpose: users row says
    // canonical@example.com, credential external_sub says user@example.com,
    // and the verified attribute says attr@example.com. Only attribute
    // sourcing (the #229 resolver) produces the asserted claims — a
    // regression to either legacy source fails here.
    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(
      credentialFixture({
        credentialData: { password_hash: 'hash', email_verified: false },
      })
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(
      userFixture({ email: 'canonical@example.com', emailVerified: true })
    );
    (
      fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue([
      {
        id: 'attr-1',
        userId: 'user-1',
        source: 'self_reported',
        attrKey: 'email',
        attrValue: 'attr@example.com',
        verified: true,
        expiresAt: null,
        createdAt: 1,
        updatedAt: 1,
      },
    ]);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'sc-uuid',
      clientId: 'system',
      audience: ['https://auth.example.com'],
    });
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    if (!ctx.handler) throw new Error('Handler missing');
    await ctx.handler(
      {
        body: { email: 'user@example.com', password: 'p' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
        log: requestLog(),
      },
      createReply()
    );

    // Full-payload strictness kept from the #228 before-fixture: exact object,
    // with email from the verified attribute and email_verified literally true.
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).toHaveBeenCalledWith(
      'user-1',
      'email'
    );
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith({
      sub: 'user-1',
      email: 'attr@example.com',
      email_verified: true,
      clientId: 'system',
      aud: 'https://auth.example.com',
    });
    // The provider is resolved from the registry — it is load-bearing, not
    // decorative (ADR-003).
    expect(fastify.providerRegistry.resolve).toHaveBeenCalledWith('password');
  });

  it('omits BOTH email claims from the access token when no verified attribute exists — BREAKING #229', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
    (
      fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue([]);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'sc-uuid',
      clientId: 'system',
      audience: ['https://auth.example.com'],
    });
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    if (!ctx.handler) throw new Error('Handler missing');
    const result = await ctx.handler(
      {
        body: { email: 'user@example.com', password: 'p' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
        log: requestLog(),
      },
      createReply()
    );

    // Login itself still succeeds (the F-08 gate is a separate control).
    expect(result).toMatchObject({ access_token: 'jwt', token_type: 'Bearer' });
    // Omitted means the KEYS are absent from the signed claims — never null.
    const signedClaims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect('email' in signedClaims).toBe(false);
    expect('email_verified' in signedClaims).toBe(false);
  });

  it('throws InvalidCredentialsError for unknown email and skips token minting', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(undefined);

    const request = {
      body: { email: 'missing@example.com', password: 'p' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(InvalidCredentialsError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    // Timing-profile parity with the legacy path: no argon2 burn when the
    // credential is missing (the fixed response-time floor is the equalizer).
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });

  it('throws InvalidCredentialsError for wrong password', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(false);

    const request = {
      body: { email: 'user@example.com', password: 'wrong' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(InvalidCredentialsError);
  });

  it('treats malformed credential_data as invalid credentials (401), logs for operators, skips argon2', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture({ credentialData: { passwordHash: 'camelCase-drift' } }));

    const request = {
      body: { email: 'user@example.com', password: 'p' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    // Generic 401 — a distinct status would leak account state (enumeration).
    await expect(handler(request, reply)).rejects.toThrow(InvalidCredentialsError);
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
    // The error-level log line is the operator alerting hook for corruption.
    expect(fastify.log.error).toHaveBeenCalledWith(
      expect.objectContaining({ credentialId: 'cred-1' }),
      expect.stringContaining('malformed credential_data')
    );
  });

  it('REQUIRE_EMAIL_VERIFIED gate reads credential_data.email_verified', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(
      credentialFixture({ credentialData: { password_hash: 'hash', email_verified: false } })
    );
    // users row says VERIFIED — the gate must read credential_data (false),
    // not user.emailVerified; a regression to the users-row source lets this
    // login through and fails the test.
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(
      userFixture({ emailVerified: true })
    );
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    (env as { REQUIRE_EMAIL_VERIFIED: boolean }).REQUIRE_EMAIL_VERIFIED = true;
    try {
      const request = {
        body: { email: 'user@example.com', password: 'p' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
        log: requestLog(),
      };
      const reply = createReply();
      if (!handler) throw new Error('Handler missing');

      await expect(handler(request, reply)).rejects.toThrow(
        'Email address not verified. Check your inbox.'
      );
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
      // The gate fires before the user lookup — its source is the credential.
      expect(fastify.repositories.users.findById).not.toHaveBeenCalled();
    } finally {
      (env as { REQUIRE_EMAIL_VERIFIED: boolean }).REQUIRE_EMAIL_VERIFIED = false;
    }
  });

  it('rejects with TooManyRequestsError when the identifier is locked out (#115)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    // Simulate an active lockout: ttl > 0 on the lockout key.
    (fastify.redis.ttl as unknown as Mock).mockResolvedValue(300);

    const request = {
      body: { email: 'user@example.com', password: 'p' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(TooManyRequestsError);
    // Locked out before any credential verification.
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    // Retry-After advertised.
    expect(reply.headers['Retry-After']).toBe('300');
  });
});
