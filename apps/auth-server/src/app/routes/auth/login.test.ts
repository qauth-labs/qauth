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
  },
}));

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
        findByEmail: vi.fn(),
        findById: vi.fn(),
        updateLastLogin: vi.fn().mockResolvedValue(undefined),
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
    jwtUtils: {
      signAccessToken: vi.fn(),
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

describe('POST /auth/login', () => {
  it('signs access token with aud resolved from the system client and sets Cache-Control: no-store', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const user = {
      id: 'user-1',
      email: 'user@example.com',
      emailVerified: true,
      passwordHash: 'hash',
      enabled: true,
    };
    const systemClient = {
      id: 'sc-uuid',
      clientId: 'system',
      audience: ['https://auth.example.com'],
    };

    (fastify.repositories.users.findByEmail as unknown as Mock).mockResolvedValue(user);
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

  it('throws InvalidCredentialsError for unknown email and skips token minting', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (fastify.repositories.users.findByEmail as unknown as Mock).mockResolvedValue(null);

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
  });

  it('throws InvalidCredentialsError for wrong password', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (fastify.repositories.users.findByEmail as unknown as Mock).mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      emailVerified: true,
      passwordHash: 'hash',
      enabled: true,
    });
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
