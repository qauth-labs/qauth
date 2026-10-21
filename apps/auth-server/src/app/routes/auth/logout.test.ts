import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    LOGOUT_RATE_LIMIT: 30,
    LOGOUT_RATE_WINDOW: 60,
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
  },
}));

vi.mock('../../helpers/realm', () => ({
  getOrCreateDefaultRealm: vi.fn(async () => ({ id: 'realm-1' })),
}));
vi.mock('../../helpers/oauth-client', () => ({
  getOrCreateSystemClient: vi.fn(async () => ({ clientId: 'system', audience: null })),
}));

import { signSessionId } from '../../helpers/session-cookie';
import logoutRoute from './logout';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
  routeOptions?: any;
}

interface ReplyStub {
  send: (body: unknown) => unknown;
  header: (name: string, value: string) => ReplyStub;
  headers: Record<string, string>;
}

function createReply(): ReplyStub {
  const reply: ReplyStub = {
    headers: {},
    send(body) {
      return body;
    },
    header(name, value) {
      reply.headers[name] = value;
      return reply;
    },
  };
  return reply;
}

const VALID_USER = {
  id: 'user-logout-1',
  email: 'logout@example.com',
  emailVerified: true,
  enabled: true,
};

/** The claims `/auth/login` puts on the first-party token. */
function loginClaims(overrides: Record<string, unknown> = {}) {
  return { sub: VALID_USER.id, clientId: 'system', aud: 'system', ...overrides };
}

function createFastifyStub() {
  const ctx: TestContext = {};

  const fastify: any = {
    withTypeProvider: () => ({
      post: (
        _url: string,
        opts: unknown,
        handler: (request: any, reply: any) => Promise<unknown>
      ) => {
        ctx.routeOptions = opts;
        ctx.handler = handler;
        return fastify;
      },
    }),
    repositories: {
      users: {
        findById: vi.fn().mockResolvedValue(VALID_USER),
      },
      authorizationCodes: {
        invalidateForUser: vi.fn().mockResolvedValue(0),
      },
      refreshTokens: {
        revokeAllForUser: vi.fn().mockResolvedValue(undefined),
      },
      auditLogs: {
        create: vi.fn().mockResolvedValue(undefined),
      },
    },
    jwtUtils: {
      extractFromHeader: vi.fn(),
      verifyAccessToken: vi.fn(),
      decodeTokenUnsafe: vi.fn(),
      getIssuer: vi.fn().mockReturnValue('https://auth.example.com'),
    },
    redis: {
      setex: vi.fn().mockResolvedValue('OK'),
      // The per-user index of hosted browser sessions (none by default).
      smembers: vi.fn().mockResolvedValue([]),
      del: vi.fn().mockResolvedValue(1),
    },
    sessionUtils: {
      deleteSession: vi.fn().mockResolvedValue(undefined),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };

  return { fastify: fastify as FastifyInstance, ctx };
}

function logoutRequest(
  authHeader: string | undefined = 'Bearer valid.access.jwt',
  cookie?: string
) {
  return {
    headers: {
      authorization: authHeader,
      'user-agent': 'vitest',
      ...(cookie ? { cookie } : {}),
    },
    ip: '203.0.113.7',
    // Request-scoped logger used by the structured auth-event helper (#124).
    log: { info: vi.fn(), warn: vi.fn() },
  };
}

describe('POST /auth/logout', () => {
  it('revokes all refresh tokens for the user and returns 200 on a valid token', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(loginClaims());

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const result = await handler(logoutRequest(), reply);

    expect(fastify.jwtUtils.verifyAccessToken).toHaveBeenCalledWith('valid.access.jwt', {
      issuer: 'https://auth.example.com',
    });
    expect(fastify.repositories.refreshTokens.revokeAllForUser).toHaveBeenCalledWith(
      VALID_USER.id,
      'logout'
    );
    // verifyAccessToken succeeded — must not fall back to the unsafe decode path.
    expect(fastify.jwtUtils.decodeTokenUnsafe).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      success: true,
      message: 'Successfully logged out',
    });
  });

  it('invalidates the user’s unredeemed authorization codes BEFORE sweeping refresh tokens', async () => {
    // A code redeemed after the sweep would mint a refresh token that survives
    // the logout, and a redemption in flight holds its code row locked until
    // its refresh token is committed — so the codes go first, and the sweep
    // that follows sees every refresh token (see the repository integration
    // test for the race).
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(loginClaims());

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(logoutRequest(), createReply());

    expect(fastify.repositories.authorizationCodes.invalidateForUser).toHaveBeenCalledWith(
      VALID_USER.id
    );
    const invalidateOrder = (
      fastify.repositories.authorizationCodes.invalidateForUser as unknown as Mock
    ).mock.invocationCallOrder[0];
    const sweepOrder = (fastify.repositories.refreshTokens.revokeAllForUser as unknown as Mock).mock
      .invocationCallOrder[0];
    expect(invalidateOrder).toBeLessThan(sweepOrder);
  });

  describe('hosted browser sessions', () => {
    async function logOut(fastify: FastifyInstance, ctx: TestContext, cookie?: string) {
      (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
      (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(loginClaims());
      await logoutRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');
      const reply = createReply();
      await handler(logoutRequest('Bearer valid.access.jwt', cookie), reply);
      return reply;
    }

    it('ends every hosted session of the user, with or without a cookie on the request', async () => {
      // The portal calls /auth/logout from its server, so no browser cookie
      // comes along: the sessions are found through the per-user index.
      const { fastify, ctx } = createFastifyStub();
      (fastify.redis.smembers as unknown as Mock).mockResolvedValue(['sess-a', 'sess-b']);

      await logOut(fastify, ctx);

      expect(fastify.redis.smembers).toHaveBeenCalledWith(`user-browser-sessions:${VALID_USER.id}`);
      expect(fastify.sessionUtils.deleteSession).toHaveBeenCalledWith('sess-a');
      expect(fastify.sessionUtils.deleteSession).toHaveBeenCalledWith('sess-b');
      expect(fastify.redis.del).toHaveBeenCalledWith(`user-browser-sessions:${VALID_USER.id}`);
    });

    it('clears the session cookie the request carries when it was one of them', async () => {
      const { fastify, ctx } = createFastifyStub();
      (fastify.redis.smembers as unknown as Mock).mockResolvedValue(['sess-a']);

      const reply = await logOut(fastify, ctx, `__Host-qauth_session=${signSessionId('sess-a')}`);

      expect(reply.headers['Set-Cookie']).toContain('__Host-qauth_session=');
      expect(reply.headers['Set-Cookie']).toContain('Max-Age=0');
    });

    it("leaves the cookie of a session that is not the user's alone", async () => {
      const { fastify, ctx } = createFastifyStub();
      (fastify.redis.smembers as unknown as Mock).mockResolvedValue(['sess-a']);

      const reply = await logOut(fastify, ctx, `__Host-qauth_session=${signSessionId('other')}`);

      expect(reply.headers['Set-Cookie']).toBeUndefined();
      expect(fastify.sessionUtils.deleteSession).not.toHaveBeenCalledWith('other');
    });
  });

  it('still logs a disabled user out: ending access never needs an active account', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      ...VALID_USER,
      enabled: false,
    });
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(loginClaims());

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const result = await handler(logoutRequest(), createReply());

    expect(fastify.repositories.refreshTokens.revokeAllForUser).toHaveBeenCalledWith(
      VALID_USER.id,
      'logout'
    );
    expect(result).toMatchObject({ success: true });
  });

  it('denylists the token it was called with for the rest of its lifetime', async () => {
    // Logout ends the refresh tokens; the access token presented here would
    // otherwise keep working at the management API until it expires.
    const { fastify, ctx } = createFastifyStub();
    const exp = Math.floor(Date.now() / 1000) + 600;
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(
      loginClaims({ jti: 'login-jti-1', exp })
    );

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(logoutRequest(), createReply());

    expect(fastify.redis.setex).toHaveBeenCalledTimes(1);
    const [key, ttl] = (fastify.redis.setex as unknown as Mock).mock.calls[0];
    expect(key).toBe('revoked-access-token:login-jti-1');
    expect(ttl).toBeGreaterThan(590);
    expect(ttl).toBeLessThanOrEqual(600);
  });

  it('writes no denylist entry for an expired token (it is already inert)', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('expired.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTExpiredError('Access token has expired')
    );
    (fastify.jwtUtils.decodeTokenUnsafe as unknown as Mock).mockReturnValue(
      loginClaims({ jti: 'login-jti-2', exp: Math.floor(Date.now() / 1000) - 5 })
    );

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(logoutRequest('Bearer expired.access.jwt'), createReply());

    expect(fastify.redis.setex).not.toHaveBeenCalled();
  });

  it('still logs out and returns 200 when the access token is EXPIRED (cleanup path, not 401)', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('expired.access.jwt');
    // verifyAccessToken throws expired; route falls back to the unsafe decode.
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTExpiredError('Access token has expired')
    );
    (fastify.jwtUtils.decodeTokenUnsafe as unknown as Mock).mockReturnValue(loginClaims());

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const result = await handler(logoutRequest('Bearer expired.access.jwt'), reply);

    // Expired token still triggers full cleanup.
    expect(fastify.jwtUtils.decodeTokenUnsafe).toHaveBeenCalledWith('expired.access.jwt');
    expect(fastify.repositories.refreshTokens.revokeAllForUser).toHaveBeenCalledWith(
      VALID_USER.id,
      'logout'
    );
    expect(result).toMatchObject({ success: true, message: 'Successfully logged out' });
  });

  it('records tokenExpired: true in the success audit metadata for an expired token', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('expired.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTExpiredError('Access token has expired')
    );
    (fastify.jwtUtils.decodeTokenUnsafe as unknown as Mock).mockReturnValue(loginClaims());

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(logoutRequest('Bearer expired.access.jwt'), createReply());

    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: VALID_USER.id,
        event: 'user.logout.success',
        eventType: 'auth',
        success: true,
        metadata: { tokenExpired: true },
      })
    );
  });

  it('records tokenExpired: false in the success audit metadata for a valid token', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(loginClaims());

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(logoutRequest(), createReply());

    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'user.logout.success',
        success: true,
        metadata: { tokenExpired: false },
      })
    );
  });

  it('throws JWTInvalidError (401) when the Authorization header is missing', async () => {
    const { fastify, ctx } = createFastifyStub();
    // extractFromHeader returns null for a missing/malformed header.
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(logoutRequest(undefined), createReply())).rejects.toThrow(JWTInvalidError);

    // No verification, no revocation when the header is absent.
    expect(fastify.jwtUtils.verifyAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
  });

  it('throws (401) and does NOT revoke when the JWT has a bad signature / is malformed', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('tampered.jwt');
    // A non-expiry verification error (bad signature/malformed) must propagate.
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTInvalidError('Invalid token signature')
    );

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(logoutRequest('Bearer tampered.jwt'), createReply())).rejects.toThrow(
      JWTInvalidError
    );

    // Bad-signature tokens must not be decoded unsafely or trigger cleanup.
    expect(fastify.jwtUtils.decodeTokenUnsafe).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
  });

  it.each([
    ['issued to another client', { clientId: 'third-party-app', aud: 'third-party-app' }],
    ['bound to another audience', { aud: 'https://mcp.example.com' }],
    ['delegated to an agent', { act: { sub: 'agent-1' } }],
  ])('throws (401) and does NOT revoke for a valid token %s', async (_name, overrides) => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('foreign.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(
      loginClaims(overrides)
    );

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(
      handler(logoutRequest('Bearer foreign.access.jwt'), createReply())
    ).rejects.toThrow(JWTInvalidError);
    expect(fastify.repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
  });

  it.each([
    ['issued to another client', { clientId: 'third-party-app', aud: 'third-party-app' }],
    ['bound to another audience', { aud: 'https://mcp.example.com' }],
    ['delegated to an agent', { act: { sub: 'agent-1' } }],
  ])('throws (401) and does NOT revoke for an EXPIRED token %s', async (_name, overrides) => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('foreign.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTExpiredError('Access token has expired')
    );
    (fastify.jwtUtils.decodeTokenUnsafe as unknown as Mock).mockReturnValue(loginClaims(overrides));

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(
      handler(logoutRequest('Bearer foreign.access.jwt'), createReply())
    ).rejects.toThrow(JWTInvalidError);
    expect(fastify.repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
  });

  it('throws (401) when the user does not exist, without revoking, and audits no user id', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(
      loginClaims({ sub: 'ghost-user' })
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(null);

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(logoutRequest(), createReply())).rejects.toThrow(JWTInvalidError);
    expect(fastify.repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
    // `audit_logs.user_id` references `users`: the deleted subject goes to
    // metadata, or the insert fails and the 401 becomes a 500 (#754).
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'user.logout.failure',
        userId: null,
        metadata: expect.objectContaining({ tokenSub: 'ghost-user' }),
      })
    );
  });

  it('writes a failure audit log (user.logout.failure) when logout fails', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('tampered.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTInvalidError('Invalid token signature')
    );

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(logoutRequest('Bearer tampered.jwt'), createReply())).rejects.toThrow(
      JWTInvalidError
    );

    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'user.logout.failure',
        eventType: 'auth',
        success: false,
        // userId is unknown when verification fails before identifying the user.
        userId: null,
        metadata: expect.objectContaining({ error: 'Invalid token signature' }),
      })
    );
  });

  it('configures rate limiting from LOGOUT_RATE_LIMIT / LOGOUT_RATE_WINDOW keyed on client IP', async () => {
    const { fastify, ctx } = createFastifyStub();

    await logoutRoute(fastify);
    const rateLimit = ctx.routeOptions?.config?.rateLimit;
    expect(rateLimit).toBeDefined();
    expect(rateLimit.max).toBe(30);
    // Window is configured in milliseconds (seconds * 1000).
    expect(rateLimit.timeWindow).toBe(60 * 1000);
    expect(rateLimit.keyGenerator({ ip: '203.0.113.7' })).toBe('203.0.113.7');
    expect(rateLimit.keyGenerator({ ip: undefined })).toBe('unknown');
  });
});
