import { JWTExpiredError, JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    LOGOUT_RATE_LIMIT: 30,
    LOGOUT_RATE_WINDOW: 60,
  },
}));

import logoutRoute from './logout';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
  routeOptions?: any;
}

interface ReplyStub {
  send: (body: unknown) => unknown;
}

function createReply(): ReplyStub {
  const reply: ReplyStub = {
    send(body) {
      return body;
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
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };

  return { fastify: fastify as FastifyInstance, ctx };
}

function logoutRequest(authHeader: string | undefined = 'Bearer valid.access.jwt') {
  return {
    headers: {
      authorization: authHeader,
      'user-agent': 'vitest',
    },
    ip: '203.0.113.7',
  };
}

describe('POST /auth/logout', () => {
  it('revokes all refresh tokens for the user and returns 200 on a valid token', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: VALID_USER.id,
    });

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const result = await handler(logoutRequest(), reply);

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

  it('still logs out and returns 200 when the access token is EXPIRED (cleanup path, not 401)', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('expired.access.jwt');
    // verifyAccessToken throws expired; route falls back to the unsafe decode.
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTExpiredError('Access token has expired')
    );
    (fastify.jwtUtils.decodeTokenUnsafe as unknown as Mock).mockReturnValue({ sub: VALID_USER.id });

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
    (fastify.jwtUtils.decodeTokenUnsafe as unknown as Mock).mockReturnValue({ sub: VALID_USER.id });

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
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: VALID_USER.id,
    });

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

  it('throws NotFoundError (404) when the user does not exist, without revoking', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: 'ghost-user',
    });
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(null);

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(logoutRequest(), createReply())).rejects.toThrow(NotFoundError);
    expect(fastify.repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
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
