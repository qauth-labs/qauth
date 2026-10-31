import {
  JWTExpiredError,
  JWTInvalidError,
  MissingAccessTokenError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

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

vi.mock('../../helpers/oauth-client', () => ({
  getOrCreateSystemClient: vi.fn(async () => ({ clientId: 'system', audience: null })),
}));

import {
  type BrowserSessionFixture,
  createBrowserSessionFixture,
} from '../../../testing/browser-sessions';
import { testRealm } from '../../../testing/request-realm';
import { INACTIVE_SUBJECT_DESCRIPTION } from '../../helpers/token-subject';
import { emitUserEvent } from '../../helpers/user-events';
import logoutRoute from './logout';

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

const emitUserEventMock = vi.mocked(emitUserEvent);

beforeEach(() => {
  emitUserEventMock.mockClear();
});

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

/** The realm the realm resolver (#486) decorated the request with. */
const REALM = testRealm({ id: 'realm-1' });

const VALID_USER = {
  id: 'user-logout-1',
  realmId: REALM.id,
  email: 'logout@example.com',
  emailVerified: true,
  enabled: true,
};

/** The claims `/auth/login` puts on the first-party token. */
function loginClaims(overrides: Record<string, unknown> = {}) {
  return { sub: VALID_USER.id, clientId: 'system', aud: 'system', ...overrides };
}

/** The per-user index of hosted browser sessions that logout ends. */
const SESSION_INDEX = `user-browser-sessions:${VALID_USER.id}`;

/**
 * A live hosted session of {@link VALID_USER}, recorded in the per-user index
 * as a sign-in records it.
 */
async function signedIn(sessions: BrowserSessionFixture, sid: string) {
  const signed = await sessions.signIn({
    sid,
    realmId: REALM.id,
    userId: VALID_USER.id,
    side: { identifier: VALID_USER.email },
  });
  await sessions.redis.sadd(SESSION_INDEX, sid);
  return signed;
}

function createFastifyStub() {
  const ctx: TestContext = {};
  // The session service (#488) and the Redis of the per-user index (none by
  // default) and the sessions' side records.
  const sessions = createBrowserSessionFixture();

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
    },
    jwtUtils: {
      extractFromHeader: vi.fn(),
      verifyAccessToken: vi.fn(),
      decodeTokenUnsafe: vi.fn(),
    },
    sessionService: sessions.service,
    redis: {
      ...sessions.redis,
      setex: vi.fn().mockResolvedValue('OK'),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };

  return { fastify: fastify as FastifyInstance, ctx, sessions };
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
    realm: REALM,
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

    // Verified in the request's realm: its keys, its issuer pinned (#491).
    expect(fastify.jwtUtils.verifyAccessToken).toHaveBeenCalledWith(
      { id: 'realm-1', issuer: 'https://auth.example.com' },
      'valid.access.jwt'
    );
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
      const { fastify, ctx, sessions } = createFastifyStub();
      await signedIn(sessions, 'sess-a');
      await signedIn(sessions, 'sess-b');

      await logOut(fastify, ctx);

      expect(sessions.redis.smembers).toHaveBeenCalledWith(SESSION_INDEX);
      // Revoked through the session service, in the user's realm (#488).
      expect(sessions.service.revoke).toHaveBeenCalledTimes(2);
      expect(sessions.service.revoke).toHaveBeenCalledWith({
        realmId: REALM.id,
        sid: 'sess-a',
        reason: 'sign_out_everywhere',
        actor: { type: 'user', id: VALID_USER.id },
      });
      expect(sessions.service.revoke).toHaveBeenCalledWith({
        realmId: REALM.id,
        sid: 'sess-b',
        reason: 'sign_out_everywhere',
        actor: { type: 'user', id: VALID_USER.id },
      });
      expect(sessions.service.sessions.size).toBe(0);
      // Their side records and the index go with them.
      expect(sessions.redis.hashes.size).toBe(0);
      expect(sessions.redis.del).toHaveBeenCalledWith(SESSION_INDEX);
      expect(sessions.redis.sets.has(SESSION_INDEX)).toBe(false);
    });

    it('clears the session cookie the request carries when it was one of them', async () => {
      const { fastify, ctx, sessions } = createFastifyStub();
      const { cookie } = await signedIn(sessions, 'sess-a');

      const reply = await logOut(fastify, ctx, cookie);

      expect(sessions.service.sessions.has('sess-a')).toBe(false);
      expect(reply.headers['Set-Cookie']).toContain('__Host-qauth_session=');
      expect(reply.headers['Set-Cookie']).toContain('Max-Age=0');
    });

    it("leaves the cookie of a session that is not the user's alone", async () => {
      const { fastify, ctx, sessions } = createFastifyStub();
      await signedIn(sessions, 'sess-a');
      // A live session of another user, in this browser.
      const other = await sessions.signIn({ sid: 'other', realmId: REALM.id, userId: 'user-2' });

      const reply = await logOut(fastify, ctx, other.cookie);

      expect(reply.headers['Set-Cookie']).toBeUndefined();
      expect(sessions.service.revoke).not.toHaveBeenCalledWith(
        expect.objectContaining({ sid: 'other' })
      );
      expect(sessions.service.sessions.has('other')).toBe(true);
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

  it('still logs a disabled user out with a token minted before the disablement (#748)', async () => {
    const { fastify, ctx } = createFastifyStub();
    const disabledAt = Date.now() - 60_000;
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      ...VALID_USER,
      enabled: false,
      notValidBefore: disabledAt,
    });
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(
      loginClaims({ iat: Math.floor((disabledAt - 60_000) / 1000) })
    );

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(logoutRequest(), createReply())).resolves.toMatchObject({
      success: true,
    });
    expect(fastify.repositories.refreshTokens.revokeAllForUser).toHaveBeenCalledOnce();
  });

  it('ends nothing of an account enabled again for a token minted before it was disabled (#748)', async () => {
    // Whoever held the token while the account was disabled must not sign the
    // owner out of the sessions started since.
    const { fastify, ctx, sessions } = createFastifyStub();
    const disabledAt = Date.now() - 60_000;
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      ...VALID_USER,
      enabled: true,
      notValidBefore: disabledAt,
    });
    await signedIn(sessions, 'sess-new');
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(
      loginClaims({ iat: Math.floor((disabledAt - 60_000) / 1000) })
    );

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(logoutRequest(), createReply())).rejects.toMatchObject({
      statusCode: 401,
      message: INACTIVE_SUBJECT_DESCRIPTION,
    });
    expect(fastify.repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
    expect(fastify.repositories.authorizationCodes.invalidateForUser).not.toHaveBeenCalled();
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(sessions.service.sessions.has('sess-new')).toBe(true);
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

  it('records the sign-out of an expired token as user.signed_out', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('expired.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTExpiredError('Access token has expired')
    );
    (fastify.jwtUtils.decodeTokenUnsafe as unknown as Mock).mockReturnValue(loginClaims());

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const request = logoutRequest('Bearer expired.access.jwt');
    await handler(request, createReply());

    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      request,
      'urn:qauth:event:user.signed_out:v1-rc.0',
      {},
      { realmId: 'realm-1', userId: VALID_USER.id, actor: 'user' }
    );
  });

  it('records the sign-out of a valid token as user.signed_out', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(loginClaims());

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const request = logoutRequest();
    await handler(request, createReply());

    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      request,
      'urn:qauth:event:user.signed_out:v1-rc.0',
      {},
      { realmId: 'realm-1', userId: VALID_USER.id, actor: 'user' }
    );
  });

  // No credential is not a refused token (RFC 6750 §3.1): `unauthorized`.
  it('throws MissingAccessTokenError (401) when the Authorization header is missing', async () => {
    const { fastify, ctx } = createFastifyStub();
    // extractFromHeader returns null for a missing/malformed header.
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(logoutRequest(undefined), createReply())).rejects.toThrow(
      MissingAccessTokenError
    );

    // No verification, no revocation when the header is absent.
    expect(fastify.jwtUtils.verifyAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:user.sign_out_failed:v1-rc.0',
      { reason: 'missing_token' },
      expect.objectContaining({ userId: null })
    );
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

  it.each([
    ['a live', false],
    ['an EXPIRED', true],
  ])(
    'throws (401) and does NOT revoke for %s DPoP-bound token sent as Bearer',
    async (_name, expired) => {
      // RFC 9449 §7.2 (#480): the route reads a Bearer token, and a token bound
      // to a DPoP key is never one, expired or not.
      const { fastify, ctx, sessions } = createFastifyStub();
      const claims = loginClaims({ cnf: { jkt: 'dpop-key-thumbprint' } });
      (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('bound.access.jwt');
      if (expired) {
        (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
          new JWTExpiredError('Access token has expired')
        );
        (fastify.jwtUtils.decodeTokenUnsafe as unknown as Mock).mockReturnValue(claims);
      } else {
        (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(claims);
      }

      await logoutRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(
        handler(logoutRequest('Bearer bound.access.jwt'), createReply())
      ).rejects.toBeInstanceOf(JWTInvalidError);
      expect(sessions.redis.smembers).not.toHaveBeenCalled();
      expect(sessions.service.revoke).not.toHaveBeenCalled();
      expect(fastify.repositories.authorizationCodes.invalidateForUser).not.toHaveBeenCalled();
      expect(fastify.repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
    }
  );

  it('stops at a failed write: the steps before it stay done, none after it runs, and the failure is recorded', async () => {
    // The writes are not one transaction (graphs/flows/core/logout): a store
    // failure part way answers 500 with the sessions ended and the codes spent.
    const { fastify, ctx } = createFastifyStub();
    const storeDown = new Error('connection terminated');
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(
      loginClaims({ jti: 'login-jti-3', exp: Math.floor(Date.now() / 1000) + 600 })
    );
    (fastify.repositories.refreshTokens.revokeAllForUser as unknown as Mock).mockRejectedValue(
      storeDown
    );

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(logoutRequest(), createReply())).rejects.toBe(storeDown);
    expect(fastify.redis.del).toHaveBeenCalledWith(`user-browser-sessions:${VALID_USER.id}`);
    expect(fastify.repositories.authorizationCodes.invalidateForUser).toHaveBeenCalledWith(
      VALID_USER.id
    );
    expect(fastify.redis.setex).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:user.sign_out_failed:v1-rc.0',
      { reason: 'internal_error' },
      { realmId: REALM.id, userId: VALID_USER.id, actor: 'user' }
    );
  });

  it('throws (401) when the user does not exist, without revoking, and records no user', async () => {
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
    // The deleted subject names no user, so the event has no subject (#754).
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:user.sign_out_failed:v1-rc.0',
      { reason: 'subject_not_a_user' },
      { realmId: undefined, userId: null, actor: 'user' }
    );
  });

  it('throws (401) and does NOT revoke for the token of a user of another realm, as for an unknown user (#487, #489)', async () => {
    // The management token reads the same in every realm, so its subject's
    // realm decides: a token from another realm's host ends nothing here.
    // The subject is looked up in the request's realm only (#489), so another
    // realm's user is no user here, answered exactly as an unknown subject is.
    const subject = '22222222-2222-4222-8222-222222222222';
    const ghost = '33333333-3333-4333-8333-333333333333';
    const { fastify, ctx } = createFastifyStub();
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('valid.access.jwt');
    const findById = fastify.repositories.users.findById as unknown as Mock;
    // The subject is a user of realm-other: the realm-scoped lookup finds it there only.
    findById.mockImplementation(async (realmId: string, id: string) =>
      realmId === 'realm-other' && id === subject
        ? { ...VALID_USER, id: subject, realmId: 'realm-other' }
        : undefined
    );

    await logoutRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const answer = async (sub: string) => {
      emitUserEventMock.mockClear();
      (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue(
        loginClaims({ sub })
      );
      const error = await handler(logoutRequest(), createReply()).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(JWTInvalidError);
      const { name, message, statusCode, code } = error as JWTInvalidError;
      // The events past the request each was emitted for.
      const events = emitUserEventMock.mock.calls.map(([, ...event]) => event);
      return { error: { name, message, statusCode, code }, events };
    };

    const otherRealmUser = await answer(subject);
    expect(findById).toHaveBeenCalledWith(REALM.id, subject);
    const unknownUser = await answer(ghost);

    expect(otherRealmUser).toEqual(unknownUser);
    expect(otherRealmUser.events).toEqual([
      [
        'urn:qauth:event:user.sign_out_failed:v1-rc.0',
        { reason: 'subject_not_a_user' },
        { realmId: undefined, userId: null, actor: 'user' },
      ],
    ]);
    expect(fastify.repositories.authorizationCodes.invalidateForUser).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
  });

  it('records a user.sign_out_failed event when logout fails', async () => {
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

    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:user.sign_out_failed:v1-rc.0',
      // A refused token, never the exception message.
      { reason: 'invalid_token' },
      // userId is unknown when verification fails before identifying the user.
      expect.objectContaining({ userId: null, actor: 'user' })
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
