import { InvalidCsrfTokenError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
  },
}));

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

import { createBrowserSessionFixture } from '../../../testing/browser-sessions';
import { testRealm } from '../../../testing/request-realm';
import { REDIS_KEYS } from '../../constants/redis-keys';
import { SignInRequiredError } from '../../helpers/sign-in-required';
import { emitUserEvent } from '../../helpers/user-events';
import consentsRoute from './index';

const emitUserEventMock = vi.mocked(emitUserEvent);

/** The realm the realm resolver (#486) decorated every request with. */
const REALM = testRealm({ id: 'realm-1' });

beforeEach(() => {
  emitUserEventMock.mockClear();
});

/** A consent id, a UUID as `oauth_consents.id` is. */
const CONSENT_ID = '0190c000-0000-7000-8000-0000000000c1';

interface TestContext {
  get?: (request: any, reply: any) => Promise<unknown>;
  delete?: (request: any, reply: any) => Promise<unknown>;
  /** Declared route paths, in registration order — see the routing test below. */
  urls: { method: string; url: string }[];
}

function createReply() {
  const state: {
    statusCode?: number;
    headers: Record<string, string>;
    body?: unknown;
  } = { headers: {} };
  const reply: any = {
    code(n: number) {
      state.statusCode = n;
      return reply;
    },
    header(k: string, v: string) {
      state.headers[k] = v;
      return reply;
    },
    send(body: unknown) {
      state.body = body;
      return body;
    },
  };
  return { reply, state };
}

/**
 * The realm resolver's decoration (#486): a request reaches its handler with
 * the realm of its host.
 */
function inRealm(handler: NonNullable<TestContext['get']>): NonNullable<TestContext['get']> {
  return (request, reply) => {
    request.realm ??= REALM;
    return handler(request, reply);
  };
}

function makeFastify() {
  const ctx: TestContext = { urls: [] };
  const sessions = createBrowserSessionFixture();
  const fastify: any = {
    withTypeProvider: () => ({
      get: (u: string, _o: unknown, h: any) => {
        ctx.urls.push({ method: 'GET', url: u });
        ctx.get = inRealm(h);
        return fastify;
      },
      delete: (u: string, _o: unknown, h: any) => {
        ctx.urls.push({ method: 'DELETE', url: u });
        ctx.delete = inRealm(h);
        return fastify;
      },
    }),
    repositories: {
      oauthConsents: {
        listActiveForUserWithClient: vi.fn(),
        revoke: vi.fn(),
      },
      oauthClients: {
        findById: vi.fn(),
      },
      authorizationCodes: { invalidateForUserAndClient: vi.fn().mockResolvedValue(0) },
      refreshTokens: { revokeAllForUserAndClient: vi.fn().mockResolvedValue(0) },
      // `resolveBrowserSession` only accepts a session whose user is still enabled.
      users: { findById: vi.fn(async (_realmId: string, id: string) => ({ id, enabled: true })) },
    },
    db: { transaction: vi.fn(async (cb: (tx: unknown) => Promise<unknown>) => cb('tx')) },
    sessionService: sessions.service,
    redis: sessions.redis,
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx, sessions };
}

/**
 * A live browser session in the request's realm, with its side record's
 * `apiCsrfToken` already minted when one is given.
 */
function signIn(
  sessions: ReturnType<typeof createBrowserSessionFixture>,
  userId: string,
  sid: string,
  apiCsrfToken?: string
) {
  return sessions.signIn({
    sid,
    realmId: REALM.id,
    userId,
    side: { identifier: 'a@b.com', ...(apiCsrfToken ? { apiCsrfToken } : {}) },
  });
}

describe('/consents JSON API', () => {
  it('declares paths relative to the autoload directory prefix', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);

    // `@fastify/autoload` is registered without `dirNameRoutePrefix: false`
    // (app.ts), so the `consents/` directory supplies the `/consents` prefix and
    // these paths must be relative to it. Declaring `/consents` here published
    // `/consents/consents`, which is what the developer portal's consents page
    // was failing against — it calls `${AUTH_SERVER_URL}/consents`.
    //
    // The rest of this file drives the captured handlers directly and never
    // sees a URL, which is exactly why the doubled prefix went unnoticed.
    expect(ctx.urls).toEqual([
      { method: 'GET', url: '/' },
      { method: 'DELETE', url: '/:id' },
    ]);
    expect(ctx.urls.some((r) => r.url.includes('consents'))).toBe(false);
  });

  // Without a session both routes throw the sign-in refusal, which the error
  // handler answers as the 401 `unauthorized` problem document (#513), not a
  // body of their own.
  it('GET /consents refuses a request without a session with the 401 sign-in refusal', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);

    const { reply, state } = createReply();
    const refused = await ctx.get?.({ headers: {} }, reply).catch((error: unknown) => error);

    expect(refused).toBeInstanceOf(SignInRequiredError);
    expect(refused).toMatchObject({ statusCode: 401 });
    expect(state.body).toBeUndefined();
    expect(fastify.repositories.oauthConsents.listActiveForUserWithClient).not.toHaveBeenCalled();
  });

  it('DELETE /consents/:id refuses a request without a session with the 401 sign-in refusal', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);

    const { reply, state } = createReply();
    const refused = await ctx
      .delete?.({ headers: { 'x-csrf-token': 'any' }, params: { id: CONSENT_ID } }, reply)
      .catch((error: unknown) => error);

    expect(refused).toBeInstanceOf(SignInRequiredError);
    expect(state.body).toBeUndefined();
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
  });

  it('GET /consents lists active consents and returns a CSRF token', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentsRoute(fastify);
    const { session, cookie } = await signIn(sessions, 'u1', 's1');
    (
      fastify.repositories.oauthConsents.listActiveForUserWithClient as unknown as Mock
    ).mockResolvedValue([
      {
        id: 'c1',
        oauthClientId: 'cli1',
        scopes: ['email'],
        grantedAt: 1,
        revokedAt: null,
        clientClientId: 'app-123',
        clientName: 'Cool App',
      },
    ]);

    const { reply, state } = createReply();
    await ctx.get!({ headers: { cookie } }, reply);
    expect(state.body).toMatchObject({
      consents: [{ id: 'c1', clientId: 'app-123', clientName: 'Cool App', scopes: ['email'] }],
    });
    // Listed in the session's realm (#489).
    expect(fastify.repositories.oauthConsents.listActiveForUserWithClient).toHaveBeenCalledWith(
      REALM.id,
      'u1'
    );
    // The response MUST include a CSRF token for the caller to echo back.
    expect((state.body as any).csrfToken).toEqual(expect.any(String));
    expect((state.body as any).csrfToken.length).toBeGreaterThan(0);
    // The minted token MUST have been persisted to the session's side record.
    expect((await sessions.sideRecord(session)).apiCsrfToken).toBe(
      (state.body as { csrfToken: string }).csrfToken
    );
  });

  it('GET /consents mints its CSRF token into a side record that expires at the session’s end', async () => {
    // The session is 50 minutes into its hour: the side record the token is
    // minted into must expire when the session does, not an hour from now.
    const { fastify, ctx, sessions } = makeFastify();
    await consentsRoute(fastify);
    const { session, cookie } = await sessions.signIn({
      sid: 's1',
      realmId: REALM.id,
      userId: 'u1',
      authTime: Date.now() - 50 * 60 * 1000,
    });
    (
      fastify.repositories.oauthConsents.listActiveForUserWithClient as unknown as Mock
    ).mockResolvedValue([]);

    const handler = ctx.get;
    if (!handler) throw new Error('Handler missing');
    const { reply, state } = createReply();
    await handler({ headers: { cookie } }, reply);

    expect((await sessions.sideRecord(session)).apiCsrfToken).toBe(
      (state.body as { csrfToken: string }).csrfToken
    );
    expect(
      sessions.redis.expiries.get(REDIS_KEYS.BROWSER_SESSION_SIDE_RECORD(REALM.id, 's1'))
    ).toBe(session.expiresAt);
  });

  it('GET /consents reuses the existing apiCsrfToken without re-minting', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentsRoute(fastify);
    const { session, cookie } = await signIn(sessions, 'u1', 's1', 'pre-existing-token');
    sessions.redis.multi.mockClear();
    (
      fastify.repositories.oauthConsents.listActiveForUserWithClient as unknown as Mock
    ).mockResolvedValue([]);

    const { reply, state } = createReply();
    await ctx.get!({ headers: { cookie } }, reply);
    // Existing token is reused — no re-mint / no side-record write.
    expect((state.body as any).csrfToken).toBe('pre-existing-token');
    expect(sessions.redis.multi).not.toHaveBeenCalled();
    expect((await sessions.sideRecord(session)).apiCsrfToken).toBe('pre-existing-token');
  });

  it('DELETE /consents/:id rejects when the X-CSRF-Token header is missing', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentsRoute(fastify);
    const { cookie } = await signIn(sessions, 'u1', 's2', 'valid-token');

    const { reply } = createReply();
    await expect(
      ctx.delete!(
        {
          headers: { cookie },
          params: { id: CONSENT_ID },
          ip: '1.1.1.1',
        },
        reply
      )
    ).rejects.toBeInstanceOf(InvalidCsrfTokenError);
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
    // The CSRF refusal is recorded.
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:request.csrf_rejected:v1-rc.0',
      { form: 'consent_revocation' },
      { userId: 'u1', actor: 'user' }
    );
  });

  it('DELETE /consents/:id rejects when the X-CSRF-Token header mismatches', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentsRoute(fastify);
    const { cookie } = await signIn(sessions, 'u1', 's2', 'valid-token');

    const { reply } = createReply();
    await expect(
      ctx.delete!(
        {
          headers: { cookie, 'x-csrf-token': 'wrong-token' },
          params: { id: CONSENT_ID },
          ip: '1.1.1.1',
        },
        reply
      )
    ).rejects.toBeInstanceOf(InvalidCsrfTokenError);
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
  });

  it('DELETE /consents/:id revokes when the CSRF token matches and the consent belongs to the user', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentsRoute(fastify);
    const { cookie } = await signIn(sessions, 'u1', 's2', 'valid-token');
    (
      fastify.repositories.oauthConsents.listActiveForUserWithClient as unknown as Mock
    ).mockResolvedValue([
      {
        id: CONSENT_ID,
        oauthClientId: 'cli1',
        realmId: REALM.id,
        clientClientId: 'app-123',
        clientName: 'App',
        scopes: ['email'],
        grantedAt: 1,
        revokedAt: null,
      },
    ]);
    (fastify.repositories.oauthConsents.revoke as unknown as Mock).mockResolvedValue({});
    (
      fastify.repositories.refreshTokens.revokeAllForUserAndClient as unknown as Mock
    ).mockResolvedValueOnce(3);

    const { reply, state } = createReply();
    await ctx.delete!(
      {
        headers: { cookie, 'x-csrf-token': 'valid-token' },
        params: { id: CONSENT_ID },
        ip: '1.1.1.1',
      },
      reply
    );
    expect(state.statusCode).toBe(204);
    // Owned and revoked in the session's realm (#489).
    expect(fastify.repositories.oauthConsents.listActiveForUserWithClient).toHaveBeenCalledWith(
      REALM.id,
      'u1'
    );
    expect(fastify.repositories.oauthConsents.revoke).toHaveBeenCalledWith(
      REALM.id,
      CONSENT_ID,
      'tx'
    );
    expect(fastify.repositories.authorizationCodes.invalidateForUserAndClient).toHaveBeenCalledWith(
      'u1',
      'cli1',
      'tx'
    );
    expect(fastify.repositories.refreshTokens.revokeAllForUserAndClient).toHaveBeenCalledWith(
      'u1',
      'cli1',
      'consent_revoked',
      'tx'
    );
    // Recorded in the revocation's transaction, naming the public client_id.
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:consent.revoked:v1-rc.0',
      { consentId: CONSENT_ID, revokedRefreshCount: 3 },
      { tx: 'tx', realmId: 'realm-1', userId: 'u1', clientId: 'app-123', actor: 'user' }
    );
  });

  it('DELETE /consents/:id rejects revocation for a different user', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentsRoute(fastify);
    const { cookie } = await signIn(sessions, 'u-other', 's3', 'valid-token');
    (
      fastify.repositories.oauthConsents.listActiveForUserWithClient as unknown as Mock
    ).mockResolvedValue([]);

    const { reply } = createReply();
    await expect(
      ctx.delete!(
        {
          headers: { cookie, 'x-csrf-token': 'valid-token' },
          params: { id: CONSENT_ID },
          ip: '1.1.1.1',
        },
        reply
      )
    ).rejects.toThrow(NotFoundError);
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
    expect(emitUserEventMock).not.toHaveBeenCalled();
  });
});
