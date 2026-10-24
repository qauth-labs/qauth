import { BadRequestError, NotFoundError } from '@qauth-labs/shared-errors';
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

import { emitUserEvent } from '../../helpers/user-events';
import consentsRoute from './index';

const emitUserEventMock = vi.mocked(emitUserEvent);

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

function makeFastify() {
  const ctx: TestContext = { urls: [] };
  const fastify: any = {
    withTypeProvider: () => ({
      get: (u: string, _o: unknown, h: any) => {
        ctx.urls.push({ method: 'GET', url: u });
        ctx.get = h;
        return fastify;
      },
      delete: (u: string, _o: unknown, h: any) => {
        ctx.urls.push({ method: 'DELETE', url: u });
        ctx.delete = h;
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
      users: { findById: vi.fn(async (id: string) => ({ id, enabled: true })) },
    },
    db: { transaction: vi.fn(async (cb: (tx: unknown) => Promise<unknown>) => cb('tx')) },
    sessionUtils: { getSession: vi.fn(), setSession: vi.fn().mockResolvedValue(undefined) },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

/** Session with the CSRF token already minted — for GET tests that don't care about minting. */
function sessionWith(userId: string, sessionId: string, apiCsrfToken?: string) {
  return {
    userId,
    email: 'a@b.com',
    sessionId,
    createdAt: Date.now(),
    ...(apiCsrfToken ? { apiCsrfToken } : {}),
  };
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

  it('GET /consents returns 401 when no session', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(null);

    const { reply, state } = createReply();
    await ctx.get!({ headers: {} }, reply);
    expect(state.statusCode).toBe(401);
  });

  it('GET /consents lists active consents and returns a CSRF token', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('s1');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(sessionWith('u1', 's1'));
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
    await ctx.get!({ headers: { cookie: `__Host-qauth_session=${signed}` } }, reply);
    expect(state.body).toMatchObject({
      consents: [{ id: 'c1', clientId: 'app-123', clientName: 'Cool App', scopes: ['email'] }],
    });
    // The response MUST include a CSRF token for the caller to echo back.
    expect((state.body as any).csrfToken).toEqual(expect.any(String));
    expect((state.body as any).csrfToken.length).toBeGreaterThan(0);
    // The minted token MUST have been persisted to the session.
    expect(fastify.sessionUtils.setSession).toHaveBeenCalled();
  });

  it('GET /consents mints its CSRF token without extending the session', async () => {
    // SESSION_COOKIE_TTL is 3600 s here; the session is 50 minutes old.
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('s1');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      ...sessionWith('u1', 's1'),
      createdAt: Date.now() - 50 * 60 * 1000,
    });
    (
      fastify.repositories.oauthConsents.listActiveForUserWithClient as unknown as Mock
    ).mockResolvedValue([]);

    const handler = ctx.get;
    if (!handler) throw new Error('Handler missing');
    const { reply } = createReply();
    await handler({ headers: { cookie: `__Host-qauth_session=${signed}` } }, reply);

    const ttl = (fastify.sessionUtils.setSession as unknown as Mock).mock.calls[0][2];
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(10 * 60);
  });

  it('GET /consents reuses the existing apiCsrfToken without re-minting', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('s1');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      sessionWith('u1', 's1', 'pre-existing-token')
    );
    (
      fastify.repositories.oauthConsents.listActiveForUserWithClient as unknown as Mock
    ).mockResolvedValue([]);

    const { reply, state } = createReply();
    await ctx.get!({ headers: { cookie: `__Host-qauth_session=${signed}` } }, reply);
    // Existing token is reused — no re-mint / no session write.
    expect((state.body as any).csrfToken).toBe('pre-existing-token');
    expect(fastify.sessionUtils.setSession).not.toHaveBeenCalled();
  });

  it('DELETE /consents/:id rejects when the X-CSRF-Token header is missing', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('s2');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      sessionWith('u1', 's2', 'valid-token')
    );

    const { reply } = createReply();
    await expect(
      ctx.delete!(
        {
          headers: { cookie: `__Host-qauth_session=${signed}` },
          params: { id: CONSENT_ID },
          ip: '1.1.1.1',
        },
        reply
      )
    ).rejects.toThrow(BadRequestError);
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
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('s2');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      sessionWith('u1', 's2', 'valid-token')
    );

    const { reply } = createReply();
    await expect(
      ctx.delete!(
        {
          headers: { cookie: `__Host-qauth_session=${signed}`, 'x-csrf-token': 'wrong-token' },
          params: { id: CONSENT_ID },
          ip: '1.1.1.1',
        },
        reply
      )
    ).rejects.toThrow(BadRequestError);
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
  });

  it('DELETE /consents/:id revokes when the CSRF token matches and the consent belongs to the user', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('s2');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      sessionWith('u1', 's2', 'valid-token')
    );
    (
      fastify.repositories.oauthConsents.listActiveForUserWithClient as unknown as Mock
    ).mockResolvedValue([
      {
        id: CONSENT_ID,
        oauthClientId: 'cli1',
        realmId: 'realm-1',
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
        headers: { cookie: `__Host-qauth_session=${signed}`, 'x-csrf-token': 'valid-token' },
        params: { id: CONSENT_ID },
        ip: '1.1.1.1',
      },
      reply
    );
    expect(state.statusCode).toBe(204);
    expect(fastify.repositories.oauthConsents.revoke).toHaveBeenCalledWith(CONSENT_ID, 'tx');
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
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('s3');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      sessionWith('u-other', 's3', 'valid-token')
    );
    (
      fastify.repositories.oauthConsents.listActiveForUserWithClient as unknown as Mock
    ).mockResolvedValue([]);

    const { reply } = createReply();
    await expect(
      ctx.delete!(
        {
          headers: { cookie: `__Host-qauth_session=${signed}`, 'x-csrf-token': 'valid-token' },
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
