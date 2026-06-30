import { BadRequestError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
  },
}));

import consentsRoute from './index';

interface TestContext {
  get?: (request: any, reply: any) => Promise<unknown>;
  delete?: (request: any, reply: any) => Promise<unknown>;
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
  const ctx: TestContext = {};
  const fastify: any = {
    withTypeProvider: () => ({
      get: (_u: string, _o: unknown, h: any) => {
        ctx.get = h;
        return fastify;
      },
      delete: (_u: string, _o: unknown, h: any) => {
        ctx.delete = h;
        return fastify;
      },
    }),
    repositories: {
      oauthConsents: {
        listActiveForUser: vi.fn(),
        listActiveForUserWithClient: vi.fn(),
        revoke: vi.fn(),
      },
      oauthClients: {
        findById: vi.fn(),
      },
      auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
    },
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
    createdAt: 0,
    ...(apiCsrfToken ? { apiCsrfToken } : {}),
  };
}

describe('/consents JSON API', () => {
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
          params: { id: 'c1' },
          ip: '1.1.1.1',
        },
        reply
      )
    ).rejects.toThrow(BadRequestError);
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
    // Audit logs the CSRF failure.
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'consents.revoke.csrf_failure', success: false })
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
          params: { id: 'c1' },
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
    (fastify.repositories.oauthConsents.listActiveForUser as unknown as Mock).mockResolvedValue([
      { id: 'c1', oauthClientId: 'cli1', scopes: ['email'], grantedAt: 1, revokedAt: null },
    ]);
    (fastify.repositories.oauthConsents.revoke as unknown as Mock).mockResolvedValue({});

    const { reply, state } = createReply();
    await ctx.delete!(
      {
        headers: { cookie: `__Host-qauth_session=${signed}`, 'x-csrf-token': 'valid-token' },
        params: { id: 'c1' },
        ip: '1.1.1.1',
      },
      reply
    );
    expect(state.statusCode).toBe(204);
    expect(fastify.repositories.oauthConsents.revoke).toHaveBeenCalledWith('c1');
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'oauth.consent.revoked', success: true })
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
    (fastify.repositories.oauthConsents.listActiveForUser as unknown as Mock).mockResolvedValue([]);

    const { reply } = createReply();
    await expect(
      ctx.delete!(
        {
          headers: { cookie: `__Host-qauth_session=${signed}`, 'x-csrf-token': 'valid-token' },
          params: { id: 'c1' },
          ip: '1.1.1.1',
        },
        reply
      )
    ).rejects.toThrow(NotFoundError);
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
  });
});
