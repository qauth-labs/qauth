import { NotFoundError } from '@qauth-labs/shared-errors';
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
        revoke: vi.fn(),
      },
      oauthClients: {
        findById: vi.fn(),
      },
      auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
    },
    sessionUtils: { getSession: vi.fn() },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
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

  it('GET /consents lists active consents for the user', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('s1');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'u1',
      email: 'a@b.com',
      sessionId: 's1',
      createdAt: 0,
    });
    (fastify.repositories.oauthConsents.listActiveForUser as unknown as Mock).mockResolvedValue([
      { id: 'c1', oauthClientId: 'cli1', scopes: ['email'], grantedAt: 1, revokedAt: null },
    ]);
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue({
      clientId: 'app-123',
      name: 'Cool App',
    });

    const { reply, state } = createReply();
    await ctx.get!({ headers: { cookie: `__Host-qauth_session=${signed}` } }, reply);
    expect(state.body).toMatchObject({
      consents: [{ id: 'c1', clientId: 'app-123', clientName: 'Cool App', scopes: ['email'] }],
    });
  });

  it('DELETE /consents/:id revokes when the consent belongs to the user', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('s2');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'u1',
      email: 'a@b.com',
      sessionId: 's2',
      createdAt: 0,
    });
    (fastify.repositories.oauthConsents.listActiveForUser as unknown as Mock).mockResolvedValue([
      { id: 'c1', oauthClientId: 'cli1', scopes: ['email'], grantedAt: 1, revokedAt: null },
    ]);
    (fastify.repositories.oauthConsents.revoke as unknown as Mock).mockResolvedValue({});

    const { reply, state } = createReply();
    await ctx.delete!(
      {
        headers: { cookie: `__Host-qauth_session=${signed}` },
        params: { id: 'c1' },
        ip: '1.1.1.1',
      },
      reply
    );
    expect(state.statusCode).toBe(204);
    expect(fastify.repositories.oauthConsents.revoke).toHaveBeenCalledWith('c1');
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalled();
  });

  it('DELETE /consents/:id rejects revocation for a different user', async () => {
    const { fastify, ctx } = makeFastify();
    await consentsRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('s3');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'u-other',
      email: 'x@y.com',
      sessionId: 's3',
      createdAt: 0,
    });
    (fastify.repositories.oauthConsents.listActiveForUser as unknown as Mock).mockResolvedValue([]);

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
    ).rejects.toThrow(NotFoundError);
    expect(fastify.repositories.oauthConsents.revoke).not.toHaveBeenCalled();
  });
});
