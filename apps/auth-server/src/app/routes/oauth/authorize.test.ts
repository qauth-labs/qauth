import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_WINDOW: 60,
    DEFAULT_REALM_NAME: 'master',
    SYSTEM_CLIENT_ID: 'system',
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
  },
}));

import authorizeRoute from './authorize';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

function createReply() {
  const state: {
    statusCode?: number;
    headers: Record<string, string>;
    redirected?: string;
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
    redirect(url: string, code: number) {
      state.redirected = url;
      state.statusCode = code;
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
      get: (_url: string, _opts: unknown, handler: any) => {
        ctx.handler = handler;
        return fastify;
      },
    }),
    repositories: {
      realms: {
        findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'master', enabled: true }),
        create: vi.fn(),
      },
      oauthClients: {
        findByClientId: vi.fn(),
      },
      oauthConsents: {
        findActive: vi.fn(),
      },
      authorizationCodes: {
        create: vi.fn().mockResolvedValue({ id: 'code-1' }),
      },
      auditLogs: {
        create: vi.fn().mockResolvedValue(undefined),
      },
    },
    jwtUtils: {
      extractFromHeader: vi.fn(),
      verifyAccessToken: vi.fn(),
    },
    sessionUtils: {
      getSession: vi.fn(),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

const CLIENT = {
  id: 'client-uuid-1',
  clientId: 'app-123',
  clientSecretHash: 'h',
  enabled: true,
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  scopes: ['read:foo', 'email'],
  audience: null,
  redirectUris: ['https://example.com/cb'],
  dynamicRegisteredAt: null,
};

const BASE_QUERY = {
  response_type: 'code',
  client_id: 'app-123',
  redirect_uri: 'https://example.com/cb',
  code_challenge: 'A'.repeat(43),
  code_challenge_method: 'S256',
  state: 'xyz',
  scope: 'email',
};

describe('GET /oauth/authorize — session-cookie integration', () => {
  it('redirects unauthenticated requests to /ui/login with return_to', async () => {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(null);

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123',
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toBeDefined();
    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(state.redirected).toContain(encodeURIComponent('/oauth/authorize'));
  });

  it('redirects to /ui/consent when session is valid but no prior consent', async () => {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(undefined);

    // Build a valid signed cookie matching the mocked secret.
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-1');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-1',
      createdAt: Date.now(),
    });

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('/ui/consent?');
    // The code must NOT have been issued yet.
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('skips consent and issues code when existing consent covers the requested scopes', async () => {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email', 'read:foo'],
      revokedAt: null,
    });

    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-2');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-2',
      createdAt: Date.now(),
    });

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('code=');
    expect(state.redirected).toContain('state=xyz');
  });

  it('persists RFC 8707 resource indicator(s) onto the authorization code', async () => {
    // RFC 8707 clients sends `resource` with /oauth/authorize;
    // the code row MUST carry it so /oauth/token can set `aud` correctly.
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      revokedAt: null,
    });
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-3');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-3',
      createdAt: Date.now(),
    });

    const { reply } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, resource: ['https://api.example.com/v1'] },
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email&resource=https%3A%2F%2Fapi.example.com%2Fv1',
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.resource).toEqual(['https://api.example.com/v1']);
  });
});
