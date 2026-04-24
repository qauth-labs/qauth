import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_WINDOW: 60,
    DEFAULT_REALM_NAME: 'master',
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
  },
}));

import consentRoute from './consent';

interface TestContext {
  get?: (request: any, reply: any) => Promise<unknown>;
  post?: (request: any, reply: any) => Promise<unknown>;
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
        ctx.get = handler;
        return fastify;
      },
      post: (_url: string, _opts: unknown, handler: any) => {
        ctx.post = handler;
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
        upsertGrant: vi.fn().mockResolvedValue({}),
      },
      authorizationCodes: {
        create: vi.fn().mockResolvedValue({ id: 'code-1' }),
      },
      auditLogs: {
        create: vi.fn().mockResolvedValue(undefined),
      },
    },
    sessionUtils: {
      getSession: vi.fn(),
      setSession: vi.fn().mockResolvedValue(undefined),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

const CLIENT = {
  id: 'client-uuid-1',
  clientId: 'app-123',
  clientSecretHash: 'h',
  name: 'Test App',
  enabled: true,
  scopes: ['read:foo', 'email'],
  redirectUris: ['https://example.com/cb'],
  audience: null,
  dynamicRegisteredAt: null,
  metadata: null,
};

const BASE_QUERY = {
  response_type: 'code' as const,
  client_id: 'app-123',
  redirect_uri: 'https://example.com/cb',
  code_challenge: 'A'.repeat(43),
  code_challenge_method: 'S256' as const,
  state: 'xyz',
  scope: 'email',
};

describe('UI /ui/consent GET — rendering', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('redirects to /ui/login when no session cookie present', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(null);

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: BASE_QUERY,
        url: '/ui/consent?...',
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('/ui/login?return_to=');
  });

  it('renders consent HTML with CSRF token hidden input when session is valid', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-g1');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-g1',
      createdAt: Date.now(),
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: BASE_QUERY,
        url: '/ui/consent?...',
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    const html = state.body as string;
    expect(typeof html).toBe('string');
    expect(html).toContain('Test App wants to access your account');
    expect(html).toContain('csrf_token');
    expect(state.headers['Content-Type']).toContain('text/html');
    expect(state.headers['X-Frame-Options']).toBe('DENY');
    expect(fastify.sessionUtils.setSession).toHaveBeenCalledOnce();
  });
});

describe('UI /ui/consent POST — allow/deny', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('deny path redirects to redirect_uri with error=access_denied and preserves state', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-d');
    const csrf = 'csrf-token-value-deny';
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-d',
      csrfToken: csrf,
      createdAt: Date.now(),
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'deny',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: 'email',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('error=access_denied');
    expect(state.redirected).toContain('state=xyz');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('rejects when CSRF token does not match', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-bad');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-bad',
      csrfToken: 'expected-csrf-token',
      createdAt: Date.now(),
    });

    const { reply } = createReply();
    await expect(
      ctx.post!(
        {
          body: {
            decision: 'allow',
            csrf_token: 'attacker-guessed',
            client_id: 'app-123',
            redirect_uri: 'https://example.com/cb',
            code_challenge: 'A'.repeat(43),
            code_challenge_method: 'S256',
            response_type: 'code',
          },
          headers: { cookie: `__Host-qauth_session=${signed}` },
          ip: '127.0.0.1',
        },
        reply
      )
    ).rejects.toThrow(/invalid_csrf_token/);
  });

  it('allow + allow_forever persists consent and issues an authorization code', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-a');
    const csrf = 'csrf-token-allow';
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-a',
      csrfToken: csrf,
      createdAt: Date.now(),
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          allow_forever: '1',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: 'email',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.oauthConsents.upsertGrant).toHaveBeenCalledWith(
      'user-1',
      'client-uuid-1',
      'realm-1',
      ['email']
    );
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('code=');
    expect(state.redirected).toContain('state=xyz');
  });

  it('allow without allow_forever issues code but does NOT persist consent', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-once');
    const csrf = 'csrf-once';
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-once',
      csrfToken: csrf,
      createdAt: Date.now(),
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          scope: 'email',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.oauthConsents.upsertGrant).not.toHaveBeenCalled();
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('https://example.com/cb');
  });
});
