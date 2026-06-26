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
    // Mirrors @fastify/helmet's enableCSPNonces decorator (issue #113): the
    // consent/login renderers read reply.cspNonce.style for the inline <style>.
    cspNonce: { script: 'test-script-nonce', style: 'test-style-nonce' },
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
    // Clickjacking/MIME/Referrer/CSP hardening moved to the global
    // security-headers plugin (#113) — covered in security-headers.test.ts.
    // The page stamps the per-request CSP nonce onto its inline <style>.
    expect(html).toContain('nonce="test-style-nonce"');
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
      consentScopes: { 'app-123': ['email'] },
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

  it('persists RFC 8707 resource on the code when POST body carries resource field(s)', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-res');
    const csrf = 'csrf-res';
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-res',
      csrfToken: csrf,
      createdAt: Date.now(),
      consentScopes: { 'app-123': ['email'] },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply } = createReply();
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
          // Hidden form inputs from the consent page — one or more values
          // (Fastify parses multi-value form bodies as an array).
          resource: ['https://api.example.com/v1'],
        },
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.resource).toEqual(['https://api.example.com/v1']);
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
      consentScopes: { 'app-123': ['email'] },
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

  it('refuses to grant scopes the hidden field tampered beyond what was rendered (#150 binding)', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-tamper');
    const csrf = 'csrf-tamper';
    // The GET render bound only `email` (what the user saw). Both `email` and
    // `read:foo` are in the client allowlist, so a tampered `scope=email
    // read:foo` survives the allowlist filter — the binding check is what stops
    // the grant of the unseen `read:foo`.
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-tamper',
      csrfToken: csrf,
      createdAt: Date.now(),
      consentScopes: { 'app-123': ['email'] },
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
          // Tampered: user only saw `email`.
          scope: 'email read:foo',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    // No code minted, no grant persisted — redirected with invalid_scope.
    expect(state.redirected).toContain('error=invalid_scope');
    expect(state.redirected).toContain('state=xyz');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthConsents.upsertGrant).not.toHaveBeenCalled();
  });
});

describe('UI /ui/consent — agent scope-mode cap (ADR-007 §2, #184)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // An agent capped at `readonly` whose ALLOWLIST contains `agent:exec`. This
  // is the exact bypass the blocker described: the allowlist would permit
  // agent:exec, but the cap must refuse to mint a code for it on the consent
  // (code-issuing) path. `filterRequestedScopes` alone would have let it through.
  const READONLY_AGENT = {
    ...CLIENT,
    scopes: ['agent:readonly', 'agent:exec', 'email'],
    isAgent: true,
    maxAgentMode: 'readonly' as const,
  };

  function agentSession(sid: string, csrf: string) {
    return {
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: sid,
      csrfToken: csrf,
      createdAt: Date.now(),
      // The over-cap / non-agent tests reject at the agent-cap gate BEFORE the
      // scope-presentation binding check; the in-cap success test POSTs
      // `agent:readonly`, so bind that so its grant matches what was rendered.
      consentScopes: { 'app-123': ['agent:readonly'] },
    };
  }

  it('POST rejects an over-cap scope with invalid_scope and issues NO code (blocker regression)', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-cap-1');
    const csrf = 'csrf-cap-1';
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      agentSession('sid-cap-1', csrf)
    );
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      READONLY_AGENT
    );

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
          // Attacker-controlled hidden field — the allowlist permits it, the cap must not.
          scope: 'agent:exec',
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
    expect(state.redirected).toContain('error=invalid_scope');
    expect(state.redirected).toContain('state=xyz');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthConsents.upsertGrant).not.toHaveBeenCalled();
  });

  it('POST allows an in-cap scope and issues a code', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-cap-2');
    const csrf = 'csrf-cap-2';
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      agentSession('sid-cap-2', csrf)
    );
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      READONLY_AGENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: 'agent:readonly',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('code=');
    expect(state.redirected).not.toContain('error=');
  });

  it('POST rejects ANY agent scope for a non-agent client even if allowlisted (untrusted is_agent)', async () => {
    const nonAgent = { ...READONLY_AGENT, isAgent: false };
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-cap-3');
    const csrf = 'csrf-cap-3';
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      agentSession('sid-cap-3', csrf)
    );
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      nonAgent
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: 'agent:readonly',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('error=invalid_scope');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('GET fails fast with invalid_scope for an over-cap scope (no consent screen rendered)', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-cap-4');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-cap-4',
      createdAt: Date.now(),
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      READONLY_AGENT
    );

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: { ...BASE_QUERY, scope: 'agent:exec' },
        url: '/ui/consent?scope=agent:exec',
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('error=invalid_scope');
    expect(state.redirected).toContain('state=xyz');
    // No HTML consent page was rendered.
    expect(state.body).toBeUndefined();
  });
});

describe('UI /ui/consent — step-up authentication (ADR-007 §2, #185)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Client whose allowlist includes a DANGEROUS scope (write:foo). Used to
  // prove the mint path forces a fresh authentication before a dangerous grant.
  const DANGEROUS_CLIENT = {
    ...CLIENT,
    scopes: ['read:foo', 'write:foo', 'email'],
  };

  const MINUTE = 60 * 1000;

  function postBody(overrides: Record<string, unknown> = {}) {
    return {
      decision: 'allow',
      allow_forever: '1',
      csrf_token: 'csrf-su',
      client_id: 'app-123',
      redirect_uri: 'https://example.com/cb',
      state: 'xyz',
      scope: 'write:foo',
      code_challenge: 'A'.repeat(43),
      code_challenge_method: 'S256',
      response_type: 'code',
      ...overrides,
    };
  }

  // Scope-presentation binding (#150 hardening): the consent GET render binds the
  // visible scope set to the session; the POST grants ONLY that set. The bound
  // set must equal what the test POSTs, so callers pass the scope they submit
  // (default `write:foo`, the dangerous scope these step-up tests exercise).
  function session(createdAt: number, boundScope = 'write:foo') {
    return {
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-su',
      csrfToken: 'csrf-su',
      createdAt,
      consentScopes: { 'app-123': boundScope.split(/\s+/).filter((s) => s.length > 0) },
    };
  }

  it('refuses to mint a code for a dangerous scope on a STALE session and bounces to /ui/login', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-su');
    // Session authenticated 10 minutes ago — outside the 2-minute fresh window.
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      session(Date.now() - 10 * MINUTE)
    );
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      DANGEROUS_CLIENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody(),
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    // Bounced to login (fresh-auth required); NO code, NO grant persisted.
    expect(state.redirected).toContain('/ui/login?return_to=');
    // The dangerous scope survives the round-trip; the return_to is itself
    // URL-encoded, so `scope=write:foo` appears doubly-encoded.
    expect(decodeURIComponent(state.redirected as string)).toContain('scope=write%3Afoo');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthConsents.upsertGrant).not.toHaveBeenCalled();
    // The step-up requirement is audited.
    const events = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls.map(
      (c) => (c[0] as { event: string }).event
    );
    expect(events).toContain('oauth.stepup.required');
  });

  it('mints a dangerous-scope code on a FRESH session and audits the elevation', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-su');
    // Authenticated 5 seconds ago — within the fresh-auth window.
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      session(Date.now() - 5000)
    );
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      DANGEROUS_CLIENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody(),
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    const events = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls.map(
      (c) => (c[0] as { event: string }).event
    );
    expect(events).toContain('oauth.stepup.elevation');
    expect(events).toContain('oauth.consent.granted');
  });

  it('per-agent audit (#186): elevation by an agent client attributes actor + scope mode', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-su');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      session(Date.now() - 5000, 'agent:exec')
    );
    // An EXEC-capped agent elevating to the dangerous `agent:exec` scope.
    const EXEC_AGENT = {
      ...DANGEROUS_CLIENT,
      isAgent: true,
      maxAgentMode: 'exec' as const,
      scopes: ['read:foo', 'agent:exec', 'email'],
    };
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      EXEC_AGENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody({ scope: 'agent:exec' }),
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('code=');
    const elevation = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls
      .map((c) => c[0])
      .find((a) => a?.event === 'oauth.stepup.elevation');
    expect(elevation).toMatchObject({
      userId: 'user-1',
      actorClientId: 'app-123',
      scopeMode: 'exec',
    });
    // No-leak: the step-up elevation row must carry no session/CSRF secret,
    // no minted code, and no token material — only public identifiers.
    const serialized = JSON.stringify(elevation);
    expect(serialized).not.toContain('csrf-su');
    expect(serialized).not.toContain('sid-su');
    expect(serialized).not.toContain(signed);
    expect(serialized).not.toContain('code=');
  });

  it('per-agent audit (#186): elevation by a NON-agent client records no agent attribution', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-su');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      session(Date.now() - 5000)
    );
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      DANGEROUS_CLIENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody(),
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('code=');
    const elevation = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls
      .map((c) => c[0])
      .find((a) => a?.event === 'oauth.stepup.elevation');
    // Non-agent client: the elevation is still audited, but with no agent fields.
    expect(elevation).toMatchObject({ actorClientId: null, scopeMode: null });
  });

  it('forces fresh auth for prompt=login on a stale session even with a non-dangerous scope', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-su');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      session(Date.now() - 10 * MINUTE, 'email')
    );
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody({ scope: 'email', prompt: 'login' }),
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('mints a non-dangerous scope without step-up on a stale session (no over-gating)', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-su');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(
      session(Date.now() - 10 * MINUTE, 'email')
    );
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody({ scope: 'email' }),
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
  });
});
