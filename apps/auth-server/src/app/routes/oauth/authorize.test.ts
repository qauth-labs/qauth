import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

const { ssrfSafeGet } = vi.hoisted(() => ({ ssrfSafeGet: vi.fn() }));

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
    // CIMD config (consumed transitively via client-resolution → cimd).
    CIMD_ENABLED: true,
    CIMD_TRUST_POLICY: 'accept-any-https',
    CIMD_TRUSTED_DOMAINS: [],
    CIMD_CACHE_DEFAULT_TTL: 300,
    CIMD_CACHE_MAX_TTL: 3600,
    CIMD_MAX_DOCUMENT_BYTES: 65536,
    CIMD_FETCH_TIMEOUT_MS: 5000,
    CIMD_ALLOW_PRIVATE_ADDRESSES: false,
  },
}));

// Mock only the network layer so CIMD resolution runs against a fixture doc.
vi.mock('../../helpers/ssrf-safe-fetch', async () => {
  const actual = await vi.importActual<typeof import('../../helpers/ssrf-safe-fetch')>(
    '../../helpers/ssrf-safe-fetch'
  );
  return { ...actual, ssrfSafeGet };
});

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

  it('parses RFC 8707 resource from request.url even when the validator does not populate request.query', async () => {
    // Regression: fastify-type-provider-zod@6.1.0 does NOT put the Zod-parsed
    // `resource` back onto `request.query` for GET routes, so a real auth
    // flow had `query.resource === undefined` despite the URL carrying
    // `?resource=X`. We now parse the URL directly — testing that path.
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      revokedAt: null,
    });
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-4');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-4',
      createdAt: Date.now(),
    });

    const { reply } = createReply();
    await ctx.handler!(
      {
        // `request.query` intentionally DOES NOT include `resource` — mirrors
        // what we see in production when the Zod validator strips it.
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email&resource=https%3A%2F%2Fapi.example.com%2Fv1',
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.resource).toEqual(['https://api.example.com/v1']);
  });

  it('parses multiple `resource=` params from request.url into an array', async () => {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      revokedAt: null,
    });
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId('sid-5');
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-5',
      createdAt: Date.now(),
    });

    const { reply } = createReply();
    await ctx.handler!(
      {
        query: BASE_QUERY,
        url:
          '/oauth/authorize?response_type=code&client_id=app-123&scope=email' +
          '&resource=https%3A%2F%2Fapi.example.com%2Fv1' +
          '&resource=https%3A%2F%2Fapi2.example.com%2Fv1',
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );

    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.resource).toEqual([
      'https://api.example.com/v1',
      'https://api2.example.com/v1',
    ]);
  });
});

describe('GET /oauth/authorize — CIMD (Client ID Metadata Documents)', () => {
  const CIMD_ID = 'https://app.example.com/client-metadata.json';

  function cimdDoc(redirectUris: string[]) {
    return {
      status: 200,
      body: JSON.stringify({
        client_id: CIMD_ID,
        client_name: 'MCP Client',
        redirect_uris: redirectUris,
      }),
      headers: { 'cache-control': 'max-age=600' },
    };
  }

  function makeCimdFastify() {
    const ctx: { handler?: (req: any, reply: any) => Promise<unknown> } = {};
    const store = new Map<string, string>();
    const fastify: any = {
      withTypeProvider: () => ({
        get: (_url: string, _opts: unknown, handler: any) => {
          ctx.handler = handler;
          return fastify;
        },
      }),
      redis: {
        get: vi.fn(async (k: string) => store.get(k) ?? null),
        set: vi.fn(async (k: string, v: string) => {
          store.set(k, v);
          return 'OK';
        }),
      },
      passwordHasher: { hashPassword: vi.fn(async () => 'argon2id$sentinel') },
      repositories: {
        realms: {
          findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'master', enabled: true }),
          create: vi.fn(),
        },
        oauthClients: {
          // No pre-registered row → falls through to CIMD resolution.
          findByClientId: vi.fn().mockResolvedValue(undefined),
          upsertCimdClient: vi.fn(async (row: any) => ({
            ...row,
            id: '22222222-2222-2222-2222-222222222222',
            audience: null,
            dynamicRegisteredAt: null,
          })),
        },
        oauthConsents: { findActive: vi.fn() },
        authorizationCodes: { create: vi.fn().mockResolvedValue({ id: 'code-1' }) },
        auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
      },
      jwtUtils: { extractFromHeader: vi.fn(), verifyAccessToken: vi.fn() },
      sessionUtils: { getSession: vi.fn() },
      log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    };
    return { fastify: fastify as FastifyInstance, ctx };
  }

  it('rejects when redirect_uri is not in the CIMD document (mismatch)', async () => {
    ssrfSafeGet.mockReset();
    ssrfSafeGet.mockResolvedValue(cimdDoc(['https://app.example.com/other-cb']));

    const { fastify, ctx } = makeCimdFastify();
    await authorizeRoute(fastify);

    const { reply } = createReply();
    await expect(
      ctx.handler!(
        {
          query: {
            response_type: 'code',
            client_id: CIMD_ID,
            redirect_uri: 'https://app.example.com/callback', // not in the doc
            code_challenge: 'A'.repeat(43),
            code_challenge_method: 'S256',
            state: 'xyz',
          },
          url: `/oauth/authorize?response_type=code&client_id=${encodeURIComponent(CIMD_ID)}`,
          headers: {},
          ip: '127.0.0.1',
        },
        reply
      )
    ).rejects.toThrow(/redirect_uri/);
  });

  it('happy path: resolves CIMD client, materialises it, and proceeds to login/consent', async () => {
    ssrfSafeGet.mockReset();
    ssrfSafeGet.mockResolvedValue(cimdDoc(['https://app.example.com/callback']));

    const { fastify, ctx } = makeCimdFastify();
    await authorizeRoute(fastify);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(null);

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: {
          response_type: 'code',
          client_id: CIMD_ID,
          redirect_uri: 'https://app.example.com/callback', // in the doc
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          state: 'xyz',
        },
        url: `/oauth/authorize?response_type=code&client_id=${encodeURIComponent(CIMD_ID)}`,
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    // The redirect_uri matched the document → resolution + materialisation
    // succeeded, and with no session the flow proceeds to login.
    expect(fastify.repositories.oauthClients.upsertCimdClient).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('/ui/login?return_to=');
  });
});

describe('GET /oauth/authorize — agent scope-mode cap (ADR-007 §2, #184)', () => {
  // An agent capped at `readonly` whose ALLOWLIST nevertheless contains
  // `agent:exec` — the exact escalation the cap must block even though the
  // ordinary allowlist would permit the scope.
  const READONLY_AGENT = {
    ...CLIENT,
    clientId: 'agent-ro',
    scopes: ['agent:readonly', 'agent:exec', 'email'],
    isAgent: true,
    maxAgentMode: 'readonly' as const,
  };

  async function runAuthorize(client: typeof CLIENT, scope: string, sid: string) {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    // Existing consent covers the requested scopes so the flow reaches code
    // issuance (skips the /ui/consent redirect) — isolating the cap check.
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['agent:readonly', 'agent:exec', 'email'],
      revokedAt: null,
    });
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId(sid);
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: sid,
      createdAt: Date.now(),
    });
    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, client_id: (client as { clientId: string }).clientId, scope },
        url: `/oauth/authorize?response_type=code&client_id=${(client as { clientId: string }).clientId}&scope=${encodeURIComponent(scope)}`,
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );
    return { fastify, state };
  }

  it('rejects an over-cap scope with invalid_scope and issues NO code', async () => {
    const { fastify, state } = await runAuthorize(READONLY_AGENT, 'agent:exec', 'sid-ro-1');
    expect(state.redirected).toContain('error=invalid_scope');
    expect(state.redirected).toContain('state=xyz');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('allows an in-cap scope and issues a code', async () => {
    const { fastify, state } = await runAuthorize(READONLY_AGENT, 'agent:readonly', 'sid-ro-2');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('code=');
    expect(state.redirected).not.toContain('error=');
  });

  it('rejects ANY agent scope for a non-agent client even if allowlisted (untrusted is_agent)', async () => {
    // is_agent omitted ⇒ not an agent ⇒ agent:readonly denied despite the cap.
    const nonAgent = { ...READONLY_AGENT, clientId: 'not-agent', isAgent: false };
    const { fastify, state } = await runAuthorize(nonAgent, 'agent:readonly', 'sid-ro-3');
    expect(state.redirected).toContain('error=invalid_scope');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('rejects an agent scope when the cap is null (default-deny)', async () => {
    const noCap = { ...READONLY_AGENT, clientId: 'no-cap', maxAgentMode: null };
    const { fastify, state } = await runAuthorize(noCap, 'agent:readonly', 'sid-ro-4');
    expect(state.redirected).toContain('error=invalid_scope');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });
});

describe('GET /oauth/authorize — step-up authentication (ADR-007 §2, #185)', () => {
  // Client whose allowlist includes a dangerous (write:*) scope.
  const DANGEROUS_CLIENT = {
    ...CLIENT,
    clientId: 'app-danger',
    scopes: ['read:foo', 'write:foo', 'email'],
  };

  const MINUTE = 60 * 1000;

  async function run(opts: {
    client?: typeof CLIENT;
    scope: string;
    priorConsent?: string[] | null;
    createdAt: number;
    prompt?: string;
    maxAge?: string;
    sid: string;
  }) {
    const client = opts.client ?? DANGEROUS_CLIENT;
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(
      opts.priorConsent === null || opts.priorConsent === undefined
        ? undefined
        : { scopes: opts.priorConsent, revokedAt: null }
    );
    const { signSessionId } = await import('../../helpers/session-cookie');
    const signed = signSessionId(opts.sid);
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue({
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: opts.sid,
      createdAt: opts.createdAt,
    });
    const clientId = (client as { clientId: string }).clientId;
    const query: Record<string, unknown> = {
      ...BASE_QUERY,
      client_id: clientId,
      scope: opts.scope,
    };
    if (opts.prompt) query.prompt = opts.prompt;
    if (opts.maxAge) query.max_age = Number(opts.maxAge);
    const urlParams = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      scope: opts.scope,
      ...(opts.prompt ? { prompt: opts.prompt } : {}),
      ...(opts.maxAge ? { max_age: opts.maxAge } : {}),
    });
    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query,
        url: `/oauth/authorize?${urlParams.toString()}`,
        headers: { cookie: `__Host-qauth_session=${signed}` },
        ip: '127.0.0.1',
      },
      reply
    );
    return { fastify, state };
  }

  it('forces a fresh login for a dangerous elevation on a stale session', async () => {
    const { fastify, state } = await run({
      scope: 'write:foo',
      priorConsent: null,
      createdAt: Date.now() - 10 * MINUTE,
      sid: 'sid-su-1',
    });
    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    const events = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls.map(
      (c) => (c[0] as { event: string }).event
    );
    expect(events).toContain('oauth.stepup.required');
  });

  it('sends a non-dangerous elevation to the consent screen (incremental consent), not silently widened', async () => {
    // Prior consent covers read:foo; the request adds write:foo? No — use a
    // non-dangerous widening: prior covers email, request adds read:foo.
    const { fastify, state } = await run({
      client: CLIENT,
      scope: 'read:foo email',
      priorConsent: ['email'],
      createdAt: Date.now() - 10 * MINUTE,
      sid: 'sid-su-2',
    });
    // read:foo is a NEW (elevated) scope → must re-consent, not skip.
    expect(state.redirected).toContain('/ui/consent?');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('skips step-up when the request is fully within the prior grant and not dangerous', async () => {
    const { fastify, state } = await run({
      client: CLIENT,
      scope: 'email',
      priorConsent: ['email', 'read:foo'],
      createdAt: Date.now() - 10 * MINUTE,
      sid: 'sid-su-3',
    });
    // No elevation, no danger, no prompt → code issued directly.
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('code=');
  });

  it('does NOT loop: a dangerous elevation on a FRESH session proceeds to consent', async () => {
    const { fastify, state } = await run({
      scope: 'write:foo',
      priorConsent: null,
      createdAt: Date.now() - 5000, // fresh
      sid: 'sid-su-4',
    });
    // Fresh auth satisfies the login requirement; the elevation still needs
    // consent (no prior grant), so we land on the consent screen — not login.
    expect(state.redirected).toContain('/ui/consent?');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('prompt=login forces fresh auth even for a covered, non-dangerous scope', async () => {
    const { fastify, state } = await run({
      client: CLIENT,
      scope: 'email',
      priorConsent: ['email'],
      createdAt: Date.now() - 10 * MINUTE,
      prompt: 'login',
      sid: 'sid-su-5',
    });
    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('max_age=0 forces fresh auth when the session is a second or more old', async () => {
    const { fastify, state } = await run({
      client: CLIENT,
      scope: 'email',
      priorConsent: ['email'],
      createdAt: Date.now() - 5000, // 5s old → floor(5) = 5 > 0
      maxAge: '0',
      sid: 'sid-su-6',
    });
    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  // BLOCKER #1 regression: the authorize → login → authorize round-trip for
  // max_age=0 MUST terminate. After login re-mints the session, the second
  // authorize sees a sub-second-old auth_time; with OIDC second-granularity
  // (floor), max_age=0 is satisfied (0 > 0 is false) and a code is minted
  // rather than bouncing to /ui/login again forever.
  it('max_age=0 TERMINATES: a just-logged-in (sub-second) session mints the code', async () => {
    const { fastify, state } = await run({
      client: CLIENT,
      scope: 'email',
      priorConsent: ['email'],
      createdAt: Date.now() - 40, // 40ms old, simulating the post-login return trip
      maxAge: '0',
      sid: 'sid-su-6b',
    });
    expect(state.redirected).not.toContain('/ui/login');
    expect(state.redirected).toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
  });

  // Should-fix #2: a dangerous scope already covered by a remembered prior
  // consent must STILL force fresh auth on the authorize skip-consent path — it
  // cannot be replayed off a stale grant. (Previously this minted directly.)
  it('forces fresh auth for a REMEMBERED dangerous scope on a stale session (no replay)', async () => {
    const { fastify, state } = await run({
      scope: 'write:foo',
      priorConsent: ['write:foo'], // remembered → would otherwise skip consent
      createdAt: Date.now() - 10 * MINUTE,
      sid: 'sid-su-7',
    });
    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  // OIDC Core §3.1.2.1: prompt=none must NOT show UI; an interaction need is
  // reported as the matching error to the client instead.
  it('prompt=none returns login_required (no UI) when a dangerous scope needs fresh auth', async () => {
    const { fastify, state } = await run({
      scope: 'write:foo',
      priorConsent: ['write:foo'],
      createdAt: Date.now() - 10 * MINUTE,
      prompt: 'none',
      sid: 'sid-su-8',
    });
    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('error=login_required');
    expect(state.redirected).not.toContain('/ui/login');
    expect(state.redirected).not.toContain('/ui/consent');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('prompt=none returns consent_required (no UI) for a non-dangerous elevation', async () => {
    const { fastify, state } = await run({
      client: CLIENT,
      scope: 'read:foo email',
      priorConsent: ['email'], // read:foo is a new, non-dangerous elevation
      createdAt: Date.now() - 1000,
      prompt: 'none',
      sid: 'sid-su-9',
    });
    expect(state.redirected).toContain('error=consent_required');
    expect(state.redirected).not.toContain('/ui/consent');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('prompt=none proceeds (mints a code) when no interaction is required', async () => {
    const { fastify, state } = await run({
      client: CLIENT,
      scope: 'email',
      priorConsent: ['email'],
      createdAt: Date.now() - 1000,
      prompt: 'none',
      sid: 'sid-su-10',
    });
    expect(state.redirected).toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
  });
});

describe('GET /oauth/authorize — Bearer path step-up (ADR-007 §2, #185)', () => {
  // The Bearer (legacy first-party) path cannot run interactive step-up, so a
  // dangerous scope on it is refused rather than minted with no fresh auth.
  const DANGEROUS_CLIENT = {
    ...CLIENT,
    clientId: 'app-bearer',
    scopes: ['read:foo', 'write:foo', 'email'],
  };

  async function runBearer(scope: string) {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      DANGEROUS_CLIENT
    );
    // No browser session; a valid Bearer token resolves the user.
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(null);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('bearer.token');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({ sub: 'user-1' });
    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, client_id: 'app-bearer', scope },
        url: `/oauth/authorize?response_type=code&client_id=app-bearer&scope=${encodeURIComponent(scope)}`,
        headers: { authorization: 'Bearer bearer.token' },
        ip: '127.0.0.1',
      },
      reply
    );
    return { fastify, state };
  }

  it('refuses a dangerous scope on the Bearer path with access_denied (no interactive step-up)', async () => {
    const { fastify, state } = await runBearer('write:foo');
    expect(state.redirected).toContain('error=access_denied');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('still mints a code for a non-dangerous scope on the Bearer path', async () => {
    const { fastify, state } = await runBearer('email');
    expect(state.redirected).toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
  });
});
