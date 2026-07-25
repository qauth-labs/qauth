import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

/**
 * Login-redirect header-size regression (issue #316 follow-up).
 *
 * #316 raised the `state`/`nonce` cap from 255 to
 * `OAUTH_OPAQUE_PARAM_MAX_LENGTH` (2048). That made a pathological but legal
 * client reachable: one that puts a RAW (non-base64) JSON blob in `state`.
 * Every `{`, `"`, `:`, `,` and `}` percent-encodes to three bytes in the
 * authorize query string, and nesting that whole query string inside
 * `/ui/login?return_to=` re-encodes each `%` again (`%XX` → `%25XX`), so the
 * 2048-char `state` alone lands at ~4x its size in the `Location` header.
 *
 * Measured before the pending-authorization handle landed, that header was
 * ~10.4 KB — past nginx's default `large_client_header_buffers 4 8k` and past
 * typical ALB/CDN request-line limits, so the browser saw a 414/400 instead of
 * the login page. It only bites behind a reverse proxy, so neither local dev
 * nor the route unit tests caught it.
 *
 * These tests pin the fix at EVERY surface that bounces an end user to
 * `/ui/login`: a miss on any one of them reintroduces the amplification on
 * that path (the fix-one-site-at-a-time trap #316 was itself about).
 */

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

vi.mock('../../helpers/ssrf-safe-fetch', async () => {
  const actual = await vi.importActual<typeof import('../../helpers/ssrf-safe-fetch')>(
    '../../helpers/ssrf-safe-fetch'
  );
  return { ...actual, ssrfSafeGet };
});

import { OAUTH_OPAQUE_PARAM_MAX_LENGTH } from '../../constants';
import { RESUME_PATH_PREFIX } from '../../helpers/pending-authorization';
import { signSessionId } from '../../helpers/session-cookie';
import authorizeRoute from '../oauth/authorize';
import consentRoute from './consent';

/**
 * nginx's default `large_client_header_buffers 4 8k` bounds a single header
 * line at 8 KB. We assert comfortably under it so the budget survives the
 * `Location:` name, the scheme+host a reverse proxy may prepend on an absolute
 * redirect, and any future param growth.
 */
const HEADER_BUDGET_BYTES = 8 * 1024;

/**
 * The handle-based bounce is a FIXED 92 bytes
 * (`Location: /ui/login?return_to=%2Fui%2Fresume%2F<43-char handle>`), so the
 * header no longer scales with `state` at all. This second, much tighter bound
 * is what actually catches a regression: a call site that goes back to nesting
 * the query string would still pass the 8 KB check for a small `state` and only
 * break in production behind a proxy.
 */
const HANDLE_BOUNCE_BUDGET_BYTES = 256;

/**
 * Worst-case `state`: raw JSON at exactly the permitted maximum. Every
 * character except the bare identifiers percent-encodes, which is precisely
 * what drives the amplification.
 */
function worstCaseState(): string {
  const unit = '{"a":"b","c":"d"},';
  let s = '';
  while (s.length < OAUTH_OPAQUE_PARAM_MAX_LENGTH) s += unit;
  return s.slice(0, OAUTH_OPAQUE_PARAM_MAX_LENGTH);
}

const WORST_CASE_STATE = worstCaseState();

const CLIENT = {
  id: 'client-uuid-1',
  clientId: 'app-123',
  clientSecretHash: 'h',
  name: 'Test App',
  enabled: true,
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  scopes: ['read:foo', 'email', 'write:foo'],
  audience: null,
  redirectUris: ['https://example.com/cb'],
  dynamicRegisteredAt: null,
  metadata: null,
};

const BASE_QUERY = {
  response_type: 'code' as const,
  client_id: 'app-123',
  redirect_uri: 'https://example.com/cb',
  code_challenge: 'A'.repeat(43),
  code_challenge_method: 'S256' as const,
  scope: 'email',
  state: WORST_CASE_STATE,
  nonce: 'n'.repeat(OAUTH_OPAQUE_PARAM_MAX_LENGTH),
};

/** The authorize URL a browser would actually send for {@link BASE_QUERY}. */
function authorizeUrl(query: Record<string, string> = BASE_QUERY): string {
  const usp = new URLSearchParams(query);
  return `/oauth/authorize?${usp.toString()}`;
}

function createReply() {
  const state: {
    statusCode?: number;
    headers: Record<string, string>;
    redirected?: string;
    body?: unknown;
  } = { headers: {} };
  const reply: any = {
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
  const ctx: {
    get?: (request: any, reply: any) => Promise<unknown>;
    post?: (request: any, reply: any) => Promise<unknown>;
  } = {};
  const stash = new Map<string, unknown>();
  const fastify: any = {
    withTypeProvider: () => {
      const route = {
        get: (_url: string, _opts: unknown, handler: any) => {
          ctx.get = handler;
          return route;
        },
        post: (_url: string, _opts: unknown, handler: any) => {
          ctx.post = handler;
          return route;
        },
      };
      return route;
    },
    repositories: {
      realms: {
        findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'master', enabled: true }),
        create: vi.fn(),
      },
      oauthClients: { findByClientId: vi.fn().mockResolvedValue(CLIENT) },
      oauthConsents: { findActive: vi.fn(), upsertGrant: vi.fn().mockResolvedValue({}) },
      authorizationCodes: { create: vi.fn().mockResolvedValue({ id: 'code-1' }) },
      auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
    },
    jwtUtils: {
      extractFromHeader: vi.fn().mockReturnValue(null),
      verifyAccessToken: vi.fn(),
      getIssuer: () => 'https://auth.example.com',
    },
    // NOTE: the real `createSessionUtils` prefixes every key with `session:`
    // internally, so callers pass the BARE id (`resolveBrowserSession` passes
    // the session id from the cookie). This double must therefore be seeded
    // with bare ids too — seeding `session:sid-1` made `getSession('sid-1')`
    // miss, which silently degraded the step-up tests below into the
    // no-session branch and left both step-up call sites unverified.
    sessionUtils: {
      getSession: vi.fn(async (id: string) => stash.get(id) ?? null),
      setSession: vi.fn(async (id: string, data: unknown) => {
        stash.set(id, data);
      }),
      deleteSession: vi.fn(async (id: string) => {
        stash.delete(id);
      }),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx, stash };
}

/** Byte length of the `Location:` header line the redirect would emit. */
function locationHeaderBytes(location: string | undefined): number {
  expect(location).toBeDefined();
  return Buffer.byteLength(`Location: ${location}\r\n`, 'utf8');
}

/**
 * Assert a login bounce is both SMALL and LOSSLESS: the header stays well
 * inside the proxy budget, and the authorize URL stashed server-side still
 * carries every round-tripped parameter byte-for-byte.
 */
function expectCompactLoginBounce(
  location: string | undefined,
  fastify: FastifyInstance,
  expected: Record<string, string>
): void {
  const bytes = locationHeaderBytes(location);
  expect(bytes).toBeLessThan(HEADER_BUDGET_BYTES);
  expect(bytes).toBeLessThan(HANDLE_BOUNCE_BUDGET_BYTES);
  expect(location).toContain('/ui/login?return_to=');
  // The whole point: what rides in the URL is a handle, not the parameters.
  expect(location).toContain(encodeURIComponent(RESUME_PATH_PREFIX));
  expect(location).not.toContain(encodeURIComponent('/oauth/authorize'));

  const setSession = fastify.sessionUtils.setSession as unknown as Mock;
  const pending = setSession.mock.calls
    .map((c) => c[1] as { authorizeUrl?: string })
    .filter((d) => typeof d?.authorizeUrl === 'string');
  expect(pending.length).toBeGreaterThan(0);
  const stashed = new URL(
    (pending[pending.length - 1] as { authorizeUrl: string }).authorizeUrl,
    'http://placeholder'
  );
  for (const [k, v] of Object.entries(expected)) {
    expect(stashed.searchParams.get(k)).toBe(v);
  }
}

/**
 * Positive proof that a step-up test actually reached the step-up branch.
 *
 * Without this, a seeding mistake (or a regression in session resolution) makes
 * the request fall through to the NO-SESSION bounce, which produces an
 * identical-looking compact redirect — so the assertions above pass while the
 * call site under test never runs. That is exactly what happened here once.
 */
function expectStepUpBranchRan(fastify: FastifyInstance): void {
  const create = fastify.repositories.auditLogs.create as unknown as Mock;
  const events = create.mock.calls.map((c) => (c[0] as { event?: string })?.event);
  expect(events).toContain('oauth.stepup.required');
}

describe('login redirect size — /oauth/authorize', () => {
  it('GET with no session stays far under the proxy header budget', async () => {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(null);

    const { reply, state } = createReply();
    await ctx.get!({ query: BASE_QUERY, url: authorizeUrl(), headers: {}, ip: '127.0.0.1' }, reply);

    expectCompactLoginBounce(state.redirected, fastify, {
      state: WORST_CASE_STATE,
      nonce: BASE_QUERY.nonce,
      code_challenge: BASE_QUERY.code_challenge,
      scope: 'email',
      redirect_uri: 'https://example.com/cb',
    });
  });

  it('POST (OIDC Core §3.1.2.1) with no session stays under the budget', async () => {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(null);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        method: 'POST',
        body: BASE_QUERY,
        url: '/oauth/authorize',
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    expectCompactLoginBounce(state.redirected, fastify, {
      state: WORST_CASE_STATE,
      nonce: BASE_QUERY.nonce,
    });
  });

  it('step-up fresh-login bounce stays under the budget', async () => {
    const { fastify, ctx, stash } = makeFastify();
    await authorizeRoute(fastify);
    stash.set('sid-1', {
      userId: 'user-1',
      sessionId: 'sid-1',
      createdAt: Date.now() - 10 * 60 * 1000,
    });
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(undefined);

    const query = { ...BASE_QUERY, prompt: 'login' as const };
    const { reply, state } = createReply();
    await ctx.get!(
      {
        query,
        url: authorizeUrl({ ...BASE_QUERY, prompt: 'login' }),
        headers: { cookie: `__Host-qauth_session=${signSessionId('sid-1')}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expectStepUpBranchRan(fastify);
    expectCompactLoginBounce(state.redirected, fastify, {
      state: WORST_CASE_STATE,
      prompt: 'login',
    });
  });
});

describe('login redirect size — /ui/consent', () => {
  it('GET with no session stays under the budget', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(null);

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: BASE_QUERY,
        url: `/ui/consent?${new URLSearchParams(BASE_QUERY)}`,
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    expectCompactLoginBounce(state.redirected, fastify, {
      state: WORST_CASE_STATE,
      nonce: BASE_QUERY.nonce,
      code_challenge: BASE_QUERY.code_challenge,
    });
  });

  it('POST with no session stays under the budget', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(null);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: { ...BASE_QUERY, decision: 'allow', csrf_token: 'c', allow_forever: '1' },
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    expectCompactLoginBounce(state.redirected, fastify, {
      state: WORST_CASE_STATE,
      nonce: BASE_QUERY.nonce,
    });
  });

  it('POST step-up bounce stays under the budget', async () => {
    const { fastify, ctx, stash } = makeFastify();
    await consentRoute(fastify);
    stash.set('sid-su', {
      userId: 'user-1',
      email: 'a@b.com',
      sessionId: 'sid-su',
      csrfToken: 'csrf-su',
      createdAt: Date.now() - 10 * 60 * 1000,
      consentScopes: { 'app-123': ['write:foo'] },
    });

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          ...BASE_QUERY,
          scope: 'write:foo',
          decision: 'allow',
          csrf_token: 'csrf-su',
          allow_forever: '1',
          resource: [],
        },
        headers: { cookie: `__Host-qauth_session=${signSessionId('sid-su')}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expectStepUpBranchRan(fastify);
    expectCompactLoginBounce(state.redirected, fastify, {
      state: WORST_CASE_STATE,
      scope: 'write:foo',
    });
  });
});
