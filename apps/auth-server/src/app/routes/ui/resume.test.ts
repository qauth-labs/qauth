import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_WINDOW: 60,
    LOGIN_RATE_LIMIT: 5,
    LOGIN_RATE_WINDOW: 900,
    DEFAULT_REALM_NAME: 'master',
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
  },
}));

import { PENDING_AUTHORIZATION_MAX_URL_BYTES, PENDING_AUTHORIZATION_TTL_MS } from '../../constants';
import {
  consumePendingAuthorization,
  isPendingAuthorizationHandle,
  redirectToLoginWithPendingAuthorization,
  RESUME_PATH_PREFIX,
  stashPendingAuthorization,
} from '../../helpers/pending-authorization';
import loginRoute from './login';
import resumeRoute from './resume';

/**
 * `/ui/resume/:handle` + the pending-authorization stash behind it
 * (qauth-labs/qauth#316 follow-up). Covers the three things the handle has to
 * get right: it must not become an open redirector, it must be unguessable and
 * single-use, and a missing / expired / replayed handle must degrade to
 * something safe and comprehensible rather than a 500 or a silent redirect.
 */

function createReply() {
  const state: {
    statusCode?: number;
    headers: Record<string, string>;
    setCookies: string[];
    redirected?: string;
    body?: unknown;
  } = { headers: {}, setCookies: [] };
  const reply: any = {
    cspNonce: { script: 'test-script-nonce', style: 'test-style-nonce' },
    code(n: number) {
      state.statusCode = n;
      return reply;
    },
    header(k: string, v: string) {
      if (k.toLowerCase() === 'set-cookie') state.setCookies.push(v);
      else state.headers[k] = v;
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

/** Fastify double with a real in-memory stand-in for the Redis session store. */
function makeFastify() {
  const ctx: {
    get?: (request: any, reply: any) => Promise<unknown>;
    post?: (request: any, reply: any) => Promise<unknown>;
  } = {};
  const store = new Map<string, { value: unknown; ttl: number }>();
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
    sessionUtils: {
      setSession: vi.fn(async (id: string, value: unknown, ttl: number) => {
        store.set(id, { value, ttl });
      }),
      getSession: vi.fn(async (id: string) => store.get(id)?.value ?? null),
      deleteSession: vi.fn(async (id: string) => {
        store.delete(id);
      }),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx, store };
}

/** A representative authorize URL with every round-tripped parameter present. */
const AUTHORIZE_URL =
  '/oauth/authorize?response_type=code&client_id=app-123' +
  '&redirect_uri=https%3A%2F%2Fexample.com%2Fcb' +
  `&code_challenge=${'A'.repeat(43)}&code_challenge_method=S256` +
  '&scope=email+write%3Afoo' +
  '&state=%7B%22a%22%3A%22b%22%7D' +
  '&nonce=n-0123456789' +
  '&prompt=login&max_age=0' +
  '&resource=https%3A%2F%2Fapi.example.com%2Fmcp';

describe('pending-authorization stash', () => {
  beforeEach(() => vi.clearAllMocks());

  it('mints an unguessable 43-char base64url handle and never repeats it', async () => {
    const { fastify } = makeFastify();
    const handles = new Set<string>();
    for (let i = 0; i < 64; i++) {
      const h = await stashPendingAuthorization(fastify, AUTHORIZE_URL);
      expect(isPendingAuthorizationHandle(h)).toBe(true);
      expect(h).toMatch(/^[A-Za-z0-9_-]{43}$/);
      handles.add(h);
    }
    // 32 CSPRNG bytes: a collision in 64 draws would mean the source is broken.
    expect(handles.size).toBe(64);
  });

  it('stores under a namespaced key with the pending-authorization TTL', async () => {
    const { fastify, store } = makeFastify();
    const handle = await stashPendingAuthorization(fastify, AUTHORIZE_URL);
    const key = `pending-authz:${handle}`;
    expect(store.has(key)).toBe(true);
    expect(store.get(key)?.ttl).toBe(PENDING_AUTHORIZATION_TTL_MS / 1000);
    // Namespaced away from browser-session ids (UUIDs) in the same keyspace.
    expect(key.startsWith('pending-authz:')).toBe(true);
  });

  it('refuses to stash anything that is not a relative authorize URL', async () => {
    const { fastify } = makeFastify();
    for (const bad of [
      'https://evil.example/oauth/authorize?x=1',
      '//evil.example/oauth/authorize',
      '/ui/consent?client_id=app-123',
      '/oauth/authorizeX?a=1',
      'javascript:alert(1)',
      // `\` folds to `/` in the WHATWG URL parser, so this resolves to the host
      // `evil.example` in a browser exactly as `//evil.example` would.
      '/\\evil.example/oauth/authorize',
      // Path traversal past the authorize path.
      '/oauth/authorize/../../ui/logout',
    ]) {
      await expect(stashPendingAuthorization(fastify, bad)).rejects.toThrow(
        /relative \/oauth\/authorize URL/
      );
    }
  });

  it('accepts the trailing-slash form the router lets through, and canonicalises it', async () => {
    // `main.ts` sets `routerOptions.ignoreTrailingSlash: true`, so the handler
    // legitimately sees `request.url === '/oauth/authorize/?…'`. Rejecting that
    // 500'd the unauthenticated entry point; see authorize-routing.test.ts for
    // the end-to-end proof through a real router.
    const { fastify, store } = makeFastify();
    const handle = await stashPendingAuthorization(fastify, '/oauth/authorize/?client_id=app-123');
    expect(store.get(`pending-authz:${handle}`)?.value).toMatchObject({
      authorizeUrl: '/oauth/authorize?client_id=app-123',
    });
    expect(await consumePendingAuthorization(fastify, handle)).toBe(
      '/oauth/authorize?client_id=app-123'
    );
  });

  it('rejects an oversized authorize URL with a 400 instead of writing it to Redis', async () => {
    // The stash is written BEFORE the user authenticates, into the Redis that
    // also holds live browser sessions, and lives for the full TTL. It must
    // never be an unbounded pre-auth write primitive — not even if a schema
    // `max()` is dropped later.
    const { fastify } = makeFastify();
    const oversized = `/oauth/authorize?state=${'x'.repeat(PENDING_AUTHORIZATION_MAX_URL_BYTES)}`;

    await expect(stashPendingAuthorization(fastify, oversized)).rejects.toThrow(/too large/);
    expect(fastify.sessionUtils.setSession as unknown as Mock).not.toHaveBeenCalled();

    const { reply, state } = createReply();
    await expect(
      redirectToLoginWithPendingAuthorization(fastify, reply, oversized)
    ).rejects.toThrow(/too large/);
    expect(state.redirected).toBeUndefined();
  });

  it('is single-use: the second consume returns null', async () => {
    const { fastify } = makeFastify();
    const handle = await stashPendingAuthorization(fastify, AUTHORIZE_URL);
    expect(await consumePendingAuthorization(fastify, handle)).toBe(AUTHORIZE_URL);
    expect(await consumePendingAuthorization(fastify, handle)).toBeNull();
  });

  it('returns null for an unknown/expired handle without throwing', async () => {
    const { fastify } = makeFastify();
    // Well-formed but never minted — indistinguishable from a TTL expiry, since
    // Redis simply has no key either way.
    expect(await consumePendingAuthorization(fastify, 'B'.repeat(43))).toBeNull();
  });

  it('rejects a malformed handle before touching Redis', async () => {
    const { fastify } = makeFastify();
    for (const bad of ['', 'short', '../../etc/passwd', 'A'.repeat(44), null, undefined, 42]) {
      expect(await consumePendingAuthorization(fastify, bad)).toBeNull();
    }
    expect(fastify.sessionUtils.getSession as unknown as Mock).not.toHaveBeenCalled();
  });

  it('refuses a poisoned record whose stored URL is not our authorize path', async () => {
    const { fastify, store } = makeFastify();
    const handle = 'C'.repeat(43);
    store.set(`pending-authz:${handle}`, {
      value: { authorizeUrl: 'https://evil.example/steal', createdAt: Date.now() },
      ttl: 600,
    });
    expect(await consumePendingAuthorization(fastify, handle)).toBeNull();
    // Consumed anyway, so a poisoned entry cannot be probed repeatedly.
    expect(store.has(`pending-authz:${handle}`)).toBe(false);
  });
});

/**
 * Redis is the FIRST server-side dependency the unauthenticated login bounce
 * has ever had: before the stash landed, `GET /oauth/authorize` with no cookie
 * did zero Redis I/O (`resolveBrowserSession` returns null without a lookup
 * when the cookie is absent) and the rate limiter fails open. A failover
 * therefore must not convert a 302-to-login into a 500 at the authorization
 * endpoint.
 */
describe('pending-authorization store outage', () => {
  beforeEach(() => vi.clearAllMocks());

  it('falls back to an inline return_to when the stash write fails', async () => {
    const { fastify } = makeFastify();
    (fastify.sessionUtils.setSession as unknown as Mock).mockRejectedValue(
      new Error('ECONNREFUSED redis')
    );

    const { reply, state } = createReply();
    await redirectToLoginWithPendingAuthorization(fastify, reply, AUTHORIZE_URL);

    expect(state.statusCode).toBe(302);
    const returnTo = new URL(state.redirected as string, 'http://placeholder').searchParams.get(
      'return_to'
    );
    // Degraded, but still a correct and SAFE relative target: the pre-#316
    // behaviour, which the login page handles unchanged.
    expect(returnTo).toBe(AUTHORIZE_URL);
    expect(returnTo?.startsWith('//')).toBe(false);
    expect(fastify.log.warn as unknown as Mock).toHaveBeenCalled();
  });

  it('treats a failed stash read as an expired handle rather than throwing', async () => {
    const { fastify, ctx } = makeFastify();
    await resumeRoute(fastify);
    (fastify.sessionUtils.getSession as unknown as Mock).mockRejectedValue(
      new Error('ECONNREFUSED redis')
    );

    const { reply, state } = createReply();
    await ctx.get!({ params: { handle: 'F'.repeat(43) }, headers: {}, ip: '127.0.0.1' }, reply);

    expect(state.statusCode).toBe(400);
    expect(state.redirected).toBeUndefined();
    expect(String(state.body)).toContain('This sign-in request has expired');
  });
});

describe('GET /ui/resume/:handle', () => {
  beforeEach(() => vi.clearAllMocks());

  it('redirects to the stashed authorize URL with every parameter byte-for-byte', async () => {
    const { fastify, ctx } = makeFastify();
    await resumeRoute(fastify);
    const handle = await stashPendingAuthorization(fastify, AUTHORIZE_URL);

    const { reply, state } = createReply();
    await ctx.get!({ params: { handle }, headers: {}, ip: '127.0.0.1' }, reply);

    expect(state.statusCode).toBe(302);
    expect(state.redirected).toBe(AUTHORIZE_URL);
    expect(state.headers['Cache-Control']).toBe('no-store');

    // PKCE, scope, state, nonce and the ADR-007 step-up params all survive.
    const resumed = new URL(state.redirected as string, 'http://placeholder');
    const original = new URL(AUTHORIZE_URL, 'http://placeholder');
    for (const key of [
      'response_type',
      'client_id',
      'redirect_uri',
      'code_challenge',
      'code_challenge_method',
      'scope',
      'state',
      'nonce',
      'prompt',
      'max_age',
    ]) {
      expect(resumed.searchParams.get(key)).toBe(original.searchParams.get(key));
    }
    // RFC 8707 resource indicators are multi-valued; compare the whole list.
    expect(resumed.searchParams.getAll('resource')).toEqual(
      original.searchParams.getAll('resource')
    );
  });

  it('renders a 400 "expired" page for a replayed handle, and never redirects', async () => {
    const { fastify, ctx } = makeFastify();
    await resumeRoute(fastify);
    const handle = await stashPendingAuthorization(fastify, AUTHORIZE_URL);

    const first = createReply();
    await ctx.get!({ params: { handle }, headers: {}, ip: '127.0.0.1' }, first.reply);
    expect(first.state.redirected).toBe(AUTHORIZE_URL);

    const second = createReply();
    await ctx.get!({ params: { handle }, headers: {}, ip: '127.0.0.1' }, second.reply);
    expect(second.state.redirected).toBeUndefined();
    expect(second.state.statusCode).toBe(400);
    expect(String(second.state.body)).toContain('This sign-in request has expired');
    expect(second.state.headers['Cache-Control']).toBe('no-store');
  });

  it('degrades identically for missing, expired and malformed handles', async () => {
    const { fastify, ctx } = makeFastify();
    await resumeRoute(fastify);

    const bodies: string[] = [];
    for (const handle of ['D'.repeat(43), 'not-a-handle', '']) {
      const { reply, state } = createReply();
      await ctx.get!({ params: { handle }, headers: {}, ip: '127.0.0.1' }, reply);
      expect(state.statusCode).toBe(400);
      expect(state.redirected).toBeUndefined();
      bodies.push(String(state.body));
    }
    // Byte-identical responses: nothing distinguishes "never existed" from
    // "expired" from "already used", so handles cannot be probed.
    expect(new Set(bodies).size).toBe(1);
  });

  it('never redirects to an absolute URL held in a poisoned record', async () => {
    const { fastify, ctx, store } = makeFastify();
    await resumeRoute(fastify);
    const handle = 'E'.repeat(43);
    store.set(`pending-authz:${handle}`, {
      value: { authorizeUrl: '//evil.example/oauth/authorize', createdAt: Date.now() },
      ttl: 600,
    });

    const { reply, state } = createReply();
    await ctx.get!({ params: { handle }, headers: {}, ip: '127.0.0.1' }, reply);

    expect(state.redirected).toBeUndefined();
    expect(state.statusCode).toBe(400);
  });
});

describe('login round-trip', () => {
  beforeEach(() => vi.clearAllMocks());

  it('produces a return_to that isSafeReturnTo accepts unchanged', async () => {
    // The open-redirector guard in login.ts is NOT relaxed for this change; the
    // resume path simply satisfies it as-is (single leading `/`, never `//`).
    const stashFastify = makeFastify();
    const { reply: bounceReply, state: bounceState } = createReply();
    await redirectToLoginWithPendingAuthorization(stashFastify.fastify, bounceReply, AUTHORIZE_URL);

    const returnTo = new URL(
      bounceState.redirected as string,
      'http://placeholder'
    ).searchParams.get('return_to') as string;
    expect(returnTo.startsWith(RESUME_PATH_PREFIX)).toBe(true);
    expect(returnTo.startsWith('//')).toBe(false);

    // Render the login page with it and confirm the value survives into the
    // hidden field that the POST handler reads back.
    const loginFastify = makeFastify();
    (loginFastify.fastify as any).repositories = { auditLogs: { create: vi.fn() } };
    await loginRoute(loginFastify.fastify);
    const { reply, state } = createReply();
    await loginFastify.ctx.get!({ query: { return_to: returnTo }, headers: {} }, reply);
    expect(String(state.body)).toContain(`name="return_to" value="${returnTo}"`);
  });

  it('completes authorize → login → resume back to the identical authorize URL', async () => {
    const { fastify, ctx } = makeFastify();
    await resumeRoute(fastify);

    // 1. A route bounces the user to login with a handle.
    const bounce = createReply();
    await redirectToLoginWithPendingAuthorization(fastify, bounce.reply, AUTHORIZE_URL);
    const returnTo = new URL(
      bounce.state.redirected as string,
      'http://placeholder'
    ).searchParams.get('return_to') as string;

    // 2. login POST redirects to that path verbatim after a successful sign-in.
    const handle = returnTo.slice(RESUME_PATH_PREFIX.length);

    // 3. Resume hands back exactly what was parked.
    const { reply, state } = createReply();
    await ctx.get!({ params: { handle }, headers: {}, ip: '127.0.0.1' }, reply);
    expect(state.redirected).toBe(AUTHORIZE_URL);
  });
});
