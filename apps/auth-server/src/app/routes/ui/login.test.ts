import { createPasswordProvider } from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    DEFAULT_REALM_NAME: 'master',
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
    LOGIN_RATE_LIMIT: 5,
    LOGIN_RATE_WINDOW: 900,
  },
}));

import loginRoute from './login';

interface TestContext {
  get?: (request: any, reply: any) => Promise<unknown>;
  post?: (request: any, reply: any) => Promise<unknown>;
}

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
      // Mirror Fastify: Set-Cookie accumulates rather than overwriting.
      if (k.toLowerCase() === 'set-cookie') {
        state.setCookies.push(v);
      } else {
        state.headers[k] = v;
      }
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
      users: {
        findById: vi.fn(),
        updateLastLogin: vi.fn().mockResolvedValue(undefined),
      },
      userCredentials: {
        findByRealmProviderSub: vi.fn(),
        findById: vi.fn(),
      },
      auditLogs: {
        create: vi.fn().mockResolvedValue(undefined),
      },
    },
    passwordHasher: {
      verifyPassword: vi.fn(),
    },
    providerRegistry: {
      resolve: vi.fn().mockReturnValue(createPasswordProvider()),
      has: vi.fn().mockReturnValue(true),
      register: vi.fn(),
    },
    sessionUtils: {
      setSession: vi.fn().mockResolvedValue(undefined),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

/** The #228 credential-row fixture the login lookup returns. */
function credentialFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 'cred-1',
    userId: 'user-1',
    realmId: 'realm-1',
    providerType: 'password',
    externalSub: 'user@example.com',
    credentialData: { password_hash: 'hash', email_verified: true },
    ...overrides,
  };
}

/** Extract the raw login-CSRF token from the Set-Cookie header rendered on GET. */
function csrfCookieValue(setCookies: string[]): string {
  const cookie = setCookies.find((c) => c.startsWith('__Host-qauth_login_csrf='));
  if (!cookie) throw new Error('login CSRF cookie was not set');
  return cookie.split('=')[1].split(';')[0];
}

describe('UI /ui/login — CSRF defence', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('GET sets a signed login-CSRF cookie and embeds the token in the form', async () => {
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);

    const { reply, state } = createReply();
    await ctx.get!({ query: {}, headers: {}, ip: '127.0.0.1' }, reply);

    const cookieValue = csrfCookieValue(state.setCookies);
    // `<token>.<hmac>` — the raw token is the part before the separator.
    const rawToken = cookieValue.split('.')[0];
    expect(rawToken.length).toBeGreaterThan(0);
    expect(state.body as string).toContain('name="csrf_token"');
    expect(state.body as string).toContain(`value="${rawToken}"`);
  });

  it('POST rejects (403) when the CSRF token is missing/invalid — no credential check', async () => {
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: { email: 'user@example.com', password: 'pw', csrf_token: 'forged' },
        // No valid CSRF cookie present.
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(403);
    // The DB / password path must never be reached on a CSRF failure.
    expect(fastify.repositories.userCredentials.findByRealmProviderSub).not.toHaveBeenCalled();
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
    const events = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls.map(
      (c) => (c[0] as { event: string }).event
    );
    expect(events).toContain('ui.login.csrf_failure');
  });

  it('POST succeeds when the submitted token matches the signed cookie', async () => {
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);

    // First GET to obtain a valid signed cookie + matching token.
    const getReply = createReply();
    await ctx.get!({ query: {}, headers: {}, ip: '127.0.0.1' }, getReply.reply);
    const cookieValue = csrfCookieValue(getReply.state.setCookies);
    const rawToken = cookieValue.split('.')[0];

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      passwordHash: 'hash',
      enabled: true,
    });
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: { email: 'user@example.com', password: 'correct', csrf_token: rawToken },
        headers: { cookie: `__Host-qauth_login_csrf=${cookieValue}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toBe('/');
    expect(state.statusCode).toBe(302);
    expect(fastify.sessionUtils.setSession).toHaveBeenCalledOnce();
    // The login-CSRF cookie is burned on success (Max-Age=0).
    const cleared = state.setCookies.find(
      (c) => c.startsWith('__Host-qauth_login_csrf=') && c.includes('Max-Age=0')
    );
    expect(cleared).toBeDefined();
  });

  it('POST rejects a disabled user (401 re-render) even with valid credentials', async () => {
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);

    const getReply = createReply();
    await ctx.get!({ query: {}, headers: {}, ip: '127.0.0.1' }, getReply.reply);
    const cookieValue = csrfCookieValue(getReply.state.setCookies);
    const rawToken = cookieValue.split('.')[0];

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    // The enabled gate still reads the users row (#228 keeps it there).
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      passwordHash: 'hash',
      enabled: false,
    });
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: { email: 'user@example.com', password: 'correct', csrf_token: rawToken },
        headers: { cookie: `__Host-qauth_login_csrf=${cookieValue}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(401);
    expect(fastify.sessionUtils.setSession).not.toHaveBeenCalled();
  });

  it('POST with a tampered token whose signature does not validate is rejected (403)', async () => {
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);

    // Obtain a valid cookie, then submit a DIFFERENT token value that the cookie
    // signature does not cover.
    const getReply = createReply();
    await ctx.get!({ query: {}, headers: {}, ip: '127.0.0.1' }, getReply.reply);
    const cookieValue = csrfCookieValue(getReply.state.setCookies);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: { email: 'user@example.com', password: 'pw', csrf_token: 'a-different-token' },
        headers: { cookie: `__Host-qauth_login_csrf=${cookieValue}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(403);
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });
});
