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

// Failed-login throttling has its own tests (helpers/failed-login.test.ts);
// here it is a seam, so these tests assert the route wires it in.
vi.mock('../../helpers/failed-login', () => ({
  checkLockout: vi.fn().mockResolvedValue({ locked: false }),
  recordFailedAttempt: vi.fn().mockResolvedValue({ lockedOut: false }),
  resetFailedAttempts: vi.fn().mockResolvedValue(undefined),
}));

import { env } from '../../../config/env';
import { hashEmail } from '../../helpers/auth-events';
import { checkLockout, recordFailedAttempt, resetFailedAttempts } from '../../helpers/failed-login';
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

    // #237/#240: a password credential is `assuranceLevel: 'low'` (ADR-003), so
    // the session records NO assurance at all. This is the ORIGIN of the
    // invariant that password-authenticated ID tokens carry no `acr` claim:
    // /oauth/authorize copies this field onto the authorization code, and
    // /oauth/token renders `acr` only from a level that is present.
    const sessionPayload = (fastify.sessionUtils.setSession as unknown as Mock).mock
      .calls[0][1] as Record<string, unknown>;
    expect('assuranceLevel' in sessionPayload).toBe(false);
  });

  describe("POST shares the API login's failed-login lockout and email-verified gate", () => {
    const LOCKOUT_IDS = [`email:${hashEmail('user@example.com')}`, 'ip:127.0.0.1'];

    async function postLogin(options: { verifies: boolean; emailVerified?: boolean }) {
      const { fastify, ctx } = makeFastify();
      await loginRoute(fastify);
      const getReply = createReply();
      await ctx.get!({ query: {}, headers: {}, ip: '127.0.0.1' }, getReply.reply);
      const cookieValue = csrfCookieValue(getReply.state.setCookies);
      const rawToken = cookieValue.split('.')[0];

      (
        fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
      ).mockResolvedValue(
        credentialFixture({
          credentialData: { password_hash: 'hash', email_verified: options.emailVerified ?? true },
        })
      );
      (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
        id: 'user-1',
        email: 'user@example.com',
        passwordHash: 'hash',
        enabled: true,
      });
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(
        options.verifies
      );

      const { reply, state } = createReply();
      await ctx.post!(
        {
          body: { email: 'User@Example.com', password: 'pw', csrf_token: rawToken },
          headers: { cookie: `__Host-qauth_login_csrf=${cookieValue}` },
          ip: '127.0.0.1',
        },
        reply
      );
      return { fastify, state };
    }

    beforeEach(() => {
      vi.mocked(checkLockout).mockClear().mockResolvedValue({ locked: false });
      vi.mocked(recordFailedAttempt).mockClear();
      vi.mocked(resetFailedAttempts).mockClear();
      (env as { REQUIRE_EMAIL_VERIFIED?: boolean }).REQUIRE_EMAIL_VERIFIED = false;
    });

    it('refuses a locked-out identifier (429) before any credential check', async () => {
      vi.mocked(checkLockout).mockResolvedValue({ locked: true, retryAfterSeconds: 120 });

      const { fastify, state } = await postLogin({ verifies: true });

      expect(checkLockout).toHaveBeenCalledWith(undefined, LOCKOUT_IDS);
      expect(state.statusCode).toBe(429);
      expect(state.headers['Retry-After']).toBe('120');
      expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
      expect(fastify.sessionUtils.setSession).not.toHaveBeenCalled();
    });

    it('records a failed attempt on a wrong password, with the API login identifiers', async () => {
      const { state } = await postLogin({ verifies: false });

      expect(state.statusCode).toBe(401);
      expect(recordFailedAttempt).toHaveBeenCalledWith(undefined, LOCKOUT_IDS);
      expect(resetFailedAttempts).not.toHaveBeenCalled();
    });

    it('clears failed-login state on success', async () => {
      const { state } = await postLogin({ verifies: true });

      expect(state.statusCode).toBe(302);
      expect(resetFailedAttempts).toHaveBeenCalledWith(undefined, LOCKOUT_IDS);
      expect(recordFailedAttempt).not.toHaveBeenCalled();
    });

    it('refuses an unverified credential (403, no session) when REQUIRE_EMAIL_VERIFIED is on', async () => {
      (env as { REQUIRE_EMAIL_VERIFIED?: boolean }).REQUIRE_EMAIL_VERIFIED = true;

      const { fastify, state } = await postLogin({ verifies: true, emailVerified: false });

      expect(state.statusCode).toBe(403);
      expect(fastify.sessionUtils.setSession).not.toHaveBeenCalled();
      expect(recordFailedAttempt).toHaveBeenCalledWith(undefined, LOCKOUT_IDS);
    });

    it('still signs in an unverified credential when REQUIRE_EMAIL_VERIFIED is off (default)', async () => {
      const { fastify, state } = await postLogin({ verifies: true, emailVerified: false });

      expect(state.statusCode).toBe(302);
      expect(fastify.sessionUtils.setSession).toHaveBeenCalledOnce();
    });
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

/**
 * `return_to` open-redirect guard (`isSafeReturnTo`).
 *
 * The value reaches `reply.redirect(returnTo, 302)` after a successful
 * sign-in, so anything the guard accepts is a place this server will send a
 * freshly-authenticated user. It is deliberately allowlist-shaped — "a single
 * leading `/`" — and everything it rejects falls back to `/`.
 */
describe('UI /ui/login — return_to open-redirect guard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const UNSAFE = [
    'https://evil.example/steal',
    '//evil.example/steal',
    // `\` folds to `/` for special schemes in the WHATWG URL parser, which is
    // the algorithm browsers use to resolve a `Location` header. So
    // `Location: /\evil.example` navigates to `https://evil.example` — the same
    // cross-origin bounce as `//evil.example`, spelled differently.
    '/\\evil.example/steal',
    // The URL parser DISCARDS tab, LF and CR before it parses, so each of these
    // reads as a single leading `/` here and is protocol-relative by the time a
    // browser resolves it — the same bounce again, spelled a third way. See
    // `helpers/return-to.test.ts`.
    '/\t/evil.example/steal',
    '/\n/evil.example/steal',
    '/\r/evil.example/steal',
    '/\t\\evil.example/steal',
    'javascript:alert(1)',
    'relative/path',
    '',
  ];

  it.each(UNSAFE)('GET falls back to "/" for return_to=%j', async (returnTo) => {
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);

    const { reply, state } = createReply();
    await ctx.get!({ query: { return_to: returnTo }, headers: {}, ip: '127.0.0.1' }, reply);

    expect(state.body as string).toContain('name="return_to" value="/"');
  });

  it.each(UNSAFE)('POST redirects to "/" rather than %j', async (returnTo) => {
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);

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
        body: {
          email: 'user@example.com',
          password: 'correct',
          csrf_token: rawToken,
          return_to: returnTo,
        },
        headers: { cookie: `__Host-qauth_login_csrf=${cookieValue}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(302);
    expect(state.redirected).toBe('/');
  });

  it('keeps accepting a deep multi-segment relative path', async () => {
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);

    const returnTo = `/ui/resume/${'A'.repeat(43)}`;
    const { reply, state } = createReply();
    await ctx.get!({ query: { return_to: returnTo }, headers: {}, ip: '127.0.0.1' }, reply);

    expect(state.body as string).toContain(`name="return_to" value="${returnTo}"`);
  });
});
