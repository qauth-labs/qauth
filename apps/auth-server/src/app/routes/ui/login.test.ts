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
  registerLoginAttempt: vi.fn().mockResolvedValue({ locked: false }),
  recordSuccessfulLogin: vi.fn().mockResolvedValue(undefined),
  resetFailedAttempts: vi.fn().mockResolvedValue(undefined),
}));

import { env } from '../../../config/env';
import { hashEmail } from '../../helpers/auth-events';
import {
  recordSuccessfulLogin,
  registerLoginAttempt,
  resetFailedAttempts,
} from '../../helpers/failed-login';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import loginRoute from './login';

interface TestContext {
  get?: (request: any, reply: any) => Promise<unknown>;
  post?: (request: any, reply: any) => Promise<unknown>;
  /** The POST route's options, so a test can reach the form schema Fastify applies. */
  postOpts?: { schema: { body: { safeParse: (value: unknown) => { success: boolean } } } };
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
      post: (_url: string, opts: TestContext['postOpts'], handler: any) => {
        ctx.post = handler;
        ctx.postOpts = opts;
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
      hashPassword: vi.fn().mockResolvedValue('decoy-hash'),
    },
    providerRegistry: {
      resolve: vi.fn().mockReturnValue(createPasswordProvider()),
      has: vi.fn().mockReturnValue(true),
      register: vi.fn(),
    },
    sessionUtils: {
      setSession: vi.fn().mockResolvedValue(undefined),
    },
    // The per-user index of browser sessions that `/auth/logout` ends.
    redis: (() => {
      const chain = {
        sadd: vi.fn(() => chain),
        expire: vi.fn(() => chain),
        exec: vi.fn().mockResolvedValue([]),
      };
      return { chain, multi: vi.fn(() => chain) };
    })(),
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

  it('GET never renders caller-supplied text in the error banner (01VEX7C3)', async () => {
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);
    if (!ctx.get) throw new Error('Handler missing');

    const { reply, state } = createReply();
    await ctx.get(
      { query: { error: 'Call +1-800-555-0199 to reactivate.' }, headers: {}, ip: '127.0.0.1' },
      reply
    );

    expect(state.body as string).not.toContain('class="error"');
    expect(state.body as string).not.toContain('+1-800-555-0199');
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

    // The new session is recorded under its user, so `/auth/logout` can end it.
    const sessionId = (fastify.sessionUtils.setSession as unknown as Mock).mock.calls[0][0];
    const redis = (fastify as unknown as { redis: { chain: { sadd: Mock } } }).redis;
    expect(redis.chain.sadd).toHaveBeenCalledWith('user-browser-sessions:user-1', sessionId);
  });

  describe("POST shares the API login's failed-login lockout and email-verified gate", () => {
    const LOCKOUT_IDS = [`email:${hashEmail('user@example.com')}`, 'ip:127.0.0.1'];

    async function postLogin(options: { verifies: boolean; emailVerified?: boolean; ip?: string }) {
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
          ip: options.ip ?? '127.0.0.1',
        },
        reply
      );
      return { fastify, state };
    }

    beforeEach(() => {
      vi.mocked(registerLoginAttempt).mockClear().mockResolvedValue({ locked: false });
      vi.mocked(recordSuccessfulLogin).mockClear();
      vi.mocked(resetFailedAttempts).mockClear();
      (env as { REQUIRE_VERIFIED_ACCOUNT?: boolean }).REQUIRE_VERIFIED_ACCOUNT = false;
    });

    it('refuses a locked-out identifier (429) before any credential check', async () => {
      vi.mocked(registerLoginAttempt).mockResolvedValue({ locked: true, retryAfterSeconds: 120 });

      const { fastify, state } = await postLogin({ verifies: true });

      expect(registerLoginAttempt).toHaveBeenCalledWith(expect.anything(), LOCKOUT_IDS);
      expect(state.statusCode).toBe(429);
      expect(state.headers['Retry-After']).toBe('120');
      expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
      expect(fastify.sessionUtils.setSession).not.toHaveBeenCalled();
    });

    it('counts the attempt before the password is verified, with the API login identifiers', async () => {
      const { fastify, state } = await postLogin({ verifies: false });

      expect(state.statusCode).toBe(401);
      expect(registerLoginAttempt).toHaveBeenCalledWith(expect.anything(), LOCKOUT_IDS);
      // Counted on the way in, not after argon2 has returned, so concurrent
      // guesses cannot outrun the counter (ROIQJSAT); a failure leaves it counted.
      expect(vi.mocked(registerLoginAttempt).mock.invocationCallOrder[0]).toBeLessThan(
        (fastify.passwordHasher.verifyPassword as unknown as Mock).mock.invocationCallOrder[0]
      );
      expect(recordSuccessfulLogin).not.toHaveBeenCalled();
      expect(resetFailedAttempts).not.toHaveBeenCalled();
    });

    it('keys the ip: identifier on the /64 of an IPv6 client', async () => {
      await postLogin({ verifies: false, ip: '2001:db8:1:2:aaaa:bbbb:cccc:7' });

      expect(registerLoginAttempt).toHaveBeenCalledWith(expect.anything(), [
        LOCKOUT_IDS[0],
        'ip:2001:db8:1:2::',
      ]);
    });

    it('clears the failed-login state of the email on success, not of the source address', async () => {
      const attempt = { locked: false, counted: LOCKOUT_IDS, armed: [] };
      vi.mocked(registerLoginAttempt).mockResolvedValue(attempt);

      const { state } = await postLogin({ verifies: true });

      expect(state.statusCode).toBe(302);
      // Anyone can register an account: its login must not wipe the failures
      // counted against the address it comes from (GPU4YL6X).
      expect(recordSuccessfulLogin).toHaveBeenCalledExactlyOnceWith(expect.anything(), attempt, [
        LOCKOUT_IDS[0],
      ]);
      expect(resetFailedAttempts).not.toHaveBeenCalled();
    });

    it('refuses an unverified credential exactly as a wrong password when REQUIRE_VERIFIED_ACCOUNT is on (ANT-2026-SPEMY9GU)', async () => {
      (env as { REQUIRE_VERIFIED_ACCOUNT?: boolean }).REQUIRE_VERIFIED_ACCOUNT = true;

      /** What the browser sees, with the per-run CSRF token masked. */
      const seen = (state: Awaited<ReturnType<typeof postLogin>>['state']) => ({
        statusCode: state.statusCode,
        headers: state.headers,
        setCookies: state.setCookies,
        redirected: state.redirected,
        body: String(state.body).replace(/name="csrf_token" value="[^"]*"/, 'CSRF'),
      });
      /** Whether the timing floor ran before the audit write, as on every refusal. */
      const floorFirst = (fastify: FastifyInstance) =>
        vi.mocked(ensureMinimumResponseTime).mock.invocationCallOrder.at(-1)! <
        (fastify.repositories.auditLogs.create as unknown as Mock).mock.invocationCallOrder.at(-1)!;

      // A just-registered FREE address, signed in with the password its
      // registrant chose: right password, unverified account.
      const fresh = await postLogin({ verifies: true, emailVerified: false });
      const freshFloorFirst = floorFirst(fresh.fastify);
      // The same attempt on an address that was already registered: wrong
      // password for the owner's verified account.
      const taken = await postLogin({ verifies: false, emailVerified: true });

      expect(seen(fresh.state)).toEqual(seen(taken.state));
      expect(fresh.state.statusCode).toBe(401);
      expect(String(fresh.state.body)).toContain(
        'If you have just registered, confirm your email address first'
      );
      expect(freshFloorFirst).toBe(true);
      expect(floorFirst(taken.fastify)).toBe(true);
      expect(fresh.fastify.sessionUtils.setSession).not.toHaveBeenCalled();
      // Stays counted as a failed attempt.
      expect(registerLoginAttempt).toHaveBeenCalledWith(expect.anything(), LOCKOUT_IDS);
      expect(recordSuccessfulLogin).not.toHaveBeenCalled();
      expect(resetFailedAttempts).not.toHaveBeenCalled();
      // The reason is kept where only operators read it.
      expect(fresh.fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-1',
          metadata: { email: 'user@example.com', reason: 'email_not_verified' },
        })
      );
    });

    it('still signs in an unverified credential when an operator turns REQUIRE_VERIFIED_ACCOUNT off', async () => {
      const { fastify, state } = await postLogin({ verifies: true, emailVerified: false });

      expect(state.statusCode).toBe(302);
      expect(fastify.sessionUtils.setSession).toHaveBeenCalledOnce();
    });
  });

  it('POST spends one decoy argon2 verification on an unknown email, like a wrong password', async () => {
    // CXMKR1RL: a miss that skips argon2 answers on time behind a backlog of
    // argon2 jobs while a hit waits in it, so latency told them apart.
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);
    if (!ctx.get || !ctx.post) throw new Error('Handlers missing');

    const getReply = createReply();
    await ctx.get({ query: {}, headers: {}, ip: '127.0.0.1' }, getReply.reply);
    const cookieValue = csrfCookieValue(getReply.state.setCookies);
    const rawToken = cookieValue.split('.')[0];

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(undefined);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(false);

    const { reply, state } = createReply();
    await ctx.post(
      {
        body: { email: 'nobody@example.com', password: 'guess', csrf_token: rawToken },
        headers: { cookie: `__Host-qauth_login_csrf=${cookieValue}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(401);
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledExactlyOnceWith(
      'decoy-hash',
      'guess'
    );
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

describe('UI /ui/login — the email field is bounded', () => {
  // A refused sign-in writes the address to `audit_logs`; with no bound, one
  // anonymous request stored a 1 MiB row. RFC 5321 caps an address at 254.
  it('the form schema refuses an address longer than 254 characters', async () => {
    const { fastify, ctx } = makeFastify();
    await loginRoute(fastify);
    const schema = ctx.postOpts?.schema.body;
    if (!schema) throw new Error('POST schema missing');

    const atBound = `${'a'.repeat(254 - '@example.com'.length)}@example.com`;
    const form = { password: 'pw', csrf_token: 'csrf' };
    expect(schema.safeParse({ ...form, email: atBound }).success).toBe(true);
    expect(schema.safeParse({ ...form, email: `a${atBound}` }).success).toBe(false);
  });
});
