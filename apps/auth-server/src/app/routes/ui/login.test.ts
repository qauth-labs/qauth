import { createPasswordProvider } from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

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
import { createBrowserSessionFixture, sessionCookie } from '../../../testing/browser-sessions';
import { testRealm } from '../../../testing/request-realm';
import { hashEmail } from '../../helpers/auth-events';
import {
  recordSuccessfulLogin,
  registerLoginAttempt,
  resetFailedAttempts,
} from '../../helpers/failed-login';
import type { RealmRow } from '../../helpers/request-realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { emitUserEvent } from '../../helpers/user-events';
import loginRoute from './login';

const emitUserEventMock = vi.mocked(emitUserEvent);

/** The realm the realm resolver (#486) decorated every request with. */
const REALM = testRealm({ id: 'realm-1' });

beforeEach(() => {
  emitUserEventMock.mockClear();
});

interface TestContext {
  get?: (request: any, reply: any) => Promise<unknown>;
  post?: (request: any, reply: any) => Promise<unknown>;
  /** The POST route's options, so a test can reach the form schema Fastify applies. */
  postOpts?: { schema: { body: { safeParse: (value: unknown) => { success: boolean } } } };
}

/** A captured route handler, called with a plain-object request. */
type RouteHandler = NonNullable<TestContext['post']>;

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

/**
 * The realm resolver's decoration (#486): a request reaches its handler with
 * the realm of its host. A request that names its own realm keeps it.
 */
function withRealm(handler: RouteHandler): RouteHandler {
  return (request, reply) => {
    request.realm ??= REALM;
    return handler(request, reply);
  };
}

function makeFastify() {
  const ctx: TestContext = {};
  // The session service (#488) and the Redis that holds the session's side
  // record.
  const sessions = createBrowserSessionFixture();
  const fastify: any = {
    withTypeProvider: () => ({
      get: (_url: string, _opts: unknown, handler: any) => {
        ctx.get = withRealm(handler);
        return fastify;
      },
      post: (_url: string, opts: TestContext['postOpts'], handler: any) => {
        ctx.post = withRealm(handler);
        ctx.postOpts = opts;
        return fastify;
      },
    }),
    repositories: {
      users: {
        findById: vi.fn(),
        updateLastLogin: vi.fn().mockResolvedValue(undefined),
      },
      userCredentials: {
        findByRealmProviderSub: vi.fn(),
        findById: vi.fn(),
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
    sessionService: sessions.service,
    signer: sessions.signer,
    redis: sessions.redis,
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx, sessions };
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

/** The `name=value` pair of the session cookie the reply set, if it set one. */
function sessionCookieSet(setCookies: string[]): string | undefined {
  return setCookies.find((c) => c.startsWith('__Host-qauth_session='))?.split(';')[0];
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
    // `<kid>.<token>.<mac>` (#493) — the raw token is the middle part.
    const rawToken = cookieValue.split('.')[1];
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
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:request.csrf_rejected:v1-rc.0',
      { form: 'sign_in' },
      { actor: 'user' }
    );
  });

  it('POST succeeds when the submitted token matches the signed cookie', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await loginRoute(fastify);

    // First GET to obtain a valid signed cookie + matching token.
    const getReply = createReply();
    await ctx.get!({ query: {}, headers: {}, ip: '127.0.0.1' }, getReply.reply);
    const cookieValue = csrfCookieValue(getReply.state.setCookies);
    const rawToken = cookieValue.split('.')[1];

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

    const before = Date.now();
    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: { email: 'User@Example.com', password: 'correct', csrf_token: rawToken },
        headers: {
          cookie: `__Host-qauth_login_csrf=${cookieValue}`,
          'user-agent': 'TestBrowser/1.0',
        },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toBe('/');
    expect(state.statusCode).toBe(302);
    // The login-CSRF cookie is burned on success (Max-Age=0).
    const cleared = state.setCookies.find(
      (c) => c.startsWith('__Host-qauth_login_csrf=') && c.includes('Max-Age=0')
    );
    expect(cleared).toBeDefined();

    // One new session through the session service (#488), in the user's
    // realm, with the request's address and User-Agent.
    expect(sessions.service.create).toHaveBeenCalledOnce();
    const input = sessions.service.create.mock.calls[0][0];
    expect(input).toEqual({
      realmId: 'realm-1',
      userId: 'user-1',
      authTime: expect.any(Number),
      // #237/#240: a password credential is `assuranceLevel: 'low'` (ADR-003),
      // so the session records NO assurance level. This is the ORIGIN of the
      // invariant that password-authenticated ID tokens carry no `acr` claim:
      // /oauth/authorize copies this field onto the authorization code, and
      // /oauth/token renders `acr` only from a level that is present.
      assuranceLevel: null,
      ipAddress: '127.0.0.1',
      userAgent: 'TestBrowser/1.0',
      issuedAt: expect.any(Number),
    });
    expect(input.authTime).toBeGreaterThanOrEqual(before);
    expect(input.authTime).toBeLessThanOrEqual(Date.now());
    const session = await sessions.service.create.mock.results[0].value;

    // #230: the consent screen shows the credential's external_sub, not the
    // address as typed. It lives in the side record, not in the session.
    await expect(sessions.sideRecord(session)).resolves.toMatchObject({
      identifier: 'user@example.com',
    });
    // The cookie names the new session.
    expect(sessionCookieSet(state.setCookies)).toBe(await sessionCookie(fastify, session));

    // The sign-in is recorded for its user, without the session id or the
    // return path.
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:user.signed_in:v1-rc.0',
      { method: 'password' },
      { realmId: 'realm-1', userId: 'user-1', actor: 'user' }
    );
  });

  // A disablement that commits while the account is being read is not seen
  // by the read: the session counts from before the read (#748).
  it('POST counts the new session from the time taken before the account is read (#748)', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await loginRoute(fastify);
    const getReply = createReply();
    await ctx.get!({ query: {}, headers: {}, ip: '127.0.0.1' }, getReply.reply);
    const cookieValue = csrfCookieValue(getReply.state.setCookies);
    const rawToken = cookieValue.split('.')[1];
    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      const beforeRead = Date.now();
      (fastify.repositories.users.findById as unknown as Mock).mockImplementation(async () => {
        // The read waits, on the disabling transaction's row lock say, while
        // the clock moves on.
        vi.setSystemTime(Date.now() + 5_000);
        return { id: 'user-1', email: 'user@example.com', passwordHash: 'hash', enabled: true };
      });
      const { reply, state } = createReply();
      await ctx.post!(
        {
          body: { email: 'user@example.com', password: 'correct', csrf_token: rawToken },
          headers: { cookie: `__Host-qauth_login_csrf=${cookieValue}` },
          ip: '127.0.0.1',
        },
        reply
      );

      expect(state.statusCode).toBe(302);
      expect(sessions.service.create).toHaveBeenCalledOnce();
      expect(sessions.service.create.mock.calls[0][0].issuedAt).toBe(beforeRead);
    } finally {
      vi.useRealTimers();
    }
  });

  it('POST signs in to a NEW session even when the browser already carries one (session fixation)', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await loginRoute(fastify);
    if (!ctx.get || !ctx.post) throw new Error('Handlers missing');

    const getReply = createReply();
    await ctx.get({ query: {}, headers: {}, ip: '127.0.0.1' }, getReply.reply);
    const cookieValue = csrfCookieValue(getReply.state.setCookies);
    const rawToken = cookieValue.split('.')[1];

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

    // A live session cookie the browser already holds: planted by an
    // attacker, or left from an earlier sign-in.
    const planted = await sessions.signIn({
      sid: 'planted-sid',
      realmId: REALM.id,
      userId: 'user-1',
    });

    const { reply, state } = createReply();
    await ctx.post(
      {
        body: { email: 'user@example.com', password: 'correct', csrf_token: rawToken },
        headers: { cookie: `__Host-qauth_login_csrf=${cookieValue}; ${planted.cookie}` },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.statusCode).toBe(302);
    expect(sessions.service.create).toHaveBeenCalledOnce();
    const session = await sessions.service.create.mock.results[0].value;
    expect(session.sid).not.toBe('planted-sid');
    expect(sessionCookieSet(state.setCookies)).toBe(await sessionCookie(fastify, session));
  });

  describe("POST shares the API login's failed-login lockout and email-verified gate", () => {
    const LOCKOUT_IDS = [`email:${hashEmail('user@example.com')}`, 'ip:127.0.0.1'];

    async function postLogin(options: {
      verifies: boolean;
      emailVerified?: boolean;
      ip?: string;
      /** The realm of the host the request named; {@link REALM} when absent. */
      realm?: RealmRow;
    }) {
      const { fastify, ctx, sessions } = makeFastify();
      await loginRoute(fastify);
      const getReply = createReply();
      // The login page of the same realm: its CSRF cookie is bound to it (#493).
      await ctx.get!(
        { query: {}, headers: {}, ip: '127.0.0.1', realm: options.realm },
        getReply.reply
      );
      const cookieValue = csrfCookieValue(getReply.state.setCookies);
      const rawToken = cookieValue.split('.')[1];

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
          realm: options.realm,
        },
        reply
      );
      return { fastify, state, sessions };
    }

    beforeEach(() => {
      vi.mocked(registerLoginAttempt).mockClear().mockResolvedValue({ locked: false });
      vi.mocked(recordSuccessfulLogin).mockClear();
      vi.mocked(resetFailedAttempts).mockClear();
      (env as { REQUIRE_VERIFIED_ACCOUNT?: boolean }).REQUIRE_VERIFIED_ACCOUNT = false;
    });

    it('refuses a locked-out identifier (429) before any credential check', async () => {
      vi.mocked(registerLoginAttempt).mockResolvedValue({ locked: true, retryAfterSeconds: 120 });

      const { fastify, state, sessions } = await postLogin({ verifies: true });

      expect(registerLoginAttempt).toHaveBeenCalledWith(expect.anything(), REALM.id, LOCKOUT_IDS);
      expect(state.statusCode).toBe(429);
      expect(state.headers['Retry-After']).toBe('120');
      expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
      expect(sessions.service.create).not.toHaveBeenCalled();
      // No subject and never the typed address: a locked-out attempt names no user.
      expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
        expect.anything(),
        'urn:qauth:event:user.sign_in_failed:v1-rc.0',
        { method: 'password', reason: 'locked_out' },
        { realmId: REALM.id, actor: 'user' }
      );
    });

    it('counts the attempt before the password is verified, with the API login identifiers', async () => {
      const { fastify, state } = await postLogin({ verifies: false });

      expect(state.statusCode).toBe(401);
      expect(registerLoginAttempt).toHaveBeenCalledWith(expect.anything(), REALM.id, LOCKOUT_IDS);
      // Counted on the way in, not after argon2 has returned, so concurrent
      // guesses cannot outrun the counter (ROIQJSAT); a failure leaves it counted.
      expect(vi.mocked(registerLoginAttempt).mock.invocationCallOrder[0]).toBeLessThan(
        (fastify.passwordHasher.verifyPassword as unknown as Mock).mock.invocationCallOrder[0]
      );
      expect(recordSuccessfulLogin).not.toHaveBeenCalled();
      expect(resetFailedAttempts).not.toHaveBeenCalled();
    });

    it("looks the account up and counts the attempt in the request's realm (#487)", async () => {
      const { fastify } = await postLogin({ verifies: false, realm: testRealm({ id: 'realm-2' }) });

      expect(fastify.repositories.userCredentials.findByRealmProviderSub).toHaveBeenCalledWith(
        'realm-2',
        'password',
        'user@example.com'
      );
      expect(registerLoginAttempt).toHaveBeenCalledWith(expect.anything(), 'realm-2', LOCKOUT_IDS);
    });

    it('keys the ip: identifier on the /64 of an IPv6 client', async () => {
      await postLogin({ verifies: false, ip: '2001:db8:1:2:aaaa:bbbb:cccc:7' });

      expect(registerLoginAttempt).toHaveBeenCalledWith(expect.anything(), REALM.id, [
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
      expect(recordSuccessfulLogin).toHaveBeenCalledExactlyOnceWith(
        expect.anything(),
        REALM.id,
        attempt,
        [LOCKOUT_IDS[0]]
      );
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
      /** Whether the timing floor ran before the event, as on every refusal. */
      const floorFirst = () =>
        vi.mocked(ensureMinimumResponseTime).mock.invocationCallOrder.at(-1)! <
        emitUserEventMock.mock.invocationCallOrder.at(-1)!;

      // A just-registered FREE address, signed in with the password its
      // registrant chose: right password, unverified account.
      const fresh = await postLogin({ verifies: true, emailVerified: false });
      const freshFloorFirst = floorFirst();
      const freshEvents = [...emitUserEventMock.mock.calls];
      // The same attempt on an address that was already registered: wrong
      // password for the owner's verified account.
      const taken = await postLogin({ verifies: false, emailVerified: true });

      expect(seen(fresh.state)).toEqual(seen(taken.state));
      expect(fresh.state.statusCode).toBe(401);
      expect(String(fresh.state.body)).toContain(
        'If you have just registered, confirm your email address first'
      );
      expect(freshFloorFirst).toBe(true);
      expect(floorFirst()).toBe(true);
      expect(fresh.sessions.service.create).not.toHaveBeenCalled();
      // Stays counted as a failed attempt.
      expect(registerLoginAttempt).toHaveBeenCalledWith(expect.anything(), REALM.id, LOCKOUT_IDS);
      expect(recordSuccessfulLogin).not.toHaveBeenCalled();
      expect(resetFailedAttempts).not.toHaveBeenCalled();
      // The reason is kept where only operators read it, with the unverified
      // account as the subject; the wrong password names no user.
      expect(freshEvents).toEqual([
        [
          expect.anything(),
          'urn:qauth:event:user.sign_in_failed:v1-rc.0',
          { method: 'password', reason: 'email_not_verified' },
          { realmId: 'realm-1', userId: 'user-1', actor: 'user' },
        ],
      ]);
      expect(emitUserEventMock).toHaveBeenLastCalledWith(
        expect.anything(),
        'urn:qauth:event:user.sign_in_failed:v1-rc.0',
        { method: 'password', reason: 'invalid_credentials' },
        { realmId: 'realm-1', userId: null, actor: 'user' }
      );
      expect(emitUserEventMock).toHaveBeenCalledTimes(2);
    });

    it('still signs in an unverified credential when an operator turns REQUIRE_VERIFIED_ACCOUNT off', async () => {
      const { state, sessions } = await postLogin({ verifies: true, emailVerified: false });

      expect(state.statusCode).toBe(302);
      expect(sessions.service.create).toHaveBeenCalledOnce();
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
    const rawToken = cookieValue.split('.')[1];

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
    const { fastify, ctx, sessions } = makeFastify();
    await loginRoute(fastify);

    const getReply = createReply();
    await ctx.get!({ query: {}, headers: {}, ip: '127.0.0.1' }, getReply.reply);
    const cookieValue = csrfCookieValue(getReply.state.setCookies);
    const rawToken = cookieValue.split('.')[1];

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
    expect(sessions.service.create).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:user.sign_in_failed:v1-rc.0',
      { method: 'password', reason: 'invalid_credentials' },
      { realmId: 'realm-1', userId: null, actor: 'user' }
    );
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
    const rawToken = cookieValue.split('.')[1];

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
  // A refused sign-in once wrote the address to `audit_logs`, and with no bound
  // one anonymous request stored a 1 MiB row; the refusal page still renders it
  // back. RFC 5321 caps an address at 254.
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
