import { createPasswordProvider } from '@qauth-labs/fastify-plugin-federation';
import { InvalidCredentialsError, TooManyRequestsError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    LOGIN_RATE_LIMIT: 60,
    LOGIN_RATE_WINDOW: 60,
    SYSTEM_CLIENT_ID: 'system',
    // Failed-login tracking enabled; the redis stub's ttl defaults to -2 (not
    // locked), so the credential-flow tests are unaffected. The lockout path is
    // exercised by its own test below, and the helper internals in
    // failed-login.test.ts.
    FAILED_LOGIN_TRACKING_ENABLED: true,
    FAILED_LOGIN_MAX_ATTEMPTS: 5,
    FAILED_LOGIN_WINDOW: 900,
    FAILED_LOGIN_LOCKOUT_DURATION: 900,
    // On by default since ANT-2026-SPEMY9GU. Off here so the credential-flow
    // tests can sign in an unverified fixture; the gate tests turn it on.
    REQUIRE_VERIFIED_ACCOUNT: false,
  },
}));

import { env } from '../../../config/env';
import { createFakeSessionService } from '../../../testing/browser-sessions';
import { testRealm } from '../../../testing/request-realm';
import { hashEmail } from '../../helpers/auth-events';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { emitUserEvent } from '../../helpers/user-events';
import loginRoute from './login';

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

const emitUserEventMock = vi.mocked(emitUserEvent);

/** The realm the realm resolver (#486) decorated every request with. */
const REALM = testRealm({ id: 'realm-1', name: 'default' });

beforeEach(() => {
  emitUserEventMock.mockClear();
});

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

interface ReplyStub {
  header: (k: string, v: string) => ReplyStub;
  send: (body: unknown) => unknown;
  headers: Record<string, string>;
}

function createReply(): ReplyStub {
  const headers: Record<string, string> = {};
  const reply: ReplyStub = {
    headers,
    header(k, v) {
      headers[k] = v;
      return reply;
    },
    send(body) {
      return body;
    },
  };
  return reply;
}

function createFastifyStub() {
  const ctx: TestContext = {};
  // The browser-session service (#488): this route must never reach it.
  const sessionService = createFakeSessionService();

  const fastify: any = {
    withTypeProvider: () => ({
      post: (
        _url: string,
        _opts: unknown,
        handler: (request: any, reply: any) => Promise<unknown>
      ) => {
        ctx.handler = (request, reply) => {
          // The realm resolver's decoration (#486): a request reaches its
          // handler with the realm of its host.
          request.realm ??= REALM;
          return handler(request, reply);
        };
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
      userAttributes: {
        // #229 claim resolution default: one verified self_reported email
        // attribute matching the user fixture. Overridden per test for the
        // divergent-source and omission cases.
        findVerifiedByUserIdAndKey: vi.fn().mockResolvedValue([
          {
            id: 'attr-1',
            userId: 'user-1',
            source: 'self_reported',
            attrKey: 'email',
            attrValue: 'user@example.com',
            verified: true,
            expiresAt: null,
            createdAt: 1,
            updatedAt: 1,
          },
        ]),
      },
      oauthClients: {
        findByClientId: vi.fn(),
        create: vi.fn(),
      },
      refreshTokens: {
        create: vi.fn().mockResolvedValue(undefined),
      },
    },
    passwordHasher: {
      verifyPassword: vi.fn(),
      // Also makes the decoy hash an unknown email is verified against.
      hashPassword: vi.fn().mockResolvedValue('decoy-hash'),
    },
    // The real provider (pure, framework-free): the registry is load-bearing —
    // the route resolves 'password' through it, and one test pins that.
    providerRegistry: {
      resolve: vi.fn().mockReturnValue(createPasswordProvider()),
      has: vi.fn().mockReturnValue(true),
      register: vi.fn(),
    },
    jwtUtils: {
      signAccessToken: vi.fn(),
      // #275: classical posture — issueAccessToken takes the non-hybrid branch.
      isHybridSigningEnabled: () => false,
      generateRefreshToken: vi.fn().mockReturnValue({ token: 'rt', tokenHash: 'rth' }),
      getAccessTokenLifespan: vi.fn().mockReturnValue(900),
      getRefreshTokenLifespan: vi.fn().mockReturnValue(604800),
    },
    sessionService,
    redis: {
      ttl: vi.fn().mockResolvedValue(-2),
      incr: vi.fn().mockResolvedValue(1),
      expire: vi.fn().mockResolvedValue(1),
      set: vi.fn().mockResolvedValue('OK'),
      del: vi.fn().mockResolvedValue(0),
    },
    metrics: {
      loginAttempts: { inc: vi.fn() },
      tokensIssued: { inc: vi.fn() },
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };

  return { fastify: fastify as FastifyInstance, ctx, sessionService };
}

/** A request-scoped logger stub for the structured auth-event helper. */
function requestLog() {
  return { info: vi.fn(), warn: vi.fn() };
}

/**
 * In-memory Redis with the commands the failed-login helper uses (ttl, incr,
 * decr, expire, set with EX and optional NX, del), for the tests that need
 * the lockout's real state rather than canned answers.
 */
function createMemoryRedis() {
  const store = new Map<string, string>();
  const ttls = new Map<string, number>();
  return {
    ttl: vi.fn(async (key: string) => (store.has(key) ? (ttls.get(key) ?? -1) : -2)),
    incr: vi.fn(async (key: string) => {
      const next = Number(store.get(key) ?? '0') + 1;
      store.set(key, String(next));
      return next;
    }),
    decr: vi.fn(async (key: string) => {
      const next = Number(store.get(key) ?? '0') - 1;
      store.set(key, String(next));
      return next;
    }),
    expire: vi.fn(async (key: string, seconds: number) => {
      if (!store.has(key)) return 0;
      ttls.set(key, seconds);
      return 1;
    }),
    set: vi.fn(async (key: string, value: string, _ex: 'EX', seconds: number, nx?: 'NX') => {
      if (nx === 'NX' && store.has(key)) return null;
      store.set(key, value);
      ttls.set(key, seconds);
      return 'OK';
    }),
    del: vi.fn(async (...keys: string[]) => {
      let count = 0;
      for (const key of keys) {
        if (store.delete(key)) count++;
        ttls.delete(key);
      }
      return count;
    }),
    _store: store,
  };
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
    createdAt: 1_600_000_000_000,
    updatedAt: 1_600_000_000_000,
    ...overrides,
  };
}

function userFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 'user-1',
    email: 'user@example.com',
    emailVerified: true,
    passwordHash: 'hash',
    enabled: true,
    ...overrides,
  };
}

describe('POST /auth/login', () => {
  it('signs access token with aud resolved from the system client and sets Cache-Control: no-store', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const user = userFixture();
    const systemClient = {
      id: 'sc-uuid',
      clientId: 'system',
      audience: ['urn:qauth:aud:developer:v1-rc.0'],
    };

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(user);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      systemClient
    );
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    const request = {
      body: { email: 'user@example.com', password: 'p' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    const result = await handler(request, reply);

    // aud comes from the system client's audience, the developer API's since
    // #509 (single-item array → string)
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        clientId: 'system',
        aud: 'urn:qauth:aud:developer:v1-rc.0',
      })
    );

    // RFC 6749 §5.1 — token response must not be cached
    expect(reply.headers['Cache-Control']).toBe('no-store');
    expect(reply.headers['Pragma']).toBe('no-cache');

    expect(result).toMatchObject({
      access_token: 'jwt',
      refresh_token: 'rt',
      token_type: 'Bearer',
    });

    // The sign-in event names the user and the system client, never the session.
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      request,
      'urn:qauth:event:user.signed_in:v1-rc.0',
      { method: 'password' },
      { realmId: 'realm-1', userId: 'user-1', clientId: 'system', actor: 'user' }
    );
  });

  it('creates no browser session: a sign-in here answers with tokens only (#488)', async () => {
    // The session this route once wrote was never returned or read. Only the
    // hosted UI's sign-ins create one.
    const { fastify, ctx, sessionService } = createFastifyStub();
    // The Redis store a session was once written to, to show none is now.
    const sessionUtils = { setSession: vi.fn() };
    Object.assign(fastify, { sessionUtils });
    await loginRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'sc-uuid',
      clientId: 'system',
      audience: ['urn:qauth:aud:developer:v1-rc.0'],
    });
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    const reply = createReply();
    const result = await ctx.handler(
      {
        body: { email: 'user@example.com', password: 'p' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
        log: requestLog(),
      },
      reply
    );

    expect(result).toMatchObject({ access_token: 'jwt', refresh_token: 'rt' });
    expect(sessionService.create).not.toHaveBeenCalled();
    expect(sessionUtils.setSession).not.toHaveBeenCalled();
    expect(reply.headers['Set-Cookie']).toBeUndefined();
  });

  it.each([
    ['no sso_max_lifespan: the whole refresh lifespan', null, 604_800_000],
    ["an sso_max_lifespan of one hour: the family's end", 3600, 3_600_000],
  ])(
    'starts a refresh-token family whose first token expires after %s (#552)',
    async (_label, ssoMaxLifespan, lifetimeMs) => {
      const { fastify, ctx } = createFastifyStub();
      await loginRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');

      (
        fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
      ).mockResolvedValue(credentialFixture());
      (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
        id: 'sc-uuid',
        clientId: 'system',
        audience: ['urn:qauth:aud:developer:v1-rc.0'],
      });
      (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

      const before = Date.now();
      await ctx.handler(
        {
          realm: testRealm({ id: 'realm-1', ssoMaxLifespan }),
          body: { email: 'user@example.com', password: 'p' },
          ip: '127.0.0.1',
          headers: { 'user-agent': 'vitest' },
          log: requestLog(),
        },
        createReply()
      );

      const stored = (fastify.repositories.refreshTokens.create as unknown as Mock).mock
        .calls[0][0] as {
        familyCreatedAt: number;
        familySessionExpiresAt: number | null;
        expiresAt: number;
      };
      expect(stored.familyCreatedAt).toBeGreaterThanOrEqual(before);
      expect(stored.familyCreatedAt).toBeLessThanOrEqual(Date.now());
      expect(stored.expiresAt).toBe(stored.familyCreatedAt + lifetimeMs);
      // No browser session backs this sign-in, so none caps the family.
      expect(stored.familySessionExpiresAt).toBeNull();
    }
  );

  it('mints the first-party token with no email claims, even for a verified address — ANT-2026-2O0T72HY', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);

    // Every candidate source has an address on purpose: users row says
    // canonical@example.com, credential external_sub says user@example.com,
    // and the verified attribute says attr@example.com. An access token
    // carries email only under the `email` scope, and this token is granted
    // no scope, so none of them may appear.
    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(
      credentialFixture({
        credentialData: { password_hash: 'hash', email_verified: false },
      })
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(
      userFixture({ email: 'canonical@example.com', emailVerified: true })
    );
    (
      fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue([
      {
        id: 'attr-1',
        userId: 'user-1',
        source: 'self_reported',
        attrKey: 'email',
        attrValue: 'attr@example.com',
        verified: true,
        expiresAt: null,
        createdAt: 1,
        updatedAt: 1,
      },
    ]);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'sc-uuid',
      clientId: 'system',
      audience: ['urn:qauth:aud:developer:v1-rc.0'],
    });
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    if (!ctx.handler) throw new Error('Handler missing');
    await ctx.handler(
      {
        body: { email: 'user@example.com', password: 'p' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
        log: requestLog(),
      },
      createReply()
    );

    // Full-payload strictness kept from the #228 before-fixture: exact object.
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith({
      sub: 'user-1',
      clientId: 'system',
      aud: 'urn:qauth:aud:developer:v1-rc.0',
    });
    // The provider is resolved from the registry — it is load-bearing, not
    // decorative (ADR-003).
    expect(fastify.providerRegistry.resolve).toHaveBeenCalledWith('password');
  });

  it('omits BOTH email claims from the access token when no verified attribute exists — BREAKING #229', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
    (
      fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue([]);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'sc-uuid',
      clientId: 'system',
      audience: ['urn:qauth:aud:developer:v1-rc.0'],
    });
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    if (!ctx.handler) throw new Error('Handler missing');
    const result = await ctx.handler(
      {
        body: { email: 'user@example.com', password: 'p' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
        log: requestLog(),
      },
      createReply()
    );

    // Login itself still succeeds (the F-08 gate is a separate control).
    expect(result).toMatchObject({ access_token: 'jwt', token_type: 'Bearer' });
    // Omitted means the KEYS are absent from the signed claims — never null.
    const signedClaims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect('email' in signedClaims).toBe(false);
    expect('email_verified' in signedClaims).toBe(false);
  });

  it('throws InvalidCredentialsError for unknown email and skips token minting', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(undefined);

    const request = {
      body: { email: 'missing@example.com', password: 'p' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(InvalidCredentialsError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    // A missing credential costs the same argon2 verification as a wrong
    // password, against a decoy hash (CXMKR1RL): the fixed response-time
    // floor alone hides nothing once argon2 jobs queue up.
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledExactlyOnceWith(
      'decoy-hash',
      'p'
    );
  });

  it('throws InvalidCredentialsError for wrong password', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(false);

    const request = {
      body: { email: 'user@example.com', password: 'wrong' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(InvalidCredentialsError);
    // No address in the event, and no subject: a wrong password confirms no user.
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      request,
      'urn:qauth:event:user.sign_in_failed:v1-rc.0',
      { method: 'password', reason: 'invalid_credentials' },
      { realmId: 'realm-1', userId: null, actor: 'user' }
    );
  });

  it("looks the account up, counts the attempt and records the refusal in the request's realm (#487)", async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(undefined);

    const realm = testRealm({ id: 'realm-2' });
    const request = {
      body: { email: 'user@example.com', password: 'p' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
      realm,
    };

    await expect(handler(request, createReply())).rejects.toThrow(InvalidCredentialsError);
    expect(fastify.repositories.userCredentials.findByRealmProviderSub).toHaveBeenCalledWith(
      'realm-2',
      'password',
      'user@example.com'
    );
    expect(fastify.redis.incr).toHaveBeenCalledWith('failed-login:attempts:realm-2:ip:127.0.0.1');
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      request,
      'urn:qauth:event:user.sign_in_failed:v1-rc.0',
      { method: 'password', reason: 'invalid_credentials' },
      { realmId: 'realm-2', userId: null, actor: 'user' }
    );
  });

  it('records an unexpected failure as a sign_in_failed event with internal_error', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockRejectedValue(
      new Error('database unavailable')
    );

    const request = {
      body: { email: 'user@example.com', password: 'p' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, createReply())).rejects.toThrow('database unavailable');
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      request,
      'urn:qauth:event:user.sign_in_failed:v1-rc.0',
      { method: 'password', reason: 'internal_error' },
      { realmId: 'realm-1', userId: null, actor: 'user' }
    );
  });

  it('rejects a DISABLED user with the correct password exactly like a wrong password', async () => {
    // A disabled account must get no token, and must be indistinguishable from
    // a bad password — the same 401 the browser login already returns.
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(
      userFixture({ enabled: false })
    );
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    const request = {
      body: { email: 'user@example.com', password: 'correct' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(InvalidCredentialsError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.users.updateLastLogin).not.toHaveBeenCalled();
  });

  it('treats malformed credential_data as invalid credentials (401), logs for operators, burns a decoy argon2', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture({ credentialData: { passwordHash: 'camelCase-drift' } }));

    const request = {
      body: { email: 'user@example.com', password: 'p' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    // Generic 401 — a distinct status would leak account state (enumeration).
    await expect(handler(request, reply)).rejects.toThrow(InvalidCredentialsError);
    // The stored hash is not consulted, but the decoy costs what it would.
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledExactlyOnceWith(
      'decoy-hash',
      'p'
    );
    // The error-level log line is the operator alerting hook for corruption.
    expect(fastify.log.error).toHaveBeenCalledWith(
      expect.objectContaining({ credentialId: 'cred-1' }),
      expect.stringContaining('malformed credential_data')
    );
  });

  describe('verified-account gate (ANT-2026-SPEMY9GU)', () => {
    /**
     * Everything a caller of POST /auth/login can observe about one refused
     * attempt: the error the error handler turns into the response, the
     * response headers, the `/metrics` label, and the timing floor applied
     * before the event.
     */
    async function refusal(setup: (fastify: FastifyInstance) => void) {
      const { fastify, ctx, sessionService } = createFastifyStub();
      await loginRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');
      setup(fastify);
      vi.mocked(ensureMinimumResponseTime).mockClear();
      emitUserEventMock.mockClear();

      const reply = createReply();
      const error = await ctx
        .handler(
          {
            body: { email: 'user@example.com', password: 'p' },
            ip: '127.0.0.1',
            headers: { 'user-agent': 'vitest' },
            log: requestLog(),
          },
          reply
        )
        .then(
          () => undefined,
          (thrown: unknown) => thrown as Error & { statusCode?: number; code?: string }
        );

      const floorOrder = vi.mocked(ensureMinimumResponseTime).mock.invocationCallOrder[0];
      const eventOrder = emitUserEventMock.mock.invocationCallOrder[0];
      return {
        fastify,
        sessionService,
        observed: {
          error: error && {
            name: error.name,
            message: error.message,
            statusCode: error.statusCode,
            code: error.code,
          },
          headers: reply.headers,
          metric: (fastify.metrics.loginAttempts.inc as unknown as Mock).mock.calls,
          // The floor each refusal is padded to (the start time differs per run).
          floor: vi.mocked(ensureMinimumResponseTime).mock.calls.map(([, floorMs]) => floorMs),
          floorBeforeEvent: floorOrder !== undefined && floorOrder < eventOrder,
        },
      };
    }

    afterEach(() => {
      (env as { REQUIRE_VERIFIED_ACCOUNT: boolean }).REQUIRE_VERIFIED_ACCOUNT = false;
    });

    it('answers an unverified account exactly as a wrong password', async () => {
      (env as { REQUIRE_VERIFIED_ACCOUNT: boolean }).REQUIRE_VERIFIED_ACCOUNT = true;

      // Someone registered a FREE address with a password of their choice and
      // logs in with it: right password, unverified account.
      const fresh = await refusal((fastify) => {
        (
          fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
        ).mockResolvedValue(
          credentialFixture({ credentialData: { password_hash: 'hash', email_verified: false } })
        );
        (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      });
      // The same attempt against an address that was already registered: the
      // owner's account, and the caller's password is wrong for it.
      const taken = await refusal((fastify) => {
        (
          fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
        ).mockResolvedValue(credentialFixture());
        (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
        (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(false);
      });

      expect(fresh.observed.error).toMatchObject({
        name: 'InvalidCredentialsError',
        message: 'Invalid email or password',
        statusCode: 401,
      });
      expect(fresh.observed).toEqual(taken.observed);
      expect(fresh.observed.floorBeforeEvent).toBe(true);
      expect(fresh.fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
      expect(fresh.sessionService.create).not.toHaveBeenCalled();
    });

    it('reads credential_data.email_verified, before the users row is looked up', async () => {
      (env as { REQUIRE_VERIFIED_ACCOUNT: boolean }).REQUIRE_VERIFIED_ACCOUNT = true;

      const { fastify, observed } = await refusal((stub) => {
        (
          stub.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
        ).mockResolvedValue(
          credentialFixture({ credentialData: { password_hash: 'hash', email_verified: false } })
        );
        // users row says VERIFIED — the gate must read credential_data (false),
        // not user.emailVerified; a regression to the users-row source lets
        // this login through and fails the test.
        (stub.repositories.users.findById as unknown as Mock).mockResolvedValue(
          userFixture({ emailVerified: true })
        );
        (stub.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      });

      expect(observed.error?.name).toBe('InvalidCredentialsError');
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
      expect(fastify.repositories.users.findById).not.toHaveBeenCalled();
      // The reason survives where only operators read it.
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        'urn:qauth:event:user.sign_in_failed:v1-rc.0',
        { method: 'password', reason: 'email_not_verified' },
        expect.objectContaining({ realmId: 'realm-1', userId: 'user-1', actor: 'user' })
      );
    });

    it('still signs in an unverified account when an operator turns the gate off', async () => {
      const { fastify, ctx } = createFastifyStub();
      await loginRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');
      (
        fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
      ).mockResolvedValue(
        credentialFixture({ credentialData: { password_hash: 'hash', email_verified: false } })
      );
      (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
        id: 'sc-uuid',
        clientId: 'system',
        audience: ['urn:qauth:aud:developer:v1-rc.0'],
      });
      (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

      await expect(
        ctx.handler(
          {
            body: { email: 'user@example.com', password: 'p' },
            ip: '127.0.0.1',
            headers: { 'user-agent': 'vitest' },
            log: requestLog(),
          },
          createReply()
        )
      ).resolves.toMatchObject({ access_token: 'jwt' });
    });
  });

  it('rejects with TooManyRequestsError when the identifier is locked out (#115)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;

    // Simulate an active lockout: ttl > 0 on the lockout key.
    (fastify.redis.ttl as unknown as Mock).mockResolvedValue(300);

    const request = {
      body: { email: 'user@example.com', password: 'p' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
      log: requestLog(),
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(TooManyRequestsError);
    // Locked out before any credential verification.
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    // Retry-After advertised.
    expect(reply.headers['Retry-After']).toBe('300');
  });

  it('keys the ip: lockout identifier on the /64 of an IPv6 client', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    // Only the /64 key is locked; every address inside it must hit that key.
    const ttl = fastify.redis.ttl as unknown as Mock;
    ttl.mockImplementation(async (key: string) =>
      key === `failed-login:lockout:${REALM.id}:ip:2001:db8:1:2::` ? 300 : -2
    );

    for (const ip of ['2001:db8:1:2::1', '2001:db8:1:2:ffff:eeee:dddd:cccc']) {
      const request = {
        body: { email: 'user@example.com', password: 'p' },
        ip,
        headers: { 'user-agent': 'vitest' },
        log: requestLog(),
      };
      await expect(handler(request, createReply())).rejects.toThrow(TooManyRequestsError);
    }
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });

  it('counts the attempt before the password is verified (#115)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await loginRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(false);

    await expect(
      handler(
        {
          body: { email: 'user@example.com', password: 'wrong' },
          ip: '127.0.0.1',
          headers: { 'user-agent': 'vitest' },
          log: requestLog(),
        },
        createReply()
      )
    ).rejects.toThrow(InvalidCredentialsError);

    // Counted on the way in, not after argon2 has returned, so concurrent
    // guesses cannot outrun the counter; a failure leaves it counted.
    expect((fastify.redis.incr as unknown as Mock).mock.invocationCallOrder[0]).toBeLessThan(
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mock.invocationCallOrder[0]
    );
    expect(fastify.redis.del).not.toHaveBeenCalled();
  });

  it('verifies at most FAILED_LOGIN_MAX_ATTEMPTS passwords for a burst of concurrent guesses (#115)', async () => {
    // ROIQJSAT: 20 guesses at one account, 5 from each of 4 addresses, all in
    // flight at once. Each verification takes a few milliseconds, like argon2
    // does, so every request reaches the lockout check before any has failed.
    const { fastify, ctx } = createFastifyStub();
    (fastify as unknown as { redis: unknown }).redis = createMemoryRedis();
    await loginRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(credentialFixture());
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
    const verifyPassword = fastify.passwordHasher.verifyPassword as unknown as Mock;
    verifyPassword.mockImplementation(async (_hash: string, password: string) => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      return password === 'correct';
    });

    const guesses = Array.from({ length: 20 }, (_, i) => (i === 19 ? 'correct' : `guess-${i}`));
    const results = await Promise.allSettled(
      guesses.map((password, i) =>
        handler(
          {
            body: { email: 'user@example.com', password },
            ip: `198.51.100.${Math.floor(i / 5) + 1}`,
            headers: { 'user-agent': 'vitest' },
            log: requestLog(),
          },
          createReply()
        )
      )
    );

    // env.FAILED_LOGIN_MAX_ATTEMPTS is 5 in this file.
    expect(verifyPassword).toHaveBeenCalledTimes(5);
    const refused = results.filter(
      (result) => result.status === 'rejected' && result.reason instanceof TooManyRequestsError
    );
    expect(refused).toHaveLength(15);
    // The right password, sent last, is among the refused guesses.
    expect(results[19].status).toBe('rejected');
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it("does not let a login to one's own account clear the source address's failures (GPU4YL6X)", async () => {
    // A password spray from one address: one guess at each of many accounts,
    // so only the ip: counter sees it. Registration is open, so the caller
    // also has an account of its own and logs in to it after every 4 guesses.
    const { fastify, ctx } = createFastifyStub();
    const redis = createMemoryRedis();
    (fastify as unknown as { redis: unknown }).redis = redis;
    await loginRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockImplementation(async (_realm: string, _provider: string, email: string) =>
      credentialFixture({ externalSub: email })
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(userFixture());
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockImplementation(
      async (_hash: string, password: string) => password === 'own-password'
    );
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'sc-uuid',
      clientId: 'system',
      audience: ['urn:qauth:aud:developer:v1-rc.0'],
    });
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    const login = (email: string, password: string) =>
      handler(
        {
          body: { email, password },
          ip: '203.0.113.7',
          headers: { 'user-agent': 'vitest' },
          log: requestLog(),
        },
        createReply()
      );

    for (let i = 0; i < 4; i++) {
      await expect(login(`victim-${i}@example.com`, 'Spring2026!')).rejects.toThrow(
        InvalidCredentialsError
      );
    }
    await expect(login('attacker@example.com', 'own-password')).resolves.toMatchObject({
      access_token: 'jwt',
    });

    // The own login cleared its own email's state, not the address's: the
    // address still holds its 4 failures, so the 5th guess is the last one
    // checked and the 6th is refused (env.FAILED_LOGIN_MAX_ATTEMPTS is 5).
    expect(
      redis._store.has(
        `failed-login:attempts:${REALM.id}:email:${hashEmail('attacker@example.com')}`
      )
    ).toBe(false);
    expect(redis._store.get(`failed-login:attempts:${REALM.id}:ip:203.0.113.7`)).toBe('4');
    await expect(login('victim-4@example.com', 'Spring2026!')).rejects.toThrow(
      InvalidCredentialsError
    );
    await expect(login('victim-5@example.com', 'Spring2026!')).rejects.toThrow(
      TooManyRequestsError
    );
  });
});
