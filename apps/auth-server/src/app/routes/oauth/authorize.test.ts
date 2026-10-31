import type { SessionAssuranceLevel } from '@qauth-labs/fastify-plugin-sessions';
import { InvalidRequestError, JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

import { testRealm } from '../../../testing/request-realm';
import type { RealmRow } from '../../helpers/request-realm';
import { emitUserEvent } from '../../helpers/user-events';

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

const emitUserEventMock = vi.mocked(emitUserEvent);

beforeEach(() => {
  emitUserEventMock.mockClear();
});

const { egressGet } = vi.hoisted(() => ({ egressGet: vi.fn() }));

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
    REDIRECT_URI_CUSTOM_SCHEMES: [] as string[],
  },
}));

// Mock only the network layer so CIMD resolution runs against a fixture doc.
vi.mock('../../helpers/egress-get', () => ({ egressGet }));

import { env } from '../../../config/env';
import { createBrowserSessionFixture } from '../../../testing/browser-sessions';
import { OAUTH_OPAQUE_PARAM_MAX_LENGTH, STEP_UP_FRESH_AUTH_WINDOW_MS } from '../../constants';
import { buildAuthorizationServerMetadata } from '../../helpers/discovery';
import { authorizeQuerySchema } from '../../schemas/oauth';
import authorizeRoute from './authorize';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
  postHandler?: (request: any, reply: any) => Promise<unknown>;
}

const REALM = testRealm({ id: 'realm-1' });

/**
 * The realm resolver's decoration (#486): a request reaches its handler with
 * the realm of its host. A request that names its own realm keeps it.
 */
function withRequestRealm(
  handler: NonNullable<TestContext['handler']>
): NonNullable<TestContext['handler']> {
  return (request, reply) => {
    request.realm ??= REALM;
    return handler(request, reply);
  };
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

/** A stub transaction handle whose `transaction()` (a savepoint) runs in itself. */
function transaction(): {
  tx: true;
  transaction: (cb: (inner: unknown) => Promise<unknown>) => unknown;
} {
  const tx = {
    tx: true as const,
    transaction: (cb: (inner: unknown) => Promise<unknown>) => cb(tx),
  };
  return tx;
}

function makeFastify() {
  const ctx: TestContext = {};
  const findActive = vi.fn();
  const findByClientId = vi.fn();
  // The browser sessions the `__Host-qauth_session` cookie names (#488).
  const sessions = createBrowserSessionFixture();
  const fastify: any = {
    withTypeProvider: () => {
      const route = {
        get: (_url: string, _opts: unknown, handler: any) => {
          ctx.handler = withRequestRealm(handler);
          return route;
        },
        post: (_url: string, _opts: unknown, handler: any) => {
          ctx.postHandler = withRequestRealm(handler);
          return route;
        },
      };
      return route;
    },
    repositories: {
      oauthClients: {
        findByClientId,
        // The system client is given the developer audience the first time
        // it is read (#509): the client the lookup returns, with the update.
        update: vi.fn(async (_id: string, data: Record<string, unknown>) => ({
          ...(await findByClientId.getMockImplementation()?.()),
          ...data,
        })),
      },
      oauthConsents: {
        findActive,
        // The locked re-read in the code-insert transaction sees what the
        // first read saw, unless a test says otherwise.
        findActiveForShare: vi.fn((realmId: string, userId: string, oauthClientId: string) =>
          findActive(realmId, userId, oauthClientId)
        ),
      },
      authorizationCodes: {
        create: vi.fn().mockResolvedValue({ id: 'code-1' }),
      },
      // The client registry (#549): the session is live under the code's
      // transaction unless a test says otherwise.
      sessions: {
        recordClient: vi.fn().mockResolvedValue(true),
      },
      // Both the session path and the Bearer fallback accept only a user who is
      // still enabled, looked up in the request's realm (#489).
      users: {
        findById: vi.fn(async (realmId: string, id: string) => ({ id, enabled: true, realmId })),
      },
    },
    // A nested `transaction()` is a savepoint of the same transaction, as in
    // drizzle, so the stub hands the code insert the same handle.
    db: { transaction: vi.fn(async (cb: (tx: unknown) => Promise<unknown>) => cb(transaction())) },
    jwtUtils: {
      extractFromHeader: vi.fn(),
      verifyAccessToken: vi.fn(),
    },
    sessionService: sessions.service,
    sessionUtils: {
      getSession: vi.fn(),
      // #316 follow-up: the login bounce parks the pending authorize URL here
      // instead of nesting it in `return_to`.
      setSession: vi.fn().mockResolvedValue(undefined),
      deleteSession: vi.fn().mockResolvedValue(undefined),
    },
    redis: {
      // Where a session's side record and its user's index live.
      ...sessions.redis,
      // Per-`jti` access-token denylist (RFC 7009); nothing revoked by default.
      exists: vi.fn().mockResolvedValue(0),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx, sessions };
}

/** A Bearer token's `sub` must be a user id (UUID): the first-party pin looks it up. */
const BEARER_USER = '0190a5c8-0000-7000-8000-000000000001';

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
  // An operator-provisioned client: the only kind whose redirect URI receives
  // authorization errors by automatic redirect (ANT-2026-O8U3P920).
  provisionedByOperator: true,
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
    // #316 follow-up: `return_to` carries a short single-use handle, NOT the
    // nested authorize query string (which inflated the Location header past a
    // reverse proxy's buffer once `state` was allowed up to 2048 chars). The
    // authorize URL itself is parked in Redis.
    expect(state.redirected).toContain(encodeURIComponent('/ui/resume/'));
    expect(state.redirected).not.toContain(encodeURIComponent('/oauth/authorize'));
    const pending = (fastify.sessionUtils.setSession as unknown as Mock).mock.calls[0];
    expect(pending[0]).toMatch(/^pending-authz:[A-Za-z0-9_-]{43}$/);
    expect((pending[1] as { authorizeUrl: string }).authorizeUrl).toContain('/oauth/authorize');
  });

  it('redirects to /ui/consent when session is valid but no prior consent', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(undefined);

    // A signed-in browser: a live session in the request's realm.
    const { cookie } = await sessions.signIn({ sid: 'sid-1', realmId: REALM.id, userId: 'user-1' });

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('/ui/consent?');
    // The code must NOT have been issued yet.
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('skips consent and issues code when existing consent covers the requested scopes', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email', 'read:foo'],
      revokedAt: null,
    });

    const { cookie } = await sessions.signIn({ sid: 'sid-2', realmId: REALM.id, userId: 'user-1' });

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    // The consent is re-read under a lock, in the transaction the code is
    // written in.
    const [, tx] = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0];
    expect(tx).toMatchObject({ tx: true });
    // Both consent reads are in the request's realm (#489).
    expect(fastify.repositories.oauthConsents.findActive).toHaveBeenCalledWith(
      REALM.id,
      'user-1',
      CLIENT.id
    );
    expect(fastify.repositories.oauthConsents.findActiveForShare).toHaveBeenCalledWith(
      REALM.id,
      'user-1',
      CLIENT.id,
      tx
    );
    // The issued code's event commits in the same transaction.
    expect(emitUserEventMock).toHaveBeenCalledTimes(1);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.completed:v1-rc.0',
      {},
      {
        realmId: 'realm-1',
        userId: 'user-1',
        clientId: CLIENT.clientId,
        actor: 'user',
        tx,
      }
    );
    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('code=');
    expect(state.redirected).toContain('state=xyz');
  });

  /** A signed-in browser with a consent covering `email`, authorizing `email`. */
  async function authorizeWithSession(query: Record<string, unknown> = {}) {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({
      sid: 'sid-549',
      realmId: REALM.id,
      userId: 'user-1',
    });
    const { reply, state } = createReply();
    const call = () =>
      ctx.handler!(
        {
          query: { ...BASE_QUERY, ...query },
          url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      );
    return { fastify, state, call };
  }

  it('stores the session’s sid on the code and records the client in the code’s transaction (#549)', async () => {
    const { fastify, state, call } = await authorizeWithSession();

    await call();

    expect(state.redirected).toContain('code=');
    const create = fastify.repositories.authorizationCodes.create as unknown as Mock;
    const recordClient = fastify.repositories.sessions.recordClient as unknown as Mock;
    const [code, tx] = create.mock.calls[0];
    expect(code).toMatchObject({ sessionId: 'sid-549', userId: 'user-1' });
    expect(recordClient).toHaveBeenCalledExactlyOnceWith(REALM.id, 'sid-549', CLIENT.id, tx);
    // READ COMMITTED, so the share locks see a revocation that made them wait.
    expect(fastify.db.transaction).toHaveBeenCalledWith(expect.any(Function), {
      isolationLevel: 'read committed',
    });
    // Recorded first: a session that ended gets no code at all.
    expect(recordClient.mock.invocationCallOrder[0]).toBeLessThan(
      create.mock.invocationCallOrder[0]
    );
  });

  it('issues no code when the session ended under the request, and sends the browser to sign in (#549)', async () => {
    const { fastify, state, call } = await authorizeWithSession();
    // A sign-out committed between the cookie's check and the code's
    // transaction: the share lock finds no live session.
    (fastify.repositories.sessions.recordClient as unknown as Mock).mockResolvedValue(false);

    await call();

    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(state.redirected).not.toContain('code=');
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'login_required', reason: 'session_ended_during_authorization' },
      { realmId: REALM.id, userId: 'user-1', clientId: CLIENT.clientId, actor: 'user' }
    );
  });

  it('answers login_required under prompt=none when the session ended under the request (#549)', async () => {
    const { fastify, state, call } = await authorizeWithSession({ prompt: 'none' });
    (fastify.repositories.sessions.recordClient as unknown as Mock).mockResolvedValue(false);

    await call();

    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    const location = new URL(state.redirected as string);
    expect(location.origin + location.pathname).toBe('https://example.com/cb');
    expect(location.searchParams.get('error')).toBe('login_required');
    expect(location.searchParams.get('code')).toBeNull();
  });

  it("resolves the client in the request's realm and records that realm (#487)", async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      revokedAt: null,
    });
    const tenant = testRealm({ id: 'realm-tenant' });
    const { cookie } = await sessions.signIn({
      sid: 'sid-1',
      realmId: tenant.id,
      userId: 'user-1',
    });

    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');
    const { reply, state } = createReply();
    await handler(
      {
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { cookie },
        ip: '127.0.0.1',
        realm: tenant,
      },
      reply
    );

    expect(state.redirected).toContain('code=');
    // The session is looked up in that realm too.
    expect(sessions.service.get).toHaveBeenCalledWith({ realmId: 'realm-tenant', sid: 'sid-1' });
    expect(fastify.repositories.oauthClients.findByClientId).toHaveBeenCalledWith(
      'realm-tenant',
      CLIENT.clientId
    );
    // So are the session's user and its consent (#489).
    expect(fastify.repositories.users.findById).toHaveBeenCalledWith('realm-tenant', 'user-1');
    expect(fastify.repositories.oauthConsents.findActive).toHaveBeenCalledWith(
      'realm-tenant',
      'user-1',
      CLIENT.id
    );
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.completed:v1-rc.0',
      {},
      expect.objectContaining({ realmId: 'realm-tenant', userId: 'user-1' })
    );
  });

  // ADR-019 Decision 1: a session signs its user in to its own realm only. A
  // cookie whose session lives in another realm is no sign-in here, even with
  // a consent that would otherwise mint a code at once.
  it('treats a session cookie of another realm as no session and sends the browser to /ui/login', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email', 'read:foo'],
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({
      sid: 'sid-other-realm',
      realmId: 'realm-other',
      userId: 'user-1',
    });

    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');
    const { reply, state } = createReply();
    await handler(
      {
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(sessions.service.get).toHaveBeenCalledWith({
      realmId: REALM.id,
      sid: 'sid-other-realm',
    });
    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(fastify.repositories.users.findById).not.toHaveBeenCalled();
    // The cookie is cleared as a stale one; the session itself is left to its
    // own realm.
    expect(state.headers['Set-Cookie']).toContain('Max-Age=0');
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(sessions.service.sessions.has('sid-other-realm')).toBe(true);
  });

  // The first consent read is a snapshot. A revocation that commits after it
  // must not leave a code issued on a consent that no longer exists: the
  // request is answered as one arriving after the revocation would be.
  it.each([
    ['shows the consent screen', { prompt: undefined }, '/ui/consent?'],
    ['answers consent_required to prompt=none', { prompt: 'none' }, 'error=consent_required'],
  ])(
    'issues no code and %s when the consent is revoked between the read and the code insert',
    async (_label, extraQuery, expectedRedirect) => {
      const { fastify, ctx, sessions } = makeFastify();
      await authorizeRoute(fastify);
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        CLIENT
      );
      (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
      (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
        scopes: ['email', 'read:foo'],
        revokedAt: null,
      });
      // Revoked by the time the row is locked.
      (fastify.repositories.oauthConsents.findActiveForShare as unknown as Mock).mockResolvedValue(
        undefined
      );
      const { cookie } = await sessions.signIn({
        sid: 'sid-race',
        realmId: REALM.id,
        userId: 'user-1',
      });

      const { reply, state } = createReply();
      await ctx.handler!(
        {
          query: { ...BASE_QUERY, ...extraQuery },
          url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      );

      expect(fastify.repositories.oauthConsents.findActiveForShare).toHaveBeenCalledOnce();
      expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
      expect(state.redirected).toContain(expectedRedirect);
      expect(state.redirected).not.toContain('code=');
    }
  );

  it('fails closed, without re-running the request, when every locked re-read finds no consent', async () => {
    // A consent that keeps vanishing under the lock must not loop the handler.
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      revokedAt: null,
    });
    (fastify.repositories.oauthConsents.findActiveForShare as unknown as Mock).mockResolvedValue(
      undefined
    );
    const { cookie } = await sessions.signIn({
      sid: 'sid-race-2',
      realmId: REALM.id,
      userId: 'user-1',
    });

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, prompt: 'none' },
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email&prompt=none',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    // One pass through the handler: one client lookup, one first read.
    expect(fastify.repositories.oauthClients.findByClientId).toHaveBeenCalledOnce();
    expect(fastify.repositories.oauthConsents.findActive).toHaveBeenCalledOnce();
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(state.redirected).toContain('error=consent_required');
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'consent_required', reason: 'consent_withdrawn_during_authorization' },
      expect.objectContaining({ clientId: CLIENT.clientId, actor: 'user' })
    );
    expect(emitUserEventMock).not.toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.completed:v1-rc.0',
      expect.anything(),
      expect.anything()
    );
  });

  it('persists RFC 8707 resource indicator(s) onto the authorization code', async () => {
    // RFC 8707 clients sends `resource` with /oauth/authorize;
    // the code row MUST carry it so /oauth/token can set `aud` correctly.
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      resourceScopes: { 'https://api.example.com/v1': ['email'] },
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({ sid: 'sid-3', realmId: REALM.id, userId: 'user-1' });

    const { reply } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, resource: ['https://api.example.com/v1'] },
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email&resource=https%3A%2F%2Fapi.example.com%2Fv1',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.resource).toEqual(['https://api.example.com/v1']);
  });

  describe('a QAuth API audience as resource (#509)', () => {
    const DEVELOPER_AUDIENCE = 'urn:qauth:aud:developer:v1-rc.0';

    async function authorizeFor(client: Record<string, unknown>, resource: string[]) {
      const { fastify, ctx, sessions } = makeFastify();
      await authorizeRoute(fastify);
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        client
      );
      (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
        scopes: ['email'],
        resourceScopes: Object.fromEntries(resource.map((value) => [value, ['email']])),
        revokedAt: null,
      });
      const { cookie } = await sessions.signIn({
        sid: 'sid-509',
        realmId: REALM.id,
        userId: 'user-1',
      });
      const { reply, state } = createReply();
      await ctx.handler!(
        {
          query: { ...BASE_QUERY, resource },
          url: '/oauth/authorize',
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      );
      return { fastify, state };
    }

    it('is refused with invalid_target when the client does not list it', async () => {
      for (const resource of [
        [DEVELOPER_AUDIENCE],
        ['https://api.example.com/v1', 'urn:qauth:aud:admin:v1-rc.0'],
      ]) {
        const { fastify, state } = await authorizeFor(CLIENT, resource);
        expect(state.redirected).toContain('error=invalid_target');
        expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
      }
    });

    it('is bound to the code when the client lists it', async () => {
      const { fastify } = await authorizeFor({ ...CLIENT, audience: [DEVELOPER_AUDIENCE] }, [
        DEVELOPER_AUDIENCE,
      ]);
      expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
      const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
        .calls[0][0];
      expect(createArg.resource).toEqual([DEVELOPER_AUDIENCE]);
    });
  });

  it('never reads RFC 8707 resource back out of request.url', async () => {
    // Regression: the handler used to re-parse `request.url` with
    // `URLSearchParams`, trusting that Zod had validated what it found there.
    // Zod validates what FASTIFY's parser found, and the two disagree
    // (`??resource=system`), so an unvalidated string became the token's `aud`.
    // Only the validated `request.query` may be bound to the code;
    // authorize-routing.test.ts covers the same thing with the real router.
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({ sid: 'sid-4', realmId: REALM.id, userId: 'user-1' });

    const { reply } = createReply();
    await ctx.handler!(
      {
        // `request.query` intentionally DOES NOT include `resource` — the
        // schema saw the unknown key `?resource` and stripped it.
        query: BASE_QUERY,
        url: '/oauth/authorize??resource=system&response_type=code&client_id=app-123&scope=email',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.resource).toEqual([]);
  });

  it('persists multiple RFC 8707 resource indicators as an array', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      resourceScopes: {
        'https://api.example.com/v1': ['email'],
        'https://api2.example.com/v1': ['email'],
      },
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({ sid: 'sid-5', realmId: REALM.id, userId: 'user-1' });

    const { reply } = createReply();
    await ctx.handler!(
      {
        query: {
          ...BASE_QUERY,
          resource: ['https://api.example.com/v1', 'https://api2.example.com/v1'],
        },
        url:
          '/oauth/authorize?response_type=code&client_id=app-123&scope=email' +
          '&resource=https%3A%2F%2Fapi.example.com%2Fv1' +
          '&resource=https%3A%2F%2Fapi2.example.com%2Fv1',
        headers: { cookie },
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

  // RFC 8707: a `resource` becomes the token's `aud`. A grant the user
  // remembered for one resource server must not silently yield a code for
  // another, on the interactive path or under prompt=none.
  it.each([
    ['a resource the stored consent does not list', { 'https://api.example.com/v1': ['email'] }],
    [
      'a scope that was approved for another resource only',
      { 'https://api.example.com/v1': ['email'], 'https://other.example.com/v1': ['read:foo'] },
    ],
  ])('does not issue a code silently for %s', async (_label, resourceScopes) => {
    for (const [prompt, expectedRedirect] of [
      [undefined, '/ui/consent?'],
      ['none', 'error=consent_required'],
    ] as const) {
      const { fastify, ctx, sessions } = makeFastify();
      await authorizeRoute(fastify);
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        CLIENT
      );
      (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
        scopes: ['email', 'read:foo'],
        resourceScopes,
        revokedAt: null,
      });
      const { cookie } = await sessions.signIn({
        sid: 'sid-other-resource',
        realmId: REALM.id,
        userId: 'user-1',
      });

      const { reply, state } = createReply();
      await ctx.handler!(
        {
          query: { ...BASE_QUERY, prompt, resource: ['https://other.example.com/v1'] },
          url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email&resource=https%3A%2F%2Fother.example.com%2Fv1',
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      );

      expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
      expect(state.redirected).toContain(expectedRedirect);
    }
  });
});

describe('POST /oauth/authorize (OIDC Core §3.1.2.1)', () => {
  it('issues a code from a form-encoded POST body, identically to GET', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email', 'read:foo'],
      revokedAt: null,
    });

    // Signed in a minute ago, so the session's auth time is not the mint time.
    const { session, cookie } = await sessions.signIn({
      sid: 'sid-post-1',
      realmId: REALM.id,
      userId: 'user-1',
      authTime: Date.now() - 60_000,
    });

    expect(ctx.postHandler).toBeDefined();
    const { reply, state } = createReply();
    await ctx.postHandler!(
      {
        method: 'POST',
        body: { ...BASE_QUERY, scope: 'email' },
        query: {},
        url: '/oauth/authorize',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('code=');
    expect(state.redirected).toContain('state=xyz');

    // OIDC Core §2: the REAL session auth-time (ms) is persisted on the code.
    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.authTime).toBe(session.authTime);
    // #552: and the session's absolute end, which caps the refresh family.
    expect(createArg.sessionExpiresAt).toBe(session.expiresAt);
  });

  it.each([
    ['a wallet session at high assurance', 'high', 'high'],
    ['a wallet session at substantial assurance', 'substantial', 'substantial'],
    // The password path: `ui/login.ts` signs in with no `assuranceLevel`
    // (ADR-003 makes a password credential `'low'`), so the session holds NULL,
    // the code records NULL and /oauth/token emits no `acr`. This is the
    // #237/#240 invariant, asserted at the hop where it could first be broken.
    ['a password session', null, null],
    // The session service's type admits neither of these; the route still
    // binds only a level it reads as above `low`.
    ['a session that somehow carries low', 'low', null],
    ['a session carrying an unreadable level', 'medium', null],
  ])(
    'binds the assurance level of %s onto the authorization code (#237)',
    async (_label, sessionLevel, expected) => {
      const { fastify, ctx, sessions } = makeFastify();
      await authorizeRoute(fastify);
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        CLIENT
      );
      (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
      (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
        scopes: ['email', 'read:foo'],
        revokedAt: null,
      });

      const { session, cookie } = await sessions.signIn({
        sid: 'sid-acr-1',
        realmId: REALM.id,
        userId: 'user-1',
        assuranceLevel: sessionLevel as SessionAssuranceLevel | null,
      });
      expect(session.assuranceLevel).toBe(sessionLevel);

      const { reply } = createReply();
      await ctx.postHandler!(
        {
          method: 'POST',
          body: { ...BASE_QUERY, scope: 'email' },
          query: {},
          url: '/oauth/authorize',
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      );

      const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
        .calls[0][0];
      expect(createArg.assuranceLevel).toBe(expected);
    }
  );

  it('reconstructs a lossless return_to from the POST body on the login round-trip', async () => {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);

    const { reply, state } = createReply();
    await ctx.postHandler!(
      {
        method: 'POST',
        body: { ...BASE_QUERY, scope: 'email' },
        query: {},
        url: '/oauth/authorize',
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('/ui/login?return_to=');
    // The POST params are reconstructed into an authorize URL so the GET
    // round-trip reproduces the request (PKCE challenge, scope, state,
    // client_id survive). #316 follow-up: that URL is parked server-side under
    // a handle, so the losslessness is asserted on the stash, not on the header.
    const stashed = (fastify.sessionUtils.setSession as unknown as Mock).mock.calls[0][1] as {
      authorizeUrl: string;
    };
    const resumed = new URL(stashed.authorizeUrl, 'http://placeholder');
    expect(resumed.pathname).toBe('/oauth/authorize');
    expect(resumed.searchParams.get('client_id')).toBe('app-123');
    expect(resumed.searchParams.get('code_challenge')).toBe(BASE_QUERY.code_challenge);
    expect(resumed.searchParams.get('scope')).toBe('email');
    expect(resumed.searchParams.get('state')).toBe(BASE_QUERY.state);
  });

  it('binds RFC 8707 resource from the POST body onto the code', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      resourceScopes: { 'https://api.example.com/v1': ['email'] },
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({
      sid: 'sid-post-2',
      realmId: REALM.id,
      userId: 'user-1',
    });

    const { reply } = createReply();
    await ctx.postHandler!(
      {
        method: 'POST',
        body: { ...BASE_QUERY, scope: 'email', resource: ['https://api.example.com/v1'] },
        query: {},
        url: '/oauth/authorize',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.resource).toEqual(['https://api.example.com/v1']);
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
    const ctx: {
      handler?: (req: any, reply: any) => Promise<unknown>;
      postHandler?: (req: any, reply: any) => Promise<unknown>;
    } = {};
    const store = new Map<string, string>();
    const fastify: any = {
      withTypeProvider: () => {
        const route = {
          get: (_url: string, _opts: unknown, handler: any) => {
            ctx.handler = withRequestRealm(handler);
            return route;
          },
          post: (_url: string, _opts: unknown, handler: any) => {
            ctx.postHandler = withRequestRealm(handler);
            return route;
          },
        };
        return route;
      },
      redis: {
        get: vi.fn(async (k: string) => store.get(k) ?? null),
        set: vi.fn(async (k: string, v: string) => {
          store.set(k, v);
          return 'OK';
        }),
      },
      passwordHasher: { hashPassword: vi.fn(async () => 'argon2id$sentinel') },
      repositories: {
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
      },
      jwtUtils: {
        extractFromHeader: vi.fn(),
        verifyAccessToken: vi.fn(),
      },
      sessionUtils: {
        getSession: vi.fn(),
        setSession: vi.fn().mockResolvedValue(undefined),
        deleteSession: vi.fn().mockResolvedValue(undefined),
      },
      log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    };
    return { fastify: fastify as FastifyInstance, ctx };
  }

  it('rejects when redirect_uri is not in the CIMD document (mismatch)', async () => {
    egressGet.mockReset();
    egressGet.mockResolvedValue(cimdDoc(['https://app.example.com/other-cb']));

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
    ).rejects.toBeInstanceOf(InvalidRequestError);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'invalid_request', reason: 'redirect_uri_not_registered' },
      expect.objectContaining({ clientId: CIMD_ID, actor: 'client' })
    );
  });

  // Regression (ANT-2026-D0XJAT8S): a CIMD document's `redirect_uris` never
  // went through the check registration applies, so a plain-http callback on
  // any host was stored and served — the code then crossed the network in
  // cleartext. Follow-up (2026-10-19): the whole document is refused, as DCR
  // refuses the whole request, so even its valid https URI is not served.
  it.each([
    ['the plain-http one', 'http://app.example.com/callback'],
    ['its valid https one', 'https://app.example.com/callback'],
  ])(
    'refuses a CIMD document that lists a non-loopback http redirect_uri, even for %s',
    async (_label, requested) => {
      egressGet.mockReset();
      egressGet.mockResolvedValue(
        cimdDoc(['https://app.example.com/callback', 'http://app.example.com/callback'])
      );

      const { fastify, ctx } = makeCimdFastify();
      await authorizeRoute(fastify);

      const { reply, state } = createReply();
      await expect(
        ctx.handler!(
          {
            query: {
              response_type: 'code',
              client_id: CIMD_ID,
              redirect_uri: requested,
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
      ).rejects.toBeInstanceOf(InvalidRequestError);
      expect(state.redirected).toBeUndefined();
      // Fail closed: nothing is materialised from the refused document.
      expect(fastify.repositories.oauthClients.upsertCimdClient).not.toHaveBeenCalled();
      // The refusal's prose stays in the log; the event carries the code the
      // caller is answered, and names no client: none resolved.
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        'urn:qauth:event:authorization.failed:v1-rc.0',
        { error: 'invalid_request', reason: 'cimd_client_refused' },
        { realmId: expect.any(String), actor: 'client' }
      );
    }
  );

  it('happy path: resolves CIMD client, materialises it, and proceeds to login/consent', async () => {
    egressGet.mockReset();
    egressGet.mockResolvedValue(cimdDoc(['https://app.example.com/callback']));

    const { fastify, ctx } = makeCimdFastify();
    await authorizeRoute(fastify);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);

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

  it('prompt=none with no session: shows login_required on the issuer instead of redirecting (RFC 9700 §4.11.2)', async () => {
    // Anyone who can host a document names a CIMD client's redirect URI; the
    // AS has no reason to trust it as an automatic redirect target.
    egressGet.mockReset();
    egressGet.mockResolvedValue(cimdDoc(['https://login-qauth.attacker.example/sign-in']));

    const { fastify, ctx } = makeCimdFastify();
    await authorizeRoute(fastify);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: {
          response_type: 'code',
          client_id: CIMD_ID,
          redirect_uri: 'https://login-qauth.attacker.example/sign-in',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          state: 'xyz',
          prompt: 'none',
        },
        url: `/oauth/authorize?response_type=code&client_id=${encodeURIComponent(CIMD_ID)}`,
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toBeUndefined();
    expect(state.statusCode).toBe(400);
    expect(state.body as string).toContain('<code>login_required</code>');
    expect(state.body as string).toContain('login-qauth.attacker.example');
  });
});

// Regression (ANT-2026-D0XJAT8S): the environment gate let every redirect
// through that was not a plain-http LOOPBACK one, so a registered plain-http
// callback on another host (a CIMD document's, an operator-seeded row's)
// received the code in cleartext. Registration refuses such a URI; the gate
// now does too, whatever put it in the row.
// Found while fixing the findings of scan qauth-20261015-005: registration
// accepted any syntactically valid scheme, so a stored row (or an
// operator-seeded one) can hold `javascript:` or `data:`. Authorize must not
// follow it, whatever the request does next (here: prompt=none, no session,
// an operator-provisioned client that would otherwise get the 302).
describe('GET /oauth/authorize — redirect URI scheme gate', () => {
  it.each(['javascript:alert(document.domain)//', 'data:text/html,hi', 'myapp:/callback'])(
    'refuses a registered %s before any redirect, in every environment',
    async (uri) => {
      for (const environment of ['development', 'staging', 'production']) {
        const { fastify, ctx } = makeFastify();
        await authorizeRoute(fastify);
        (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
          ...CLIENT,
          environment,
          redirectUris: [uri],
        });
        (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);

        const { reply, state } = createReply();
        await expect(
          ctx.handler!(
            {
              query: { ...BASE_QUERY, redirect_uri: uri, prompt: 'none' },
              url: '/oauth/authorize?response_type=code&client_id=app-123',
              headers: {},
              ip: '127.0.0.1',
            },
            reply
          )
        ).rejects.toBeInstanceOf(InvalidRequestError);
        expect(state.redirected).toBeUndefined();
        expect(emitUserEventMock).toHaveBeenCalledWith(
          expect.anything(),
          'urn:qauth:event:authorization.failed:v1-rc.0',
          { error: 'invalid_request', reason: 'redirect_uri_scheme_not_allowed' },
          expect.objectContaining({ clientId: CLIENT.clientId, actor: 'client' })
        );
      }
    }
  );

  it('still serves a private-use native redirect (RFC 8252 §7.1)', async () => {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...CLIENT,
      redirectUris: ['com.example.app:/oauth2redirect'],
    });
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, redirect_uri: 'com.example.app:/oauth2redirect' },
        url: '/oauth/authorize?response_type=code&client_id=app-123',
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );
    expect(state.redirected).toContain('/ui/login?return_to=');
  });

  describe('REDIRECT_URI_CUSTOM_SCHEMES (#774)', () => {
    const cursorCallback = 'cursor://anysphere.cursor-mcp/oauth/callback';

    afterEach(() => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = [];
    });

    async function authorizeWith(uri: string, environment: string) {
      const { fastify, ctx } = makeFastify();
      await authorizeRoute(fastify);
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
        ...CLIENT,
        environment,
        redirectUris: [uri],
      });
      (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
      const { reply, state } = createReply();
      const run = () =>
        ctx.handler!(
          {
            query: { ...BASE_QUERY, redirect_uri: uri },
            url: '/oauth/authorize?response_type=code&client_id=app-123',
            headers: {},
            ip: '127.0.0.1',
          },
          reply
        );
      return { fastify, run, state };
    }

    it('refuses a registered bare scheme when the setting is empty', async () => {
      const { fastify, run, state } = await authorizeWith(cursorCallback, 'production');
      await expect(run()).rejects.toBeInstanceOf(InvalidRequestError);
      expect(state.redirected).toBeUndefined();
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        'urn:qauth:event:authorization.failed:v1-rc.0',
        { error: 'invalid_request', reason: 'redirect_uri_scheme_not_allowed' },
        expect.anything()
      );
    });

    it('serves a registered bare scheme the deployment lists, in every environment', async () => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = ['cursor'];
      for (const environment of ['development', 'staging', 'production']) {
        const { run, state } = await authorizeWith(cursorCallback, environment);
        await run();
        expect(state.redirected).toContain('/ui/login?return_to=');
      }
    });

    it('still refuses a registered bare scheme that is not listed', async () => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = ['cursor'];
      const { run, state } = await authorizeWith('myapp:/callback', 'production');
      await expect(run()).rejects.toBeInstanceOf(InvalidRequestError);
      expect(state.redirected).toBeUndefined();
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        'urn:qauth:event:authorization.failed:v1-rc.0',
        { error: 'invalid_request', reason: 'redirect_uri_scheme_not_allowed' },
        expect.anything()
      );
    });
  });
});

describe('GET /oauth/authorize — plain-http redirect gate', () => {
  it('refuses a registered non-loopback http redirect_uri in every environment', async () => {
    for (const environment of ['development', 'staging', 'production']) {
      const { fastify, ctx } = makeFastify();
      await authorizeRoute(fastify);
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
        ...CLIENT,
        environment,
        redirectUris: ['http://app.example.com/callback'],
      });

      const { reply, state } = createReply();
      await expect(
        ctx.handler!(
          {
            query: { ...BASE_QUERY, redirect_uri: 'http://app.example.com/callback' },
            url: '/oauth/authorize?response_type=code&client_id=app-123',
            headers: {},
            ip: '127.0.0.1',
          },
          reply
        )
      ).rejects.toBeInstanceOf(InvalidRequestError);
      expect(state.redirected).toBeUndefined();
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        'urn:qauth:event:authorization.failed:v1-rc.0',
        { error: 'invalid_request', reason: 'http_redirect_requires_loopback' },
        expect.objectContaining({ clientId: CLIENT.clientId, actor: 'client' })
      );
    }
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
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    // Existing consent covers the requested scopes so the flow reaches code
    // issuance (skips the /ui/consent redirect) — isolating the cap check.
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['agent:readonly', 'agent:exec', 'email'],
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({ sid, realmId: REALM.id, userId: 'user-1' });
    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, client_id: (client as { clientId: string }).clientId, scope },
        url: `/oauth/authorize?response_type=code&client_id=${(client as { clientId: string }).clientId}&scope=${encodeURIComponent(scope)}`,
        headers: { cookie },
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
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'invalid_scope', reason: 'agent_scope_mode_exceeded' },
      expect.objectContaining({ clientId: READONLY_AGENT.clientId, actor: 'user' })
    );
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
    /** When the session's user authenticated, epoch ms. */
    authTime: number;
    prompt?: string;
    maxAge?: string;
    sid: string;
  }) {
    const client = opts.client ?? DANGEROUS_CLIENT;
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(
      opts.priorConsent === null || opts.priorConsent === undefined
        ? undefined
        : { scopes: opts.priorConsent, revokedAt: null }
    );
    const { cookie } = await sessions.signIn({
      sid: opts.sid,
      realmId: REALM.id,
      userId: 'user-1',
      authTime: opts.authTime,
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
        headers: { cookie },
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
      authTime: Date.now() - 10 * MINUTE,
      sid: 'sid-su-1',
    });
    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:step_up.required:v1-rc.0',
      {
        reason: 'fresh_authentication_required',
        elevatedScopes: ['write:foo'],
        dangerousScopes: ['write:foo'],
      },
      expect.objectContaining({ actor: 'user' })
    );
  });

  it('sends a non-dangerous elevation to the consent screen (incremental consent), not silently widened', async () => {
    // Prior consent covers read:foo; the request adds write:foo? No — use a
    // non-dangerous widening: prior covers email, request adds read:foo.
    const { fastify, state } = await run({
      client: CLIENT,
      scope: 'read:foo email',
      priorConsent: ['email'],
      authTime: Date.now() - 10 * MINUTE,
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
      authTime: Date.now() - 10 * MINUTE,
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
      authTime: Date.now() - 5000, // fresh
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
      authTime: Date.now() - 10 * MINUTE,
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
      authTime: Date.now() - 5000, // 5s old → floor(5) = 5 > 0
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
      authTime: Date.now() - 40, // 40ms old, simulating the post-login return trip
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
      authTime: Date.now() - 10 * MINUTE,
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
      authTime: Date.now() - 10 * MINUTE,
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
      authTime: Date.now() - 1000,
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
      authTime: Date.now() - 1000,
      prompt: 'none',
      sid: 'sid-su-10',
    });
    expect(state.redirected).toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
  });

  // Step-up compares requested scopes against a prior grant, so an EMPTY scope
  // set (every CIMD client; any client that omits `scope`) elevates nothing.
  // That must not read as "no interaction required": with no stored grant the
  // interactive path shows the consent screen, so prompt=none answers
  // consent_required and mints nothing.
  it('prompt=none returns consent_required when NO consent exists and the scope set is empty', async () => {
    const { fastify, state } = await run({
      client: CLIENT,
      scope: '',
      priorConsent: null,
      authTime: Date.now() - 1000,
      prompt: 'none',
      sid: 'sid-su-11',
    });
    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('error=consent_required');
    expect(state.redirected).not.toContain('/ui/consent');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('prompt=none returns consent_required for a dynamic client still in its badge window', async () => {
    // The interactive path always re-shows consent for a freshly registered
    // dynamic client, even over a remembered grant; prompt=none must not be
    // the way around that.
    const freshDynamicClient = {
      ...CLIENT,
      clientId: 'app-fresh-dcr',
      provisionedByOperator: false,
      dynamicRegisteredAt: Date.now() - 60 * 1000,
    } as unknown as typeof CLIENT;
    const { fastify, state } = await run({
      client: freshDynamicClient,
      scope: 'email',
      priorConsent: ['email'],
      authTime: Date.now() - 1000,
      prompt: 'none',
      sid: 'sid-su-12',
    });
    // A self-registered client's redirect URI is not one the AS trusts
    // (RFC 9700 §4.11.2): the error is shown, with the way back, rather than
    // redirected to automatically.
    expect(state.redirected).toBeUndefined();
    expect(state.statusCode).toBe(400);
    expect(state.body as string).toContain('<code>consent_required</code>');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('prompt=none still mints when a stored grant covers an empty scope set', async () => {
    const { fastify, state } = await run({
      client: CLIENT,
      scope: '',
      priorConsent: ['email'],
      authTime: Date.now() - 1000,
      prompt: 'none',
      sid: 'sid-su-13',
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

  async function runBearer(
    scope: string,
    payload: Record<string, unknown> = {},
    opts: {
      client?: Record<string, unknown>;
      /** The stored consent row; a covering, unrevoked grant unless overridden. */
      consent?: Record<string, unknown> | null;
      /** RFC 8707 resource indicators on the request. */
      resource?: string[];
      /** Why verification fails, when it does. */
      verifyError?: Error;
    } = {}
  ) {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    // `findByClientId` answers every lookup with this client, so it is also
    // the "system" client the Bearer path pins the token's `client_id` to.
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      opts.client ?? DANGEROUS_CLIENT
    );
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(
      opts.consent === undefined
        ? { scopes: ['read:foo', 'email'], revokedAt: null }
        : (opts.consent ?? undefined)
    );
    // No browser session; a valid Bearer token resolves the user.
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('bearer.token');
    if (opts.verifyError === undefined) {
      (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
        sub: BEARER_USER,
        clientId: DANGEROUS_CLIENT.clientId,
        aud: DANGEROUS_CLIENT.clientId,
        ...payload,
      });
    } else {
      (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(opts.verifyError);
    }
    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, client_id: 'app-bearer', scope, resource: opts.resource },
        url: `/oauth/authorize?response_type=code&client_id=app-bearer&scope=${encodeURIComponent(scope)}`,
        headers: { authorization: 'Bearer bearer.token' },
        ip: '127.0.0.1',
      },
      reply
    );
    return { fastify, state };
  }

  it('answers a refused token with access_denied, and a key store failure with temporarily_unavailable (#491)', async () => {
    for (const refused of [new JWTInvalidError('bad'), new JWTExpiredError('old')]) {
      const { fastify, state } = await runBearer('email', {}, { verifyError: refused });
      expect(state.redirected).toContain('error=access_denied');
      expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    }
    // RFC 6749 §4.1.2.1: the redirect URI is validated by now, so the client
    // hears it there, never as a bad token, and no code is issued.
    const { fastify, state } = await runBearer(
      'email',
      {},
      { verifyError: new Error('the key store is unreachable') }
    );
    const location = new URL(state.redirected as string);
    expect(location.searchParams.get('error')).toBe('temporarily_unavailable');
    expect(location.searchParams.get('state')).toBe(BASE_QUERY.state);
    expect(location.searchParams.get('iss')).not.toBeNull();
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(fastify.log.error).toHaveBeenCalled();
  });

  it('refuses a dangerous scope on the Bearer path with access_denied (no interactive step-up)', async () => {
    const { fastify, state } = await runBearer('write:foo');
    expect(state.redirected).toContain('error=access_denied');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:step_up.required:v1-rc.0',
      {
        reason: 'bearer_path_dangerous_scope_requires_interactive_stepup',
        error: 'access_denied',
        dangerousScopes: ['write:foo'],
      },
      expect.objectContaining({ userId: BEARER_USER, clientId: 'app-bearer', actor: 'user' })
    );
  });

  it('still mints a code for a non-dangerous scope on the Bearer path when a stored consent covers it', async () => {
    const { fastify, state } = await runBearer('email');
    expect(state.redirected).toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(fastify.repositories.oauthConsents.findActive).toHaveBeenCalledWith(
      REALM.id,
      BEARER_USER,
      DANGEROUS_CLIENT.id
    );
  });

  it('gives a Bearer-path code no session and records no client (#549)', async () => {
    const { fastify, state } = await runBearer('email');
    expect(state.redirected).toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ sessionId: null, userId: BEARER_USER }),
      expect.anything()
    );
    expect(fastify.repositories.sessions.recordClient).not.toHaveBeenCalled();
  });

  // The Bearer path cannot show a consent screen, so it must never stand in
  // for one: a code is issued only under a stored, unrevoked grant that
  // already covers the request — the same `canSkipConsent` question the
  // browser flow asks. Any client that resolves can be named here, including
  // one registered a moment ago through open Dynamic Client Registration.
  it.each([
    ['no consent exists', 'email', null],
    [
      'the stored consent does not cover the requested scopes',
      'email read:foo',
      { scopes: ['email'], revokedAt: null },
    ],
    ['the stored consent is revoked', 'email', { scopes: ['email'], revokedAt: Date.now() - 1000 }],
  ])('refuses the Bearer path with access_denied when %s', async (_label, scope, consent) => {
    const { fastify, state } = await runBearer(scope, {}, { consent });
    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('error=access_denied');
    expect(state.redirected).toContain('state=xyz');
    expect(state.redirected).not.toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'access_denied', reason: 'bearer_path_no_covering_consent' },
      expect.objectContaining({ userId: BEARER_USER, actor: 'user' })
    );
  });

  it('refuses the Bearer path for a dynamic client still in its badge window, even over a covering consent', async () => {
    const { fastify, state } = await runBearer(
      'email',
      {},
      {
        client: {
          ...DANGEROUS_CLIENT,
          provisionedByOperator: false,
          dynamicRegisteredAt: Date.now() - 60 * 1000,
        },
      }
    );
    // Refused; as a self-registered client, shown rather than redirected.
    expect(state.statusCode).toBe(400);
    expect(state.body as string).toContain('<code>access_denied</code>');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('issues no code on the Bearer path when the consent is revoked before the code insert', async () => {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      DANGEROUS_CLIENT
    );
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      revokedAt: null,
    });
    (fastify.repositories.oauthConsents.findActiveForShare as unknown as Mock).mockResolvedValue(
      undefined
    );
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('bearer.token');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: BEARER_USER,
      clientId: DANGEROUS_CLIENT.clientId,
      aud: DANGEROUS_CLIENT.clientId,
    });
    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, client_id: 'app-bearer', scope: 'email' },
        url: '/oauth/authorize?response_type=code&client_id=app-bearer&scope=email',
        headers: { authorization: 'Bearer bearer.token' },
        ip: '127.0.0.1',
      },
      reply
    );
    expect(state.redirected).toContain('error=access_denied');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  // RFC 8707: the `resource` is the token's `aud`, so the covering consent
  // must cover it too, exactly as on the browser path.
  it('refuses the Bearer path for a resource the stored consent does not cover', async () => {
    const { fastify, state } = await runBearer(
      'email',
      {},
      {
        consent: {
          scopes: ['email'],
          resourceScopes: { 'https://api.example.com/v1': ['email'] },
          revokedAt: null,
        },
        resource: ['https://payroll.example.com/v1'],
      }
    );
    expect(state.redirected).toContain('error=access_denied');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('mints on the Bearer path for a resource the stored consent covers, and binds it', async () => {
    const { fastify, state } = await runBearer(
      'email',
      {},
      {
        consent: {
          scopes: ['email'],
          resourceScopes: { 'https://api.example.com/v1': ['email'] },
          revokedAt: null,
        },
        resource: ['https://api.example.com/v1'],
      }
    );
    expect(state.redirected).toContain('code=');
    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.resource).toEqual(['https://api.example.com/v1']);
  });

  // #509: the portal's token must never become a token for an API family on
  // the Bearer path, which has no sign-in and no consent screen.
  it.each([
    [
      'the request names a family audience the client lists',
      { audience: ['urn:qauth:aud:account:v1-rc.0'] },
      ['urn:qauth:aud:account:v1-rc.0'],
    ],
    [
      "the client's default audience holds one",
      { audience: ['https://api.example.com', 'urn:qauth:aud:developer:v1-rc.0'] },
      undefined,
    ],
  ])('refuses the Bearer path with access_denied when %s', async (_label, client, resource) => {
    // The mock answers the system client lookup with this client too, so the
    // token carries its audience to pass the portal-token check.
    const { fastify, state } = await runBearer(
      'email',
      { aud: client.audience },
      {
        client: { ...DANGEROUS_CLIENT, ...client },
        consent: {
          scopes: ['email'],
          resourceScopes: { 'urn:qauth:aud:account:v1-rc.0': ['email'] },
          revokedAt: null,
        },
        resource,
      }
    );
    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('error=access_denied');
    expect(state.redirected).not.toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'access_denied', reason: 'bearer_path_reserved_audience' },
      expect.objectContaining({ userId: BEARER_USER, actor: 'user' })
    );
  });

  it('refuses a Bearer token issued to another client, even with the system audience', async () => {
    // A third-party client's user token whose `aud` was bound to `system`
    // through RFC 8707 `resource` is not the first-party login token: the
    // Bearer path must pin `client_id` like the management API does.
    const { fastify, state } = await runBearer('email', { clientId: 'third-party-app' });
    expect(state.redirected).toContain('error=access_denied');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('refuses a delegated (RFC 8693 `act`) Bearer token', async () => {
    const { fastify, state } = await runBearer('email', { act: { sub: 'agent-1' } });
    expect(state.redirected).toContain('error=access_denied');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('refuses a revoked Bearer token (per-jti denylist)', async () => {
    const { fastify, ctx } = makeFastify();
    (fastify.redis.exists as unknown as Mock).mockResolvedValue(1);
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      DANGEROUS_CLIENT
    );
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('bearer.token');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: BEARER_USER,
      jti: 'revoked-jti',
      clientId: DANGEROUS_CLIENT.clientId,
      aud: DANGEROUS_CLIENT.clientId,
    });
    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, client_id: 'app-bearer', scope: 'email' },
        url: '/oauth/authorize?response_type=code&client_id=app-bearer&scope=email',
        headers: { authorization: 'Bearer bearer.token' },
        ip: '127.0.0.1',
      },
      reply
    );
    expect(fastify.redis.exists).toHaveBeenCalledWith(expect.stringContaining('revoked-jti'));
    expect(state.redirected).toContain('error=access_denied');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('fails closed when the denylist cannot be read: temporarily_unavailable, no code (#491)', async () => {
    const { fastify, ctx } = makeFastify();
    const redisDown = new Error('redis down');
    (fastify.redis.exists as unknown as Mock).mockRejectedValue(redisDown);
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      DANGEROUS_CLIENT
    );
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('bearer.token');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: BEARER_USER,
      jti: 'some-jti',
      clientId: DANGEROUS_CLIENT.clientId,
      aud: DANGEROUS_CLIENT.clientId,
    });
    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, client_id: 'app-bearer', scope: 'email' },
        url: '/oauth/authorize?response_type=code&client_id=app-bearer&scope=email',
        headers: { authorization: 'Bearer bearer.token' },
        ip: '127.0.0.1',
      },
      reply
    );
    expect(state.redirected).toContain('error=temporarily_unavailable');
    expect(fastify.log.error).toHaveBeenCalledWith({ err: redisDown }, expect.any(String));
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });
});

describe('GET /oauth/authorize — disabled user', () => {
  // A session or a Bearer token established before the account was disabled
  // must not yield a code: the session is ended and the login page shown; the
  // Bearer path answers access_denied like an expired token.
  it('sends a session whose user has been disabled back to /ui/login', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      id: 'consent-1',
      scopes: ['email'],
    });
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-1',
      enabled: false,
    });
    const { cookie } = await sessions.signIn({ sid: 'sid-1', realmId: REALM.id, userId: 'user-1' });

    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');
    const { reply, state } = createReply();
    await handler(
      {
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(sessions.service.revoke).toHaveBeenCalledWith({
      realmId: REALM.id,
      sid: 'sid-1',
      reason: 'admin',
      actor: { type: 'system' },
    });
    expect(sessions.service.sessions.has('sid-1')).toBe(false);
    expect(state.headers['Set-Cookie']).toContain('Max-Age=0');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('refuses a Bearer token whose user has been disabled with access_denied', async () => {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      id: 'consent-1',
      scopes: ['email'],
    });
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('bearer.token');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: BEARER_USER,
      clientId: CLIENT.clientId,
      aud: CLIENT.clientId,
    });
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: BEARER_USER,
      enabled: false,
      realmId: REALM.id,
    });

    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');
    const { reply, state } = createReply();
    await handler(
      {
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { authorization: 'Bearer bearer.token' },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('error=access_denied');
    // Looked up in the request's realm (#489).
    expect(fastify.repositories.users.findById).toHaveBeenCalledWith(REALM.id, BEARER_USER);
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  /**
   * The Bearer path for the portal token of {@link BEARER_USER}, with `claims`
   * on it, when the users table holds `user` for it.
   */
  async function bearerAuthorize(
    user: Record<string, unknown>,
    claims: Record<string, unknown> = {}
  ) {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      id: 'consent-1',
      scopes: ['email'],
      revokedAt: null,
    });
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('bearer.token');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: BEARER_USER,
      clientId: CLIENT.clientId,
      aud: CLIENT.clientId,
      ...claims,
    });
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(user);

    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');
    const { reply, state } = createReply();
    await handler(
      {
        query: BASE_QUERY,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { authorization: 'Bearer bearer.token' },
        ip: '127.0.0.1',
      },
      reply
    );
    return { fastify, state };
  }

  /** The events emitted so far, by type and payload. */
  function emittedEvents() {
    return emitUserEventMock.mock.calls.map(([, type, payload]) => [type, payload]);
  }

  it('refuses a Bearer token minted before its user was last disabled, as a disabled user’s token (#748)', async () => {
    // Disabled a minute ago and enabled again since; the token is older.
    const disabledAt = Date.now() - 60_000;
    const iat = Math.floor((disabledAt - 60_000) / 1000);
    const issuedBefore = await bearerAuthorize(
      { id: BEARER_USER, enabled: true, notValidBefore: disabledAt, realmId: REALM.id },
      { iat }
    );
    expect(issuedBefore.state.redirected).toContain('https://example.com/cb');
    expect(issuedBefore.state.redirected).toContain('error=access_denied');
    expect(issuedBefore.state.redirected).not.toContain('code=');
    expect(issuedBefore.fastify.repositories.users.findById).toHaveBeenCalledWith(
      REALM.id,
      BEARER_USER
    );
    expect(issuedBefore.fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    const issuedBeforeEvents = emittedEvents();
    expect(issuedBeforeEvents).toEqual([
      ['urn:qauth:event:authorization.failed:v1-rc.0', { error: 'access_denied' }],
    ]);

    emitUserEventMock.mockClear();
    const disabled = await bearerAuthorize(
      { id: BEARER_USER, enabled: false, realmId: REALM.id },
      { iat }
    );

    // One answer: the client cannot tell the two apart.
    expect(issuedBefore.state.statusCode).toBe(disabled.state.statusCode);
    expect(issuedBefore.state.redirected).toBe(disabled.state.redirected);
    expect(issuedBeforeEvents).toEqual(emittedEvents());
  });

  it('issues a code from a Bearer token minted after its user was enabled again (#748)', async () => {
    const disabledAt = Date.now() - 600_000;
    const { fastify, state } = await bearerAuthorize(
      { id: BEARER_USER, enabled: true, notValidBefore: disabledAt, realmId: REALM.id },
      { iat: Math.floor(Date.now() / 1000) }
    );

    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('code=');
    expect(state.redirected).not.toContain('error=');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledTimes(1);
  });
});

describe('GET /oauth/authorize — environment localhost redirect gate (ADR-008 §5, #197)', () => {
  // A client that has registered an http://localhost redirect (exact-matched).
  const LOCALHOST_CLIENT = {
    ...CLIENT,
    redirectUris: ['http://localhost:3000/cb'],
  };
  const LOCALHOST_QUERY = {
    ...BASE_QUERY,
    redirect_uri: 'http://localhost:3000/cb',
  };

  async function run(realmEnv: string, clientEnv: string) {
    const { fastify, ctx } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...LOCALHOST_CLIENT,
      environment: clientEnv,
    });
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);

    const { reply, state } = createReply();
    return {
      fastify,
      state,
      call: () =>
        ctx.handler!(
          {
            query: LOCALHOST_QUERY,
            url: '/oauth/authorize?response_type=code&client_id=app-123',
            headers: {},
            ip: '127.0.0.1',
            realm: testRealm({
              id: 'realm-1',
              maxEnvironmentLaxity: realmEnv as RealmRow['maxEnvironmentLaxity'],
            }),
          },
          reply
        ),
    };
  }

  // ADR-008 (revised): http://localhost (loopback) redirects are the RFC 8252
  // standard for native / CLI clients (incl. MCP clients). They pass the gate
  // whenever PKCE is enforced — true for staging/production — so loopback +
  // PKCE works against a production AS. "Passing the gate" means the request
  // is not rejected and flows on to the unauthenticated login redirect (these
  // requests carry no session).
  it('production realm/client PERMITS http://localhost (PKCE enforced — RFC 8252)', async () => {
    const { state, call } = await run('production', 'production');
    await call();
    expect(state.redirected).toContain('/ui/login?return_to=');
  });

  it('staging client PERMITS http://localhost (PKCE enforced)', async () => {
    const { state, call } = await run('staging', 'staging');
    await call();
    expect(state.redirected).toContain('/ui/login?return_to=');
  });

  it('an UNSET environment fails safe to production, which PERMITS http://localhost (PKCE enforced)', async () => {
    const { state, call } = await run('bogus', 'also-bogus');
    await call();
    expect(state.redirected).toContain('/ui/login?return_to=');
  });

  it('development realm/client PERMITS http://localhost (passes the gate, proceeds to login)', async () => {
    const { state, call } = await run('development', 'development');
    // Not rejected by the gate — flows on to the unauthenticated login redirect
    // (the request carries no session), proving the localhost URI was allowed.
    await call();
    expect(state.redirected).toContain('/ui/login?return_to=');
  });

  it('a production realm caps a development client but still PERMITS http://localhost (PKCE enforced)', async () => {
    const { state, call } = await run('production', 'development');
    await call();
    expect(state.redirected).toContain('/ui/login?return_to=');
  });
});

describe('GET /oauth/authorize — loopback redirect on any port (RFC 8252 §7.3, #414)', () => {
  // A logged-in user with standing consent, so a matching request issues a
  // code straight away: the test sees both the stored redirect_uri and the
  // Location header.
  async function authorize(registered: string[], redirectUri: string) {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...CLIENT,
      redirectUris: registered,
    });
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email'],
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({
      sid: 'sid-loopback',
      realmId: REALM.id,
      userId: 'user-1',
    });

    const { reply, state } = createReply();
    const call = () =>
      ctx.handler!(
        {
          query: { ...BASE_QUERY, redirect_uri: redirectUri },
          url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      );
    return { fastify, state, call };
  }

  it.each([
    ['http://127.0.0.1/callback', 'http://127.0.0.1:53817/callback'],
    ['http://[::1]/callback', 'http://[::1]:53817/callback'],
    ['http://localhost/callback', 'http://localhost:53817/callback'],
    ['http://127.0.0.1:8080/callback', 'http://127.0.0.1:53817/callback'],
  ])(
    'registered %s accepts %s, binds the code to it and redirects to that port',
    async (registered, requested) => {
      const { fastify, state, call } = await authorize([registered], requested);
      await call();

      expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledWith(
        expect.objectContaining({ redirectUri: requested }),
        // The transaction the consent was re-read and locked in.
        expect.anything()
      );
      expect(state.redirected!.startsWith(`${requested}?`)).toBe(true);
      expect(new URL(state.redirected!).searchParams.get('code')).toBeTruthy();
    }
  );

  it.each([
    ['a different path', 'http://127.0.0.1:53817/other'],
    ['a different host', 'http://127.0.0.2:53817/callback'],
    ['a different loopback literal', 'http://localhost:53817/callback'],
    ['a different scheme', 'https://127.0.0.1:53817/callback'],
    ['an added query', 'http://127.0.0.1:53817/callback?x=1'],
    ['userinfo host confusion', 'http://127.0.0.1:53817@evil.example/callback'],
  ])('rejects %s on a registered loopback redirect', async (_label, requested) => {
    const { fastify, state, call } = await authorize(['http://127.0.0.1/callback'], requested);
    await expect(call()).rejects.toBeInstanceOf(InvalidRequestError);
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(state.redirected).toBeUndefined();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'invalid_request', reason: 'redirect_uri_not_registered' },
      expect.anything()
    );
  });

  it.each([
    ['https', 'https://app.example.com/cb', 'https://app.example.com:8443/cb'],
    ['https loopback', 'https://127.0.0.1/cb', 'https://127.0.0.1:8443/cb'],
    ['a custom scheme', 'com.example.app://localhost/cb', 'com.example.app://localhost:1234/cb'],
  ])('keeps exact matching, port included, for %s', async (_label, registered, requested) => {
    const { fastify, call } = await authorize([registered], requested);
    await expect(call()).rejects.toBeInstanceOf(InvalidRequestError);
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'invalid_request', reason: 'redirect_uri_not_registered' },
      expect.anything()
    );
  });
});

describe('GET /oauth/authorize — RFC 9207 §2 `iss` on every authorization response (#282)', () => {
  // The issuer of the realm this suite's requests are resolved to (REALM),
  // the `iss` of the tokens the realm signs (#491).
  const RAW_ISSUER = 'https://auth.example.com';

  /**
   * The value discovery publishes as `issuer`. Every assertion below compares
   * the redirect's `iss` against THIS rather than a hard-coded literal: the
   * acceptance criterion is byte-equality between the two documents, so the
   * test must break if either side starts shaping the issuer differently.
   */
  function discoveryIssuer(raw: string): string {
    return buildAuthorizationServerMetadata({ issuer: raw })['issuer'] as string;
  }

  /** The `iss` a redirect actually carried, percent-decoded as a client reads it. */
  function issOf(redirected: string | undefined): string | null {
    expect(redirected).toBeDefined();
    return new URL(redirected as string).searchParams.get('iss');
  }

  interface RunOptions {
    client?: Record<string, unknown>;
    query?: Record<string, unknown>;
    /** Browser session (default: fresh, valid). `null` drops the cookie entirely. */
    session?: { authTime?: number } | null;
    /** Prior consent used to reach the consent-skip / code-issuance path. */
    consent?: Record<string, unknown> | null;
    /** Present a Bearer token instead of a cookie; `false` makes verification fail. */
    bearer?: 'valid' | 'invalid';
    /**
     * The issuer of the request's realm, to prove `iss` tracks the realm row
     * verbatim (#490).
     */
    realmIssuer?: string;
  }

  async function run(opts: RunOptions = {}) {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      opts.client ?? CLIENT
    );
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(
      opts.consent === undefined ? { scopes: ['email', 'read:foo'], revokedAt: null } : opts.consent
    );

    const headers: Record<string, string> = {};
    if (opts.bearer) {
      (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue('bearer.token');
      if (opts.bearer === 'valid') {
        (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
          sub: BEARER_USER,
          clientId: (opts.client ?? CLIENT).clientId,
          aud: (opts.client ?? CLIENT).clientId,
        });
      } else {
        (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
          new JWTExpiredError('expired')
        );
      }
      headers['authorization'] = 'Bearer bearer.token';
    } else {
      (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
      if (opts.session !== null) {
        const { cookie } = await sessions.signIn({
          realmId: REALM.id,
          userId: 'user-1',
          ...opts.session,
        });
        headers['cookie'] = cookie;
      }
    }

    const query = { ...BASE_QUERY, ...opts.query };
    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query,
        url: `/oauth/authorize?response_type=code&client_id=${query.client_id}&scope=${encodeURIComponent(String(query.scope))}`,
        headers,
        ip: '127.0.0.1',
        ...(opts.realmIssuer === undefined
          ? {}
          : { realm: testRealm({ id: REALM.id, issuer: opts.realmIssuer }) }),
      },
      reply
    );
    return { fastify, state };
  }

  it('success response carries `iss` alongside the code (RFC 9207 §2)', async () => {
    const { fastify, state } = await run();
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('code=');
    expect(issOf(state.redirected)).toBe(discoveryIssuer(RAW_ISSUER));
  });

  // RFC 9700 §4.11.2: these three run before any user interaction and no
  // working flow depends on the redirect, so a client that may not use this
  // endpoint is answered with a 400 and never redirected — for every client,
  // since DCR alone can register one that fails them, with any redirect URI.
  it.each([
    ['client disabled', { enabled: false }],
    // ANT-2026-DR5XI3LV: an operator's suspension, whatever `enabled` says.
    ['client suspended by the operator', { enabled: true, suspended: true }],
    ['grant type not allowed', { grantTypes: ['client_credentials'] }],
    ['response type not allowed', { responseTypes: [] }],
  ])('unauthorized_client (%s) is a 400, never a redirect', async (_label, override) => {
    for (const client of [
      { ...CLIENT, ...override },
      {
        ...CLIENT,
        ...override,
        provisionedByOperator: false,
        dynamicRegisteredAt: Date.now() - 400 * 24 * 60 * 60 * 1000,
      },
    ]) {
      await expect(run({ client })).rejects.toMatchObject({
        message: 'unauthorized_client',
        statusCode: 400,
      });
    }
  });

  it('access_denied (invalid/expired Bearer token) carries `iss`', async () => {
    const { fastify, state } = await run({ bearer: 'invalid' });
    expect(state.redirected).toContain('error=access_denied');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(issOf(state.redirected)).toBe(discoveryIssuer(RAW_ISSUER));
  });

  it('access_denied (Bearer path dangerous-scope step-up refusal) carries `iss`', async () => {
    const { state } = await run({
      client: { ...CLIENT, clientId: 'app-bearer', scopes: ['read:foo', 'write:foo', 'email'] },
      query: { client_id: 'app-bearer', scope: 'write:foo' },
      bearer: 'valid',
    });
    expect(state.redirected).toContain('error=access_denied');
    expect(issOf(state.redirected)).toBe(discoveryIssuer(RAW_ISSUER));
  });

  it('invalid_scope (agent scope-mode cap exceeded) carries `iss`', async () => {
    const { state } = await run({
      client: {
        ...CLIENT,
        clientId: 'agent-ro',
        scopes: ['agent:readonly', 'agent:exec', 'email'],
        isAgent: true,
        maxAgentMode: 'readonly',
      },
      query: { client_id: 'agent-ro', scope: 'agent:exec' },
      consent: { scopes: ['agent:readonly', 'agent:exec', 'email'], revokedAt: null },
    });
    expect(state.redirected).toContain('error=invalid_scope');
    expect(issOf(state.redirected)).toBe(discoveryIssuer(RAW_ISSUER));
  });

  it('prompt=none interaction_required-class errors carry `iss` (OIDC Core §3.1.2.1 path)', async () => {
    // A dangerous scope on a stale session would normally bounce to /ui/login;
    // prompt=none converts that into a bare error redirect, which is still an
    // authorization response and so still needs the mix-up defence.
    const { state } = await run({
      client: { ...CLIENT, clientId: 'app-danger', scopes: ['read:foo', 'write:foo', 'email'] },
      query: { client_id: 'app-danger', scope: 'write:foo', prompt: 'none' },
      session: { authTime: Date.now() - STEP_UP_FRESH_AUTH_WINDOW_MS * 10 },
      consent: { scopes: ['read:foo', 'write:foo', 'email'], revokedAt: null },
    });
    expect(state.redirected).toContain('error=login_required');
    expect(issOf(state.redirected)).toBe(discoveryIssuer(RAW_ISSUER));
  });

  it('emits `iss` VERBATIM — a mixed-case issuer with a port and a path matches discovery byte for byte', async () => {
    // Guards the acceptance criterion directly: whatever shaping discovery
    // applies (trailing-slash strip and nothing else), the redirect applies the
    // same. `new URL(...)` would have lower-cased the host and dropped :443.
    // The realm row holds the issuer without a trailing slash (a CHECK refuses
    // one), the form discovery publishes.
    const RAW = 'https://Auth.EXAMPLE.com:8443/idp';
    const { state } = await run({ realmIssuer: RAW });
    expect(state.redirected).toContain('code=');
    expect(discoveryIssuer(RAW)).toBe(RAW);
    expect(issOf(state.redirected)).toBe(discoveryIssuer(RAW));
  });

  it("emits the request realm's issuer, not JWT_ISSUER (ADR-019 Decision 1, #490)", async () => {
    const { state } = await run({ realmIssuer: 'https://b.example.com' });
    expect(state.redirected).toContain('code=');
    expect(issOf(state.redirected)).toBe('https://b.example.com');
  });

  it("pins a Bearer token to the request realm's issuer (ADR-019 Decision 1, #490)", async () => {
    const { fastify, state } = await run({ bearer: 'valid', realmIssuer: 'https://b.example.com' });
    // The audience is assertManagementToken's to check (#509), so the
    // verification pins only the realm: its keys and its issuer (#491).
    expect(fastify.jwtUtils.verifyAccessToken).toHaveBeenCalledWith(
      { id: REALM.id, issuer: 'https://b.example.com' },
      'bearer.token'
    );
    expect(issOf(state.redirected)).toBe('https://b.example.com');
  });

  it('does NOT attach `iss` to internal /ui redirects (they are not authorization responses)', async () => {
    // /ui/login and /ui/consent are same-origin UI hops, not RFC 6749 §4.1.2
    // responses to the client. Emitting `iss` there would be meaningless noise
    // and would leak into the return_to round-trip.
    const { state } = await run({ session: null });
    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(state.redirected).not.toContain('iss=');
  });
});

/**
 * RFC 9700 §4.11.2 ("Authorization Server as Open Redirector"): the AS may
 * redirect automatically only to a redirect URI it trusts. Only a client an
 * operator provisioned carries that trust (`provisioned_by_operator`,
 * ANT-2026-O8U3P920). A client created through open Dynamic Client
 * Registration, materialised from a CIMD document, or created by a
 * self-registered developer through `POST /api/clients` registered its
 * redirect URI itself; an exact match against that registration says nothing
 * about where the URI leads. Error responses that would leave the issuer with
 * no QAuth page shown are therefore shown on the issuer, with the way back,
 * for such a client — at any age. Operator-provisioned clients keep the
 * automatic redirect OpenID Connect requires.
 */
describe('GET /oauth/authorize — error responses for clients no operator provisioned (RFC 9700 §4.11.2)', () => {
  const ATTACKER_CB = 'https://login-qauth.attacker.example/sign-in';
  const DCR_CLIENT = {
    ...CLIENT,
    clientId: 'dcr-client',
    redirectUris: [ATTACKER_CB],
    provisionedByOperator: false,
    // Long past DYNAMIC_CLIENT_BADGE_DAYS: who registered it has not changed.
    dynamicRegisteredAt: Date.now() - 400 * 24 * 60 * 60 * 1000,
    metadata: { registrationType: 'dynamic' },
  };
  // What `POST /api/clients` writes for an account anyone can open: no DCR or
  // CIMD marker at all, which the earlier rule read as trusted.
  const DEVELOPER_CLIENT = {
    ...CLIENT,
    clientId: '0190a000-0000-7000-8000-0000000000d1',
    redirectUris: [ATTACKER_CB],
    provisionedByOperator: false,
    developerId: '0190a000-0000-7000-8000-00000000000a',
    dynamicRegisteredAt: null,
    metadata: null,
  };
  // A CIMD client is covered in the CIMD suite above, which resolves a real
  // document through the (mocked) network layer.

  async function run(
    client: Record<string, unknown>,
    opts: { prompt?: string; session?: boolean; scope?: string; consent?: unknown } = {}
  ) {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(
      opts.consent
    );
    const headers: Record<string, string> = {};
    if (opts.session) {
      const { cookie } = await sessions.signIn({
        sid: 'sid-untrusted',
        realmId: REALM.id,
        userId: 'user-1',
      });
      headers['cookie'] = cookie;
    }
    const query = {
      ...BASE_QUERY,
      client_id: client.clientId,
      redirect_uri: (client.redirectUris as string[])[0],
      scope: opts.scope ?? 'email',
      ...(opts.prompt ? { prompt: opts.prompt } : {}),
    };
    const { reply, state } = createReply();
    await ctx.handler!(
      { query, url: '/oauth/authorize?response_type=code', headers, ip: '127.0.0.1' },
      reply
    );
    return { fastify, state };
  }

  function expectShownNotRedirected(
    state: { statusCode?: number; redirected?: string; body?: unknown },
    error: string
  ) {
    expect(state.redirected).toBeUndefined();
    expect(state.statusCode).toBe(400);
    const body = state.body as string;
    expect(body).toContain(`<code>${error}</code>`);
    expect(body).toContain('login-qauth.attacker.example');
  }

  it('prompt=none with no session: a dynamically registered client gets login_required on the issuer, not a 302', async () => {
    const { state } = await run(DCR_CLIENT, { prompt: 'none' });
    expectShownNotRedirected(state, 'login_required');
  });

  it('prompt=none with no session: a client a developer created through POST /api/clients gets login_required on the issuer, not a 302', async () => {
    const { state } = await run(DEVELOPER_CLIENT, { prompt: 'none' });
    expectShownNotRedirected(state, 'login_required');
  });

  it('prompt=none with a session but no consent: a developer-created client gets consent_required on the issuer', async () => {
    const { state } = await run(DEVELOPER_CLIENT, { prompt: 'none', session: true });
    expectShownNotRedirected(state, 'consent_required');
  });

  it('a client with no provisioning marker at all is not trusted (fail closed)', async () => {
    const { provisionedByOperator: _omitted, ...unmarked } = CLIENT;
    const { state } = await run(
      { ...unmarked, redirectUris: [ATTACKER_CB] } as Record<string, unknown>,
      { prompt: 'none' }
    );
    expectShownNotRedirected(state, 'login_required');
  });

  it('prompt=none with no session: an operator-provisioned client keeps the OIDC redirect', async () => {
    const { state } = await run(CLIENT, { prompt: 'none' });
    expect(state.statusCode).toBe(302);
    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('error=login_required');
    // No user is signed in: the requesting client is the actor.
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:step_up.required:v1-rc.0',
      { reason: 'prompt_none_no_session', error: 'login_required' },
      { realmId: 'realm-1', clientId: CLIENT.clientId, actor: 'client' }
    );
  });

  it('prompt=none with a session but no consent: consent_required is shown, not redirected', async () => {
    const { state } = await run(DCR_CLIENT, { prompt: 'none', session: true });
    expectShownNotRedirected(state, 'consent_required');
  });

  it('agent scope-mode refusal with a session: invalid_scope is shown, not redirected', async () => {
    const { fastify, state } = await run(
      { ...DCR_CLIENT, scopes: ['agent:exec', 'email'] },
      { session: true, scope: 'agent:exec' }
    );
    expectShownNotRedirected(state, 'invalid_scope');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('the interactive path is unchanged: no session goes to the login page', async () => {
    const { state } = await run(DCR_CLIENT);
    expect(state.redirected).toContain('/ui/login?return_to=');
  });
});

/**
 * Regression suite for qauth-labs/qauth#316 — long opaque `state` / `nonce`.
 *
 * `state` and `nonce` are opaque, client-owned params: RFC 6749 §4.1.1 and OIDC
 * Core place NO length limit on them and they are round-tripped to the client
 * verbatim. QAuth capped them at 255 in THREE independent places, so fixing one
 * only moved the failure to the next step of the SAME flow:
 *
 *   1. this route's `authorizeQuerySchema` (400 "querystring/state Too big")
 *   2. the /ui/consent form mirror  (400 "body/state Too big")  — consent.test.ts
 *   3. `authorization_codes.state`/`.nonce` varchar(255) (500 at code-mint)
 *      — covered in libs/infra/db repositories.integration.test.ts, since this
 *        harness mocks the repositories and therefore cannot observe the DDL.
 *
 * The bug was INTERMITTENT: Cursor's MCP client base64url-encodes workspace
 * context into `state`, which lands ~275 chars with a workspace open but under
 * 255 with an empty window. LONG_STATE below reproduces the over-cap shape.
 */
describe('GET /oauth/authorize — long opaque state/nonce (#316)', () => {
  /**
   * A realistic Cursor-shaped `state`: base64url of a JSON blob carrying
   * workspace + attempt context. 282 chars — comfortably over the old 255 cap
   * and comfortably under OAUTH_OPAQUE_PARAM_MAX_LENGTH.
   */
  const LONG_STATE = Buffer.from(
    JSON.stringify({
      id: 7,
      owner: { workspaceId: '9f2c1ab47de35608b1e4c7a09d5f3e21' },
      attemptId: '3f6c2b18-9d47-4e5a-b0c1-7e2f8a4d9b63',
      surface: 'mcp_process',
      redirect: 'cursor://anysphere.cursor-mcp/oauth/user-qauth/callback',
    })
  ).toString('base64url');

  /** A long OIDC `nonce`, same over-255 territory, different value. */
  const LONG_NONCE = 'n'.repeat(300);

  /** Drive the authorize handler with an existing consent so a code is minted. */
  async function mintWith(query: Record<string, unknown>) {
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email', 'read:foo'],
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({
      sid: 'sid-316',
      realmId: REALM.id,
      userId: 'user-1',
    });

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query,
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );
    return { fastify, state };
  }

  it('the fixture state is genuinely over the old 255-char cap', () => {
    // Guards the guard: if LONG_STATE ever shrank under 255 this whole suite
    // would pass vacuously against a reintroduced varchar(255).
    expect(LONG_STATE.length).toBeGreaterThan(255);
    expect(LONG_STATE.length).toBeLessThan(OAUTH_OPAQUE_PARAM_MAX_LENGTH);
  });

  it('site 1: authorizeQuerySchema accepts a ~280-char state and a 300-char nonce', () => {
    // Fastify validates the querystring with this exact schema before the
    // handler runs, so the schema — not the handler — is the failure site.
    const parsed = authorizeQuerySchema.parse({
      ...BASE_QUERY,
      state: LONG_STATE,
      nonce: LONG_NONCE,
    });
    // Verbatim: no truncation, no re-encoding.
    expect(parsed.state).toBe(LONG_STATE);
    expect(parsed.nonce).toBe(LONG_NONCE);
  });

  it('site 1: authorizeQuerySchema still rejects state/nonce over the DoS bound', () => {
    // The 2048 cap is a DoS guard, not a spec limit — it must stay enforced.
    const tooLong = 'x'.repeat(OAUTH_OPAQUE_PARAM_MAX_LENGTH + 1);
    expect(authorizeQuerySchema.safeParse({ ...BASE_QUERY, state: tooLong }).success).toBe(false);
    expect(authorizeQuerySchema.safeParse({ ...BASE_QUERY, nonce: tooLong }).success).toBe(false);
    // And exactly at the bound it is still accepted (off-by-one guard).
    const atBound = 'x'.repeat(OAUTH_OPAQUE_PARAM_MAX_LENGTH);
    expect(authorizeQuerySchema.safeParse({ ...BASE_QUERY, state: atBound }).success).toBe(true);
  });

  it('persists the full state/nonce onto the code and round-trips state VERBATIM', async () => {
    const { fastify, state } = await mintWith({
      ...BASE_QUERY,
      state: LONG_STATE,
      nonce: LONG_NONCE,
      scope: 'email',
    });

    // Site 3 boundary: the values handed to the repository are untruncated.
    // (The varchar(255) DDL that used to reject them lives in infra-db and is
    // asserted against real Postgres in repositories.integration.test.ts.)
    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.state).toBe(LONG_STATE);
    expect(createArg.nonce).toBe(LONG_NONCE);

    // RFC 6749 §4.1.2: the client gets its `state` back byte for byte.
    const redirected = new URL(state.redirected as string);
    expect(redirected.searchParams.get('state')).toBe(LONG_STATE);
    expect(redirected.searchParams.get('code')).toBeTruthy();
  });

  it('carries the full state through the /ui/consent hop when consent is required', async () => {
    // The consent round-trip is where the flow used to die one step later: the
    // authorize query schema accepted the value, then the form mirror rejected
    // it. The return query must carry the state whole for that hop to work.
    const { fastify, ctx, sessions } = makeFastify();
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(undefined);
    const { cookie } = await sessions.signIn({
      sid: 'sid-316c',
      realmId: REALM.id,
      userId: 'user-1',
    });

    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, state: LONG_STATE, nonce: LONG_NONCE, scope: 'email' },
        url: `/oauth/authorize?response_type=code&client_id=app-123&scope=email&state=${encodeURIComponent(
          LONG_STATE
        )}&nonce=${LONG_NONCE}`,
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('/ui/consent?');
    const consentUrl = new URL(state.redirected as string, 'https://auth.example.com');
    expect(consentUrl.searchParams.get('state')).toBe(LONG_STATE);
    expect(consentUrl.searchParams.get('nonce')).toBe(LONG_NONCE);
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });
});

describe('GET /oauth/authorize — dpop_jkt binds the code to a DPoP key (RFC 9449 §10, #480)', () => {
  const JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';

  /** A signed-in user whose stored consent covers the request, so a code is minted. */
  async function issueCode(dpopOn: boolean, dpopJkt: unknown) {
    const { fastify, ctx, sessions } = makeFastify();
    (fastify as unknown as { dpop: unknown }).dpop = dpopOn
      ? { algorithms: ['ES256'], verifyRequest: vi.fn() }
      : null;
    await authorizeRoute(fastify);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    (fastify.jwtUtils.extractFromHeader as unknown as Mock).mockReturnValue(null);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      scopes: ['email', 'read:foo'],
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({
      sid: 'sid-dpop',
      realmId: REALM.id,
      userId: 'user-1',
    });
    const { reply, state } = createReply();
    await ctx.handler!(
      {
        query: { ...BASE_QUERY, dpop_jkt: dpopJkt },
        url: '/oauth/authorize?response_type=code&client_id=app-123&scope=email',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );
    return { fastify, state };
  }

  it('stores the thumbprint on the code while DPoP is on', async () => {
    const { fastify, state } = await issueCode(true, JKT);
    const [created] = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0];
    expect(created.dpopJkt).toBe(JKT);
    expect(state.redirected).toContain('code=');
  });

  it('refuses a dpop_jkt that is not a SHA-256 thumbprint, before any code is minted', async () => {
    const { fastify, state } = await issueCode(true, 'not-a-thumbprint');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(state.redirected).toContain('error=invalid_request');
    expect(state.redirected).toContain('state=xyz');
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'invalid_request', reason: 'dpop_jkt_malformed' },
      expect.objectContaining({ clientId: CLIENT.clientId })
    );
  });

  it('reads no dpop_jkt while DPoP is off: the code is unbound, whatever the value', async () => {
    // Before DPoP the schema stripped the parameter, so a repeated one or one
    // of any length went through; with DPoP off it still does.
    for (const value of [JKT, 'not-a-thumbprint', [JKT, JKT], 'x'.repeat(5000)]) {
      const { fastify, state } = await issueCode(false, value);
      const [created] = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
        .calls[0];
      expect(created.dpopJkt).toBeNull();
      expect(state.redirected).toContain('code=');
    }
  });
});
