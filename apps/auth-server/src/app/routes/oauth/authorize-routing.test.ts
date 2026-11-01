import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createBrowserSessionFixture } from '../../../testing/browser-sessions';
import { supplyRequestRealm, testRealm } from '../../../testing/request-realm';
import { emitUserEvent } from '../../helpers/user-events';

/**
 * Routing-level regressions for `/oauth/authorize` (issue #316 follow-up).
 *
 * Every other authorize test drives the handler function directly through a
 * hand-rolled Fastify double, which by construction cannot observe ROUTER
 * behaviour. That blind spot hid a real one: `main.ts` starts Fastify with
 * `routerOptions.ignoreTrailingSlash: true`, so `GET /oauth/authorize/?…`
 * matches the route and `request.url` keeps the trailing slash. Any code that
 * compares `request.url` byte-exactly against `/oauth/authorize` therefore sees
 * a path the router deliberately accepted and rejects it — which turned the
 * unauthenticated entry point of the whole OAuth flow into a 500.
 *
 * These tests boot a REAL Fastify with the same `routerOptions` as `main.ts`
 * and inject real requests, so the router is in the loop.
 */

vi.mock('../../../config/env', () => ({
  env: {
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_LIMIT_LENIENT: 600,
    AUTHORIZE_RATE_WINDOW: 60,
    DEFAULT_REALM_NAME: 'master',
    SYSTEM_CLIENT_ID: 'system',
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
    CIMD_ENABLED: false,
    CIMD_TRUST_POLICY: 'accept-any-https',
    CIMD_TRUSTED_DOMAINS: [],
    CIMD_CACHE_DEFAULT_TTL: 300,
    CIMD_CACHE_MAX_TTL: 3600,
    CIMD_MAX_DOCUMENT_BYTES: 65536,
    CIMD_FETCH_TIMEOUT_MS: 5000,
  },
}));

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

const emitUserEventMock = vi.mocked(emitUserEvent);

beforeEach(() => {
  emitUserEventMock.mockClear();
});

import authorizeRoute from './authorize';

const REALM = testRealm({ id: 'realm-1' });

const CLIENT = {
  id: 'client-uuid-1',
  clientId: 'app-123',
  clientSecretHash: 'h',
  name: 'Test App',
  enabled: true,
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  scopes: ['email'],
  audience: null,
  redirectUris: ['https://example.com/cb'],
  dynamicRegisteredAt: null,
  // An operator-provisioned client: the only kind whose redirect URI receives
  // authorization errors by automatic redirect (ANT-2026-O8U3P920).
  provisionedByOperator: true,
  metadata: null,
};

const QUERY = new URLSearchParams({
  response_type: 'code',
  client_id: 'app-123',
  redirect_uri: 'https://example.com/cb',
  code_challenge: 'A'.repeat(43),
  code_challenge_method: 'S256',
  scope: 'email',
  state: 'st-1',
}).toString();

let server: FastifyInstance | undefined;
let sessions: ReturnType<typeof createBrowserSessionFixture>;

async function buildServer(): Promise<FastifyInstance> {
  sessions = createBrowserSessionFixture();
  // Same router configuration as apps/auth-server/src/main.ts.
  const fastify = Fastify({ logger: false, routerOptions: { ignoreTrailingSlash: true } });
  fastify.setValidatorCompiler(validatorCompiler);
  fastify.setSerializerCompiler(serializerCompiler);

  const findActive = vi.fn();
  fastify.decorate('repositories', {
    oauthClients: { findByClientId: vi.fn().mockResolvedValue(CLIENT) },
    oauthConsents: {
      findActive,
      // The locked re-read before the code insert sees what the first read saw.
      findActiveForShare: vi.fn((userId: string, oauthClientId: string) =>
        findActive(userId, oauthClientId)
      ),
      upsertGrant: vi.fn(),
    },
    authorizationCodes: { create: vi.fn() },
    // The session path accepts only a user who is still enabled, of this realm.
    users: {
      findById: vi.fn(async (_realmId: string, id: string) => ({
        id,
        enabled: true,
        realmId: REALM.id,
      })),
    },
    // The client registry (#549): the session is live under the code's
    // transaction.
    sessions: { recordClient: vi.fn().mockResolvedValue(true) },
  } as never);
  // A nested `transaction()` is a savepoint of the same transaction.
  const tx = { transaction: (cb: (inner: unknown) => Promise<unknown>) => cb(tx) };
  fastify.decorate('db', {
    transaction: vi.fn(async (cb: (tx: unknown) => Promise<unknown>) => cb(tx)),
  } as never);
  fastify.decorate('jwtUtils', {
    extractFromHeader: vi.fn().mockReturnValue(null),
    verifyAccessToken: vi.fn(),
  } as never);
  fastify.decorate('sessionService', sessions.service as never);
  // The session cookie is verified with the realm cookie key the signer
  // hands out (#493).
  fastify.decorate('signer', sessions.signer as never);
  fastify.decorate('redis', sessions.redis as never);
  fastify.decorate('sessionUtils', {
    getSession: vi.fn().mockResolvedValue(null),
    setSession: vi.fn().mockResolvedValue(undefined),
    deleteSession: vi.fn().mockResolvedValue(undefined),
  } as never);

  supplyRequestRealm(fastify, REALM);
  await fastify.register(authorizeRoute, { prefix: '/oauth' });
  await fastify.ready();
  return fastify;
}

afterEach(async () => {
  await server?.close();
  server = undefined;
});

describe('GET /oauth/authorize routing', () => {
  it('bounces an unauthenticated request to the login page', async () => {
    server = await buildServer();
    const response = await server.inject({ method: 'GET', url: `/oauth/authorize?${QUERY}` });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toMatch(/^\/ui\/login\?return_to=/);
  });

  it('bounces identically when the path carries a trailing slash', async () => {
    // `ignoreTrailingSlash: true` routes this to the same handler with
    // `request.url === '/oauth/authorize/?…'`. Before the normalization fix the
    // stash rejected that URL and the request 500'd — an unauthenticated 500 on
    // the most common path in the whole server.
    server = await buildServer();
    const response = await server.inject({ method: 'GET', url: `/oauth/authorize/?${QUERY}` });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toMatch(/^\/ui\/login\?return_to=/);
  });

  it('returns login_required for an unauthenticated prompt=none instead of showing UI', async () => {
    // OIDC Core §3.1.2.1: `prompt=none` forbids any user-facing UI. These
    // requests come from a hidden silent-renewal iframe, where a redirect to
    // the login page renders a form nobody can see and the client just hangs.
    // It also stopped a logged-out client's renewal polling from writing a
    // pending-authorization stash on every poll.
    server = await buildServer();
    const response = await server.inject({
      method: 'GET',
      url: `/oauth/authorize?${QUERY}&prompt=none`,
    });

    expect(response.statusCode).toBe(302);
    const location = response.headers.location as string;
    expect(location.startsWith('https://example.com/cb')).toBe(true);
    expect(location).toContain('error=login_required');
    expect(location).toContain('state=st-1');
    expect(location).not.toContain('/ui/login');

    const setSession = (
      server as unknown as { sessionUtils: { setSession: ReturnType<typeof vi.fn> } }
    ).sessionUtils.setSession;
    expect(setSession).not.toHaveBeenCalled();
  });

  it('never redirects a self-registered client automatically from prompt=none (RFC 9700 §4.11.2)', async () => {
    // One anonymous POST /oauth/register used to turn this link into an open
    // redirector on the issuer's origin.
    server = await buildServer();
    const clients = (
      server as unknown as {
        repositories: { oauthClients: { findByClientId: ReturnType<typeof vi.fn> } };
      }
    ).repositories.oauthClients;
    clients.findByClientId.mockResolvedValue({
      ...CLIENT,
      provisionedByOperator: false,
      dynamicRegisteredAt: Date.now(),
      metadata: { registrationType: 'dynamic' },
    });

    const response = await server.inject({
      method: 'GET',
      url: `/oauth/authorize?${QUERY}&prompt=none`,
    });

    expect(response.statusCode).toBe(400);
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['content-type']).toContain('text/html');
    expect(response.body).toContain('<code>login_required</code>');
  });

  it('stashes the CANONICAL authorize path, so the resume redirect is slash-free', async () => {
    server = await buildServer();
    await server.inject({ method: 'GET', url: `/oauth/authorize/?${QUERY}` });

    const setSession = (
      server as unknown as { sessionUtils: { setSession: ReturnType<typeof vi.fn> } }
    ).sessionUtils.setSession;
    const stashed = setSession.mock.calls[0]?.[1] as { authorizeUrl: string };
    expect(stashed.authorizeUrl.startsWith('/oauth/authorize?')).toBe(true);
    // Every parameter still survives the normalization.
    expect(new URL(stashed.authorizeUrl, 'http://placeholder').searchParams.get('state')).toBe(
      'st-1'
    );
  });
});

describe('GET /oauth/authorize resource binding (RFC 8707)', () => {
  /**
   * A signed-in browser whose stored consent covers the request: the
   * shortest route to a minted code in this harness.
   */
  async function injectWithSession(url: string) {
    server = await buildServer();
    const doubles = server as unknown as {
      repositories: {
        authorizationCodes: { create: ReturnType<typeof vi.fn> };
        oauthConsents: { findActive: ReturnType<typeof vi.fn> };
      };
    };
    doubles.repositories.oauthConsents.findActive.mockResolvedValue({
      scopes: ['email'],
      // RFC 8707: the grant covers the resources these tests bind.
      resourceScopes: {
        'https://api.example.com/mcp': ['email'],
        'https://api2.example.com/mcp': ['email'],
      },
      revokedAt: null,
    });
    const { cookie } = await sessions.signIn({
      realmId: REALM.id,
      userId: '0190a5c8-0000-7000-8000-000000000001',
    });
    const response = await server.inject({ method: 'GET', url, headers: { cookie } });
    return { response, createCode: doubles.repositories.authorizationCodes.create };
  }

  it('binds the validated resource: the real validator does populate request.query', async () => {
    // The handler used to re-parse `request.url` on the belief that
    // fastify-type-provider-zod drops a union + transform field from
    // `request.query`. It does not; this pins that down with the real compiler.
    const { response, createCode } = await injectWithSession(
      `/oauth/authorize?${QUERY}&resource=https%3A%2F%2Fapi.example.com%2Fmcp`
    );

    expect(response.statusCode).toBe(302);
    expect(createCode.mock.calls[0]?.[0]).toMatchObject({
      resource: ['https://api.example.com/mcp'],
    });
  });

  it('binds every value of a repeated resource', async () => {
    const { response, createCode } = await injectWithSession(
      `/oauth/authorize?${QUERY}` +
        '&resource=https%3A%2F%2Fapi.example.com%2Fmcp&resource=https%3A%2F%2Fapi2.example.com%2Fmcp'
    );

    expect(response.statusCode).toBe(302);
    expect(createCode.mock.calls[0]?.[0]).toMatchObject({
      resource: ['https://api.example.com/mcp', 'https://api2.example.com/mcp'],
    });
  });

  it('rejects a resource that is not an absolute URI', async () => {
    const { response, createCode } = await injectWithSession(
      `/oauth/authorize?resource=system&${QUERY}`
    );

    expect(response.statusCode).toBe(400);
    expect(createCode).not.toHaveBeenCalled();
  });

  it('never binds a resource the querystring schema did not see (`??resource=`)', async () => {
    // Fastify's parser names this key `?resource`, which the schema strips as
    // unknown; `URLSearchParams` drops the leading `?` and names it `resource`.
    // `system` was the audience of the first-party token `/auth/login` minted
    // before #524, so binding it handed a third-party client a token the
    // retired Bearer path accepted.
    const { response, createCode } = await injectWithSession(
      `/oauth/authorize??resource=system&${QUERY}`
    );

    expect(response.statusCode).toBe(302);
    expect(createCode.mock.calls[0]?.[0]).toMatchObject({ resource: [] });
  });
});

describe('/oauth/authorize — the retired Bearer path (#524)', () => {
  // The developer portal's token no longer stands in for a browser session
  // here: a request with only an `Authorization` header signs in first, and
  // the token is never read.
  it.each(['GET', 'POST'] as const)(
    '%s with only a Bearer token goes to the login page and mints nothing',
    async (method) => {
      server = await buildServer();
      const doubles = server as unknown as {
        jwtUtils: {
          extractFromHeader: ReturnType<typeof vi.fn>;
          verifyAccessToken: ReturnType<typeof vi.fn>;
        };
        repositories: { authorizationCodes: { create: ReturnType<typeof vi.fn> } };
      };
      doubles.jwtUtils.extractFromHeader.mockReturnValue('token');
      const headers = { authorization: 'Bearer token' };

      const response =
        method === 'GET'
          ? await server.inject({ method, url: `/oauth/authorize?${QUERY}`, headers })
          : await server.inject({
              method,
              url: '/oauth/authorize',
              // This harness registers no form parser; the handler reads the
              // validated body the same way whatever its content type.
              headers: { ...headers, 'content-type': 'application/json' },
              payload: Object.fromEntries(new URLSearchParams(QUERY)),
            });

      expect(response.statusCode).toBe(302);
      expect(response.headers.location).toMatch(/^\/ui\/login\?return_to=/);
      expect(doubles.jwtUtils.verifyAccessToken).not.toHaveBeenCalled();
      expect(doubles.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    }
  );
});

describe('POST /oauth/authorize routing', () => {
  it('bounces identically when the path carries a trailing slash', async () => {
    // `buildAuthorizeUrlWithParams` reconstructs the URL from
    // `request.url.split('?')[0]`, which yields `/oauth/authorize/` here.
    server = await buildServer();
    const response = await server.inject({
      method: 'POST',
      url: '/oauth/authorize/',
      headers: { 'content-type': 'application/json' },
      payload: {
        response_type: 'code',
        client_id: 'app-123',
        redirect_uri: 'https://example.com/cb',
        code_challenge: 'A'.repeat(43),
        code_challenge_method: 'S256',
        scope: 'email',
        state: 'st-1',
      },
    });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toMatch(/^\/ui\/login\?return_to=/);
  });
});
