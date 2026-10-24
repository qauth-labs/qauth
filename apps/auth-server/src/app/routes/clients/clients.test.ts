import {
  BadRequestError,
  ForbiddenError,
  JWTInvalidError,
  NotFoundError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

// The create route transitively imports `helpers/realm` → `config/env`, which
// validates required env at module load. Stub it so the unit run needs no real
// environment (matches `routes/oauth/register.test.ts`).
vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    DEFAULT_REALM_NAME: 'master',
    REGISTER_CLIENT_RATE_LIMIT: 30,
    REGISTER_CLIENT_RATE_WINDOW: 60,
    DEFAULT_DYNAMIC_REGISTRATION_SCOPES: ['openid', 'profile', 'email', 'offline_access'],
    MAX_CLIENTS_PER_DEVELOPER: 3,
    REDIRECT_URI_CUSTOM_SCHEMES: [] as string[],
  },
}));

// The management-token guard has its own tests (helpers/management-token.test.ts).
// Here it is a seam: every route must be registered behind exactly this guard.
const { managementGuard } = vi.hoisted(() => ({ managementGuard: vi.fn() }));
vi.mock('../../helpers/management-token', () => ({
  createRequireManagementJwt: () => managementGuard,
}));

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

import { env } from '../../../config/env';
import { emitUserEvent } from '../../helpers/user-events';
import clientsRoute, { autoPrefix } from './index';

const emitUserEventMock = vi.mocked(emitUserEvent);

beforeEach(() => {
  emitUserEventMock.mockClear();
});

type RouteHandler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>;
interface RouteOptions {
  preHandler?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  config?: {
    rateLimit?: {
      max?: number;
      timeWindow?: number;
      keyGenerator?: (req: { ip?: string }) => string;
    };
  };
}
interface RegisteredRoute {
  handler: RouteHandler;
  options: RouteOptions;
}

interface TestContext {
  // The list route (GET /) — preserved for the original #85 tests.
  handler?: RouteHandler;
  options?: RouteOptions;
  // Every registered route keyed by `METHOD path`, e.g. `POST /` or `GET /:id`.
  routes: Map<string, RegisteredRoute>;
}

// `oauth_clients.developer_id` is a UUID column and a user token's `sub` is a
// UUID `users.id`, so the developer subjects in these tests must be UUIDs.
const DEV_A = '0190a000-0000-7000-8000-00000000000a';
const DEV_B = '0190a000-0000-7000-8000-00000000000b';

function createReply() {
  const state: { statusCode?: number; body?: unknown; headers: Record<string, string> } = {
    headers: {},
  };
  const reply: any = {
    code(n: number) {
      state.statusCode = n;
      return reply;
    },
    header(name: string, value: string) {
      state.headers[name.toLowerCase()] = value;
      return reply;
    },
    send(body: unknown) {
      state.body = body;
      return body;
    },
  };
  return { reply: reply as FastifyReply, state };
}

function makeFastify() {
  const ctx: TestContext = { routes: new Map() };
  const register = (method: string) => (url: string, opts: RouteOptions, handler: RouteHandler) => {
    ctx.routes.set(`${method} ${url}`, { handler, options: opts });
    // Preserve the original single-handler contract for the GET / route so
    // the issue-#85 list tests keep working unchanged.
    if (method === 'GET' && url === '/') {
      ctx.handler = handler;
      ctx.options = opts;
    }
    return chain;
  };
  const chain: any = {
    get: register('GET'),
    post: register('POST'),
    patch: register('PATCH'),
    delete: register('DELETE'),
  };
  const fastify: any = {
    withTypeProvider: () => chain,
    requireJwt: vi.fn(),
    passwordHasher: {
      hashPassword: vi.fn(async (secret: string) => `argon2id$hash-of-${secret.slice(0, 8)}`),
    },
    repositories: {
      oauthClients: {
        listByDeveloper: vi.fn(),
        countByDeveloper: vi.fn(async () => 0),
        findById: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
      },
      realms: {
        // Realm already carries a seeded allowlist so scope-cap tests are
        // deterministic and don't depend on the env-seeding write path.
        findByName: vi.fn(async () => ({
          id: 'realm-1',
          name: 'default',
          enabled: true,
          maxEnvironmentLaxity: 'development',
          dynamicRegistrationAllowedScopes: ['openid', 'profile', 'email', 'offline_access'],
        })),
        findById: vi.fn(async () => ({
          id: 'realm-1',
          name: 'default',
          enabled: true,
          maxEnvironmentLaxity: 'development',
          dynamicRegistrationAllowedScopes: ['openid', 'profile', 'email', 'offline_access'],
        })),
        update: vi.fn(),
        create: vi.fn(),
      },
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

/** Look up a registered route handler by `METHOD path`. */
function route(ctx: TestContext, key: string): RegisteredRoute {
  const r = ctx.routes.get(key);
  if (!r) throw new Error(`route not registered: ${key}`);
  return r;
}

function authedRequest(overrides: Record<string, unknown> = {}): FastifyRequest {
  return {
    jwtPayload: { sub: DEV_A },
    headers: { authorization: 'Bearer token', 'user-agent': 'vitest' },
    ip: '127.0.0.1',
    ...overrides,
  } as unknown as FastifyRequest;
}

/**
 * Build a representative oauth_clients row. The secret hash is present so the
 * tests can assert it never leaks into the response.
 */
function makeClientRow(overrides: Record<string, unknown> = {}) {
  return {
    id: '0190a000-0000-7000-8000-000000000001',
    realmId: 'realm-1',
    clientId: 'app-123',
    clientSecretHash: 'argon2id$super-secret-hash',
    name: 'My App',
    description: 'desc',
    redirectUris: ['https://app.example.com/cb'],
    scopes: ['openid', 'email'],
    audience: null,
    environment: 'development',
    enabled: true,
    requirePkce: true,
    tokenEndpointAuthMethod: 'client_secret_post',
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    developerId: 'dev-A',
    suspended: false,
    suspendedAt: null,
    dynamicRegisteredAt: null,
    metadata: null,
    createdAt: 1700,
    updatedAt: 1700,
    lastUsedAt: null,
    ...overrides,
  };
}

describe('GET /api/clients route', () => {
  it('is mounted under the /api/clients prefix', () => {
    expect(autoPrefix).toBe('/api/clients');
  });

  it('registers the management-token guard as the preHandler (401 for any other token)', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    expect(ctx.handler).toBeDefined();
    expect(ctx.options?.preHandler).toBe(managementGuard);
  });

  it('puts EVERY client-management route behind the management-token guard', async () => {
    // requireJwt alone accepts any token this server issued for the user,
    // including one issued to a third-party client. No route may fall back to it.
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    expect(ctx.routes.size).toBeGreaterThan(0);
    for (const [key, registered] of ctx.routes) {
      expect(registered.options.preHandler, key).toBe(managementGuard);
    }
  });

  it('lists the authenticated developer clients with safe fields only (no secret)', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.listByDeveloper as unknown as Mock).mockResolvedValue([
      makeClientRow(),
    ]);

    const request = {
      jwtPayload: { sub: DEV_A },
      headers: { authorization: 'Bearer token' },
    } as unknown as FastifyRequest;
    const { reply, state } = createReply();

    await ctx.handler!(request, reply);

    expect(fastify.repositories.oauthClients.listByDeveloper).toHaveBeenCalledWith(DEV_A);
    expect(state.body).toEqual({
      clients: [
        {
          id: '0190a000-0000-7000-8000-000000000001',
          clientId: 'app-123',
          name: 'My App',
          description: 'desc',
          redirectUris: ['https://app.example.com/cb'],
          scopes: ['openid', 'email'],
          grantTypes: ['authorization_code', 'refresh_token'],
          responseTypes: ['code'],
          tokenEndpointAuthMethod: 'client_secret_post',
          enabled: true,
          suspended: false,
          requirePkce: true,
          environment: 'development',
          staticApiKeysAllowed: true,
          createdAt: 1700,
          updatedAt: 1700,
          lastUsedAt: null,
        },
      ],
    });

    // The secret hash must never be serialized.
    const serialized = JSON.stringify(state.body);
    expect(serialized).not.toContain('clientSecretHash');
    expect(serialized).not.toContain('argon2id$super-secret-hash');
  });

  it('returns an empty list when the developer owns no clients', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.listByDeveloper as unknown as Mock).mockResolvedValue([]);

    const request = {
      jwtPayload: { sub: DEV_A },
      headers: { authorization: 'Bearer token' },
    } as unknown as FastifyRequest;
    const { reply, state } = createReply();

    await ctx.handler!(request, reply);

    expect(state.body).toEqual({ clients: [] });
  });

  it('scopes the query to the caller so developer A cannot see developer B clients', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    // The repository is the isolation boundary: it is queried with the
    // caller's own developer id and returns only that developer's rows.
    (fastify.repositories.oauthClients.listByDeveloper as unknown as Mock).mockImplementation(
      async (developerId: string) =>
        developerId === DEV_A ? [makeClientRow({ developerId: DEV_A })] : []
    );

    // Developer B is authenticated and must not receive developer A's client.
    const request = {
      jwtPayload: { sub: DEV_B },
      headers: { authorization: 'Bearer token' },
    } as unknown as FastifyRequest;
    const { reply, state } = createReply();

    await ctx.handler!(request, reply);

    expect(fastify.repositories.oauthClients.listByDeveloper).toHaveBeenCalledWith(DEV_B);
    expect(fastify.repositories.oauthClients.listByDeveloper).not.toHaveBeenCalledWith(DEV_A);
    expect(state.body).toEqual({ clients: [] });
  });

  it('returns an empty list without querying when sub is not a UUID (client_credentials token)', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    // A client_credentials access token carries `sub === client_id`, an opaque
    // varchar rather than a UUID. Querying the UUID `developer_id` column with
    // it would raise Postgres 22P02 and surface as a 500, so the handler must
    // short-circuit to an empty list and never reach the repository.
    const request = {
      jwtPayload: { sub: 'app-123' },
      headers: { authorization: 'Bearer token' },
    } as unknown as FastifyRequest;
    const { reply, state } = createReply();

    await ctx.handler!(request, reply);

    expect(state.body).toEqual({ clients: [] });
    expect(fastify.repositories.oauthClients.listByDeveloper).not.toHaveBeenCalled();
  });

  it('throws JWTInvalidError when the jwt payload is missing a sub', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const request = {
      // No jwtPayload — defense-in-depth guard behind requireJwt.
      headers: { authorization: 'Bearer token' },
    } as unknown as FastifyRequest;
    const { reply } = createReply();

    await expect(ctx.handler!(request, reply)).rejects.toThrow(JWTInvalidError);
    expect(fastify.repositories.oauthClients.listByDeveloper).not.toHaveBeenCalled();
  });
});

describe('POST /api/clients (create) — #86', () => {
  it('requires a developer Bearer access token', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    expect(route(ctx, 'POST /').options.preHandler).toBe(managementGuard);
  });

  it('generates client_id + secret, hashes the secret, persists, and returns the plaintext once', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) =>
        makeClientRow({
          ...data,
          id: '0190a000-0000-7000-8000-0000000000c1',
        })
    );

    const request = authedRequest({
      body: {
        name: 'My App',
        redirectUris: ['https://app.example.com/cb'],
        scopes: ['openid'],
        tokenEndpointAuthMethod: 'client_secret_post',
      },
    });
    const { reply, state } = createReply();

    const body = (await route(ctx, 'POST /').handler(request, reply)) as Record<string, unknown>;

    // 201 + plaintext secret present exactly here.
    expect(state.statusCode).toBe(201);
    expect(typeof body.clientSecret).toBe('string');
    expect((body.clientSecret as string).length).toBe(64); // 32 bytes hex

    // developer_id is taken from the token subject, never the body.
    const created = (fastify.repositories.oauthClients.create as unknown as Mock).mock.calls[0][0];
    expect(created.developerId).toBe(DEV_A);
    expect(created.clientId).toMatch(/^[0-9a-f-]{36}$/);
    expect(created.requirePkce).toBe(true);
    // Only the hash is persisted — never the plaintext.
    expect(created.clientSecretHash).not.toBe(body.clientSecret);
    expect(created.clientSecretHash).toContain('argon2id$');

    // Response is not cacheable (carries a secret).
    expect(state.headers['cache-control']).toBe('no-store');

    // The hash must never appear in the response body.
    expect(JSON.stringify(body)).not.toContain('clientSecretHash');
  });

  it("never marks a developer's client operator-provisioned, whatever the body says (ANT-2026-O8U3P920)", async () => {
    // A developer account is self-service, so its client's redirect URI must
    // not receive authorization errors by automatic redirect.
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) => makeClientRow({ ...data })
    );

    const request = authedRequest({
      body: {
        name: 'Phish',
        redirectUris: ['https://login-qauth.attacker.example/sign-in'],
        tokenEndpointAuthMethod: 'none',
        provisionedByOperator: true,
      },
    });
    await route(ctx, 'POST /').handler(request, createReply().reply);

    const created = (fastify.repositories.oauthClients.create as unknown as Mock).mock.calls[0][0];
    expect(created.provisionedByOperator).toBe(false);
  });

  it("never stores a developer's ID-JAG targets (ADR-011, #434 — seed manifest only)", async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) => makeClientRow({ ...data })
    );

    const request = authedRequest({
      body: {
        name: 'Agent',
        tokenEndpointAuthMethod: 'client_secret_basic',
        grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange'],
        responseTypes: [],
        idJagTargets: ['https://as.partner.example'],
        id_jag_targets: ['https://as.partner.example'],
      },
    });
    await route(ctx, 'POST /').handler(request, createReply().reply);

    const created = (fastify.repositories.oauthClients.create as unknown as Mock).mock.calls[0][0];
    expect(created.idJagTargets).toEqual([]);
  });

  it('omits client_secret for a public client (token_endpoint_auth_method=none)', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) => makeClientRow({ ...data })
    );

    const request = authedRequest({
      body: {
        name: 'Public SPA',
        redirectUris: ['https://spa.example.com/cb'],
        tokenEndpointAuthMethod: 'none',
      },
    });
    const { reply } = createReply();

    const body = (await route(ctx, 'POST /').handler(request, reply)) as Record<string, unknown>;

    expect(body.clientSecret).toBeUndefined();
    // A sentinel hash is still stored so the NOT NULL column is satisfied.
    const created = (fastify.repositories.oauthClients.create as unknown as Mock).mock.calls[0][0];
    expect(created.clientSecretHash).toContain('argon2id$');
  });

  it('rejects an invalid (non-loopback http) redirect_uri before persisting', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const request = authedRequest({
      body: { name: 'Bad', redirectUris: ['http://evil.example.com/cb'] },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'POST /').handler(request, reply)).rejects.toThrow(BadRequestError);
    expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
  });

  // Found while fixing the findings of scan qauth-20261015-005: any
  // syntactically valid scheme used to be stored.
  it.each(['javascript:alert(document.domain)', 'data:text/html,hi', 'myapp:/callback'])(
    'rejects the redirect_uri %s on create and on update',
    async (uri) => {
      const { fastify, ctx } = makeFastify();
      await clientsRoute(fastify);

      await expect(
        route(ctx, 'POST /').handler(
          authedRequest({ body: { name: 'Bad', redirectUris: [uri] } }),
          createReply().reply
        )
      ).rejects.toThrow(/^invalid_redirect_uri: unsupported scheme: /);
      expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();

      (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
        makeClientRow({ developerId: DEV_A })
      );
      await expect(
        route(ctx, 'PATCH /:id').handler(
          authedRequest({
            params: { id: '0190a000-0000-7000-8000-000000000001' },
            body: { redirectUris: ['https://app.example.com/cb', uri] },
          }),
          createReply().reply
        )
      ).rejects.toThrow(/^invalid_redirect_uri: unsupported scheme: /);
      expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
    }
  );

  describe('REDIRECT_URI_CUSTOM_SCHEMES (#774)', () => {
    const cursorCallback = 'cursor://anysphere.cursor-mcp/oauth/callback';

    afterEach(() => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = [];
    });

    async function createAndUpdate(uri: string) {
      const { fastify, ctx } = makeFastify();
      await clientsRoute(fastify);
      (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
        async (data: Record<string, unknown>) => makeClientRow({ ...data })
      );
      (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
        makeClientRow({ developerId: DEV_A })
      );
      (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
        async (_id: string, data: Record<string, unknown>) =>
          makeClientRow({ developerId: DEV_A, ...data })
      );
      const create = () =>
        route(ctx, 'POST /').handler(
          authedRequest({ body: { name: 'Native', redirectUris: [uri] } }),
          createReply().reply
        );
      const update = () =>
        route(ctx, 'PATCH /:id').handler(
          authedRequest({
            params: { id: '0190a000-0000-7000-8000-000000000001' },
            body: { redirectUris: ['https://app.example.com/cb', uri] },
          }),
          createReply().reply
        );
      return { fastify, create, update };
    }

    it('refuses a bare scheme on create and on update when the setting is empty', async () => {
      const { fastify, create, update } = await createAndUpdate(cursorCallback);
      await expect(create()).rejects.toThrow(/^invalid_redirect_uri: unsupported scheme: cursor:/);
      await expect(update()).rejects.toThrow(/^invalid_redirect_uri: unsupported scheme: cursor:/);
      expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
      expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
    });

    it('stores a listed bare scheme on create and on update', async () => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = ['cursor'];
      const { fastify, create, update } = await createAndUpdate(cursorCallback);
      await create();
      await update();
      const created = (fastify.repositories.oauthClients.create as unknown as Mock).mock
        .calls[0][0];
      expect(created.redirectUris).toEqual([cursorCallback]);
      const updateArg = (fastify.repositories.oauthClients.update as unknown as Mock).mock
        .calls[0][1];
      expect(updateArg.redirectUris).toEqual(['https://app.example.com/cb', cursorCallback]);
    });

    it('still refuses a bare scheme that is not listed', async () => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = ['cursor'];
      const { fastify, create, update } = await createAndUpdate('myapp:/callback');
      await expect(create()).rejects.toThrow(/^invalid_redirect_uri: unsupported scheme: myapp:/);
      await expect(update()).rejects.toThrow(/^invalid_redirect_uri: unsupported scheme: myapp:/);
      expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
      expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
    });
  });

  it('rejects an inconsistent grant/response-type combination', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const request = authedRequest({
      body: {
        name: 'Inconsistent',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        responseTypes: ['code'],
        tokenEndpointAuthMethod: 'client_secret_post',
      },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'POST /').handler(request, reply)).rejects.toThrow(BadRequestError);
    expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
  });

  it('rejects a client_credentials public client', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const request = authedRequest({
      body: {
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        tokenEndpointAuthMethod: 'none',
      },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'POST /').handler(request, reply)).rejects.toThrow(BadRequestError);
  });

  it('rejects a client_credentials token subject (non-UUID) from creating clients', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const request = authedRequest({
      jwtPayload: { sub: 'app-123' },
      body: { name: 'X', redirectUris: [] },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'POST /').handler(request, reply)).rejects.toThrow(JWTInvalidError);
    expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
  });
});

describe('GET /api/clients/:id (get one) — #87', () => {
  it('returns the owned client with safe fields only', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A })
    );

    const request = authedRequest({ params: { id: '0190a000-0000-7000-8000-000000000001' } });
    const { reply } = createReply();

    const body = (await route(ctx, 'GET /:id').handler(request, reply)) as Record<string, unknown>;

    expect(body.id).toBe('0190a000-0000-7000-8000-000000000001');
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain('clientSecretHash');
    expect(serialized).not.toContain('argon2id$super-secret-hash');
  });

  it('returns 404 (NotFoundError) for a client owned by another developer', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_B })
    );

    const request = authedRequest({ params: { id: '0190a000-0000-7000-8000-000000000001' } });
    const { reply } = createReply();

    await expect(route(ctx, 'GET /:id').handler(request, reply)).rejects.toThrow(NotFoundError);
  });

  it('returns 404 for a non-existent client', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(undefined);

    const request = authedRequest({ params: { id: '0190a000-0000-7000-8000-000000000099' } });
    const { reply } = createReply();

    await expect(route(ctx, 'GET /:id').handler(request, reply)).rejects.toThrow(NotFoundError);
  });

  it('returns 404 without a DB hit for a non-UUID subject', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const request = authedRequest({
      jwtPayload: { sub: 'app-123' },
      params: { id: '0190a000-0000-7000-8000-000000000001' },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'GET /:id').handler(request, reply)).rejects.toThrow(NotFoundError);
    expect(fastify.repositories.oauthClients.findById).not.toHaveBeenCalled();
  });
});

describe('PATCH /api/clients/:id (update) — #88', () => {
  it('updates only the provided fields of an owned client', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A })
    );
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) =>
        makeClientRow({ developerId: DEV_A, ...data })
    );

    const request = authedRequest({
      params: { id: '0190a000-0000-7000-8000-000000000001' },
      body: { name: 'Renamed', enabled: false },
    });
    const { reply } = createReply();

    const body = (await route(ctx, 'PATCH /:id').handler(request, reply)) as Record<
      string,
      unknown
    >;

    const updateArg = (fastify.repositories.oauthClients.update as unknown as Mock).mock
      .calls[0][1];
    expect(updateArg).toEqual({ name: 'Renamed', enabled: false });
    expect(body.name).toBe('Renamed');
    expect(JSON.stringify(body)).not.toContain('clientSecretHash');
  });

  it("lets the owner re-enable a client it disabled (enabled is the owner's switch)", async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A, enabled: false })
    );
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) =>
        makeClientRow({ developerId: DEV_A, ...data })
    );

    const request = authedRequest({
      params: { id: '0190a000-0000-7000-8000-000000000001' },
      body: { enabled: true },
    });
    const body = (await route(ctx, 'PATCH /:id').handler(request, createReply().reply)) as Record<
      string,
      unknown
    >;

    const updateArg = (fastify.repositories.oauthClients.update as unknown as Mock).mock
      .calls[0][1];
    expect(updateArg).toEqual({ enabled: true });
    expect(body.enabled).toBe(true);
  });

  // ANT-2026-DR5XI3LV: an operator's cut-off is `suspended`, which the owner
  // can neither write nor clear here, so re-enabling does not bring a
  // suspended client back.
  it('never writes `suspended`: re-enabling leaves an operator suspension in place', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const suspendedRow = makeClientRow({ developerId: DEV_A, enabled: false, suspended: true });
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(suspendedRow);
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) => ({ ...suspendedRow, ...data })
    );

    const request = authedRequest({
      params: { id: '0190a000-0000-7000-8000-000000000001' },
      body: { enabled: true, suspended: false, suspendedAt: null },
    });
    const body = (await route(ctx, 'PATCH /:id').handler(request, createReply().reply)) as Record<
      string,
      unknown
    >;

    const updateArg = (fastify.repositories.oauthClients.update as unknown as Mock).mock
      .calls[0][1];
    expect(updateArg).toEqual({ enabled: true });
    expect(updateArg).not.toHaveProperty('suspended');
    expect(updateArg).not.toHaveProperty('suspendedAt');
    // The owner can see why the client is still refused.
    expect(body.suspended).toBe(true);
  });

  it('never writes ID-JAG targets on PATCH (ADR-011, #434 — seed manifest only)', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const row = makeClientRow({ developerId: DEV_A });
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(row);
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) => ({ ...row, ...data })
    );

    const request = authedRequest({
      params: { id: '0190a000-0000-7000-8000-000000000001' },
      body: { name: 'Renamed', idJagTargets: ['https://as.partner.example'] },
    });
    await route(ctx, 'PATCH /:id').handler(request, createReply().reply);

    const updateArg = (fastify.repositories.oauthClients.update as unknown as Mock).mock
      .calls[0][1];
    expect(updateArg).toEqual({ name: 'Renamed' });
  });

  it('validates the effective grant/response combination against persisted values', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    // Persisted client uses authorization_code + code. Dropping the grant to
    // refresh_token only while keeping the persisted `code` response type is
    // inconsistent and must be rejected.
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({
        developerId: DEV_A,
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
      })
    );

    const request = authedRequest({
      params: { id: '0190a000-0000-7000-8000-000000000001' },
      body: { grantTypes: ['refresh_token'] },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'PATCH /:id').handler(request, reply)).rejects.toThrow(BadRequestError);
    expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
  });

  it('returns 404 for a client owned by another developer (no update)', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_B })
    );

    const request = authedRequest({
      params: { id: '0190a000-0000-7000-8000-000000000001' },
      body: { name: 'Hijack' },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'PATCH /:id').handler(request, reply)).rejects.toThrow(NotFoundError);
    expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
  });
});

describe('DELETE /api/clients/:id — #89', () => {
  it('deletes an owned client and returns 204', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A })
    );
    (fastify.repositories.oauthClients.delete as unknown as Mock).mockResolvedValue(true);

    const request = authedRequest({ params: { id: '0190a000-0000-7000-8000-000000000001' } });
    const { reply, state } = createReply();

    await route(ctx, 'DELETE /:id').handler(request, reply);

    expect(state.statusCode).toBe(204);
    expect(fastify.repositories.oauthClients.delete).toHaveBeenCalledWith(
      '0190a000-0000-7000-8000-000000000001'
    );
  });

  it("returns 404 for another developer's client without deleting", async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_B })
    );

    const request = authedRequest({ params: { id: '0190a000-0000-7000-8000-000000000001' } });
    const { reply } = createReply();

    await expect(route(ctx, 'DELETE /:id').handler(request, reply)).rejects.toThrow(NotFoundError);
    expect(fastify.repositories.oauthClients.delete).not.toHaveBeenCalled();
  });
});

describe('POST /api/clients/:id/regenerate-secret — #90', () => {
  it('issues a new secret, stores only the hash, and returns the plaintext once', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A, tokenEndpointAuthMethod: 'client_secret_post' })
    );
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) =>
        makeClientRow({ developerId: DEV_A, ...data })
    );

    const request = authedRequest({ params: { id: '0190a000-0000-7000-8000-000000000001' } });
    const { reply, state } = createReply();

    const body = (await route(ctx, 'POST /:id/regenerate-secret').handler(
      request,
      reply
    )) as Record<string, unknown>;

    expect(typeof body.clientSecret).toBe('string');
    expect((body.clientSecret as string).length).toBe(64);

    const updateArg = (fastify.repositories.oauthClients.update as unknown as Mock).mock
      .calls[0][1];
    expect(updateArg.clientSecretHash).toContain('argon2id$');
    // Only the hash is persisted, never the plaintext.
    expect(updateArg.clientSecretHash).not.toBe(body.clientSecret);
    expect(state.headers['cache-control']).toBe('no-store');
    expect(JSON.stringify(body)).not.toContain('clientSecretHash');
  });

  it('rejects regeneration for a public client (no secret to rotate)', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A, tokenEndpointAuthMethod: 'none' })
    );

    const request = authedRequest({ params: { id: '0190a000-0000-7000-8000-000000000001' } });
    const { reply } = createReply();

    await expect(route(ctx, 'POST /:id/regenerate-secret').handler(request, reply)).rejects.toThrow(
      BadRequestError
    );
    expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
  });

  it("returns 404 for another developer's client", async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_B, tokenEndpointAuthMethod: 'client_secret_post' })
    );

    const request = authedRequest({ params: { id: '0190a000-0000-7000-8000-000000000001' } });
    const { reply } = createReply();

    await expect(route(ctx, 'POST /:id/regenerate-secret').handler(request, reply)).rejects.toThrow(
      NotFoundError
    );
    expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
  });
});

describe('per-route rate limiting on argon2id endpoints', () => {
  it('caps POST / (create) per-IP at the REGISTER_CLIENT budget', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const rl = route(ctx, 'POST /').options.config?.rateLimit;
    expect(rl).toBeDefined();
    expect(rl?.max).toBe(30);
    expect(rl?.timeWindow).toBe(60 * 1000);
    // Keyed by IP so one developer's burst can't exhaust everyone's budget.
    expect(rl?.keyGenerator?.({ ip: '203.0.113.7' })).toBe('203.0.113.7');
    expect(rl?.keyGenerator?.({})).toBe('unknown');
  });

  it('caps POST /:id/regenerate-secret per-IP at the REGISTER_CLIENT budget', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const rl = route(ctx, 'POST /:id/regenerate-secret').options.config?.rateLimit;
    expect(rl).toBeDefined();
    expect(rl?.max).toBe(30);
    expect(rl?.timeWindow).toBe(60 * 1000);
    expect(rl?.keyGenerator?.({ ip: '203.0.113.7' })).toBe('203.0.113.7');
  });

  it('does not rate-limit the read-only GET routes', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    expect(route(ctx, 'GET /').options.config?.rateLimit).toBeUndefined();
    expect(route(ctx, 'GET /:id').options.config?.rateLimit).toBeUndefined();
  });
});

describe('scope allowlist enforcement (#86/#88)', () => {
  it('rejects create when a requested scope is outside the realm allowlist', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const request = authedRequest({
      body: {
        name: 'Over-scoped',
        redirectUris: ['https://app.example.com/cb'],
        // `example:admin` is not in the realm allowlist.
        scopes: ['openid', 'example:admin'],
        tokenEndpointAuthMethod: 'client_secret_post',
      },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'POST /').handler(request, reply)).rejects.toThrow(BadRequestError);
    // Rejected before hashing or persisting.
    expect(fastify.passwordHasher.hashPassword).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
  });

  it('allows create when every requested scope is within the realm allowlist', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) => makeClientRow({ ...data })
    );

    const request = authedRequest({
      body: {
        name: 'OK',
        redirectUris: ['https://app.example.com/cb'],
        scopes: ['openid', 'email'],
        tokenEndpointAuthMethod: 'client_secret_post',
      },
    });
    const { reply, state } = createReply();

    await route(ctx, 'POST /').handler(request, reply);
    expect(state.statusCode).toBe(201);
  });

  it('rejects a PATCH that widens scopes beyond the realm allowlist', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A })
    );

    const request = authedRequest({
      params: { id: '0190a000-0000-7000-8000-000000000001' },
      body: { scopes: ['openid', 'tenant-a:write'] },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'PATCH /:id').handler(request, reply)).rejects.toThrow(BadRequestError);
    expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
  });

  it('stores a repeated scope once, on create and on PATCH', async () => {
    // The allowlist check accepted any number of repeats of an allowed scope,
    // so one row could hold `openid` 116,000 times (~1 MiB), and every list
    // request loaded it again. Dynamic registration already de-duplicates.
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) => makeClientRow({ ...data })
    );
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A })
    );
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) => makeClientRow({ ...data })
    );

    await route(ctx, 'POST /').handler(
      authedRequest({
        body: {
          name: 'Repeats',
          redirectUris: ['https://app.example.com/cb'],
          scopes: ['openid', 'openid', 'email', 'openid'],
        },
      }),
      createReply().reply
    );
    await route(ctx, 'PATCH /:id').handler(
      authedRequest({
        params: { id: '0190a000-0000-7000-8000-000000000001' },
        body: { scopes: ['email', 'email', 'openid'] },
      }),
      createReply().reply
    );

    const created = (fastify.repositories.oauthClients.create as unknown as Mock).mock.calls[0][0];
    expect(created.scopes).toEqual(['openid', 'email']);
    const updated = (fastify.repositories.oauthClients.update as unknown as Mock).mock.calls[0][1];
    expect(updated.scopes).toEqual(['email', 'openid']);
  });
});

describe('clients per developer (MAX_CLIENTS_PER_DEVELOPER)', () => {
  // Nothing limited how many clients one account owns, and `GET /api/clients`
  // returns all of them in one response: a self-registered account could
  // store enough rows that a handful of concurrent list requests ran the
  // process out of heap, again after every restart.
  function createRequest() {
    return authedRequest({
      body: { name: 'One more', redirectUris: ['https://app.example.com/cb'] },
    });
  }

  it('refuses a create once the developer owns the maximum, before hashing or persisting', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    (fastify.repositories.oauthClients.countByDeveloper as unknown as Mock).mockResolvedValue(3);

    await expect(
      route(ctx, 'POST /').handler(createRequest(), createReply().reply)
    ).rejects.toThrow(ForbiddenError);
    expect(fastify.repositories.oauthClients.countByDeveloper).toHaveBeenCalledWith(DEV_A);
    expect(fastify.passwordHasher.hashPassword).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
  });

  it('allows a create below the maximum', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    (fastify.repositories.oauthClients.countByDeveloper as unknown as Mock).mockResolvedValue(2);
    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) => makeClientRow({ ...data })
    );

    const { reply, state } = createReply();
    await route(ctx, 'POST /').handler(createRequest(), reply);
    expect(state.statusCode).toBe(201);
  });
});

describe('redirect_uris required for user-involving grants (#86/#88)', () => {
  it('rejects create of an authorization_code client with no redirect_uris', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    const request = authedRequest({
      body: {
        name: 'No redirects',
        redirectUris: [],
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
        tokenEndpointAuthMethod: 'client_secret_post',
      },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'POST /').handler(request, reply)).rejects.toThrow(BadRequestError);
    expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
  });

  it('rejects a PATCH that empties redirect_uris on an authorization_code client', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({
        developerId: DEV_A,
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
        redirectUris: ['https://app.example.com/cb'],
      })
    );

    const request = authedRequest({
      params: { id: '0190a000-0000-7000-8000-000000000001' },
      body: { redirectUris: [] },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'PATCH /:id').handler(request, reply)).rejects.toThrow(BadRequestError);
    expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
  });

  it('allows a client_credentials-only client with no redirect_uris', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) => makeClientRow({ ...data })
    );

    const request = authedRequest({
      body: {
        name: 'Service',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        responseTypes: [],
        tokenEndpointAuthMethod: 'client_secret_post',
      },
    });
    const { reply, state } = createReply();

    await route(ctx, 'POST /').handler(request, reply);
    expect(state.statusCode).toBe(201);
  });
});

describe('client-management events', () => {
  const CLIENT_ROW_ID = '0190a000-0000-7000-8000-000000000001';

  /** The options every client-management event carries: the developer acts on the client. */
  function clientEventOptions(clientId: string) {
    return {
      realmId: 'realm-1',
      userId: DEV_A,
      subject: { type: 'client', id: clientId },
      clientId,
      actor: 'user',
    };
  }

  it('records client.created with the registration facts, never the secret', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) => makeClientRow({ ...data })
    );

    const request = authedRequest({
      body: {
        name: 'Evented',
        redirectUris: ['https://app.example.com/cb'],
        scopes: ['openid', 'email'],
        tokenEndpointAuthMethod: 'client_secret_post',
      },
    });
    const body = (await route(ctx, 'POST /').handler(request, createReply().reply)) as Record<
      string,
      unknown
    >;

    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      request,
      'urn:qauth:event:client.created:v1-rc.0',
      {
        registration: 'developer_api',
        isPublic: false,
        grantTypes: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'email'],
        authMethod: 'client_secret_post',
      },
      clientEventOptions(body.clientId as string)
    );
    // The checked emitter accepted it: nothing was swallowed by the best-effort wrapper.
    expect(fastify.log.warn).not.toHaveBeenCalled();
  });

  it('records client.updated with the names of the settings written, never their values', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A })
    );
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) =>
        makeClientRow({ developerId: DEV_A, ...data })
    );

    const request = authedRequest({
      params: { id: CLIENT_ROW_ID },
      body: { name: 'Renamed', enabled: false },
    });
    await route(ctx, 'PATCH /:id').handler(request, createReply().reply);

    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      request,
      'urn:qauth:event:client.updated:v1-rc.0',
      { fields: ['name', 'enabled'] },
      clientEventOptions('app-123')
    );
    expect(fastify.log.warn).not.toHaveBeenCalled();
  });

  it('records client.deleted and client.secret_rotated against the client', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A, tokenEndpointAuthMethod: 'client_secret_post' })
    );
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) =>
        makeClientRow({ developerId: DEV_A, ...data })
    );

    const rotate = authedRequest({ params: { id: CLIENT_ROW_ID } });
    await route(ctx, 'POST /:id/regenerate-secret').handler(rotate, createReply().reply);
    const remove = authedRequest({ params: { id: CLIENT_ROW_ID } });
    await route(ctx, 'DELETE /:id').handler(remove, createReply().reply);

    expect(emitUserEventMock).toHaveBeenNthCalledWith(
      1,
      rotate,
      'urn:qauth:event:client.secret_rotated:v1-rc.0',
      {},
      clientEventOptions('app-123')
    );
    expect(emitUserEventMock).toHaveBeenNthCalledWith(
      2,
      remove,
      'urn:qauth:event:client.deleted:v1-rc.0',
      {},
      clientEventOptions('app-123')
    );
    expect(fastify.log.warn).not.toHaveBeenCalled();
  });
});

describe('client-management events are best-effort (one-time secret must survive #86/#90)', () => {
  it('still returns the created client + secret when the event write throws', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) => makeClientRow({ ...data })
    );
    emitUserEventMock.mockRejectedValueOnce(new Error('event store down'));

    const request = authedRequest({
      body: {
        name: 'Resilient',
        redirectUris: ['https://app.example.com/cb'],
        tokenEndpointAuthMethod: 'client_secret_post',
      },
    });
    const { reply, state } = createReply();

    const body = (await route(ctx, 'POST /').handler(request, reply)) as Record<string, unknown>;

    expect(state.statusCode).toBe(201);
    expect(typeof body.clientSecret).toBe('string');
    // The failure was swallowed and logged, not propagated.
    expect(fastify.log.warn).toHaveBeenCalled();
  });

  it('still returns the rotated secret when the event write throws', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A, tokenEndpointAuthMethod: 'client_secret_post' })
    );
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) =>
        makeClientRow({ developerId: DEV_A, ...data })
    );
    emitUserEventMock.mockRejectedValueOnce(new Error('event store down'));

    const request = authedRequest({ params: { id: '0190a000-0000-7000-8000-000000000001' } });
    const { reply } = createReply();

    const body = (await route(ctx, 'POST /:id/regenerate-secret').handler(
      request,
      reply
    )) as Record<string, unknown>;

    expect(typeof body.clientSecret).toBe('string');
    expect((body.clientSecret as string).length).toBe(64);
    expect(fastify.log.warn).toHaveBeenCalled();
  });
});

describe('PATCH and the operator-provisioned marker (ANT-2026-O8U3P920)', () => {
  async function patch(existing: Record<string, unknown>, body: Record<string, unknown>) {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A, ...existing })
    );
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) =>
        makeClientRow({ developerId: DEV_A, ...existing, ...data })
    );
    await route(ctx, 'PATCH /:id').handler(
      authedRequest({ params: { id: '0190a000-0000-7000-8000-000000000001' }, body }),
      createReply().reply
    );
    return (fastify.repositories.oauthClients.update as unknown as Mock).mock.calls[0][1];
  }

  it('clears the marker when the owner changes the redirect URIs the operator vouched for', async () => {
    const updateArg = await patch(
      { provisionedByOperator: true, redirectUris: ['https://app.example.com/cb'] },
      { redirectUris: ['https://login-qauth.attacker.example/sign-in'] }
    );
    expect(updateArg.provisionedByOperator).toBe(false);
  });

  it('keeps the marker when the redirect URIs are unchanged', async () => {
    const updateArg = await patch(
      { provisionedByOperator: true, redirectUris: ['https://app.example.com/cb'] },
      { name: 'Renamed', redirectUris: ['https://app.example.com/cb'] }
    );
    expect(updateArg).not.toHaveProperty('provisionedByOperator');
  });

  it('never lets the owner set the marker', async () => {
    const updateArg = await patch(
      { provisionedByOperator: false },
      { name: 'Renamed', provisionedByOperator: true }
    );
    expect(updateArg).toEqual({ name: 'Renamed' });
  });
});

describe('PATCH silently drops immutable fields (#88, Nit 8)', () => {
  it('never forwards developerId / clientId / clientSecretHash to the repository', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A })
    );
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) =>
        makeClientRow({ developerId: DEV_A, ...data })
    );

    // Attempt a mass-assignment: the Zod schema strips unknown keys, and the
    // handler only forwards the known mutable allowlist, so these are dropped.
    const request = authedRequest({
      params: { id: '0190a000-0000-7000-8000-000000000001' },
      body: {
        name: 'Renamed',
        developerId: DEV_B,
        clientId: 'attacker-chosen',
        clientSecretHash: 'argon2id$attacker',
      },
    });
    const { reply } = createReply();

    // Handler is invoked with the raw body (Zod stripping is not exercised in
    // this unit harness), so assert the handler's own allowlist drops them.
    await route(ctx, 'PATCH /:id').handler(request, reply);

    const updateArg = (fastify.repositories.oauthClients.update as unknown as Mock).mock
      .calls[0][1];
    expect(updateArg).toEqual({ name: 'Renamed' });
    expect(updateArg.developerId).toBeUndefined();
    expect(updateArg.clientId).toBeUndefined();
    expect(updateArg.clientSecretHash).toBeUndefined();
  });
});
