import { BadRequestError, JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

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
  },
}));

import clientsRoute, { autoPrefix } from './index';

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
          dynamicRegistrationAllowedScopes: ['openid', 'profile', 'email', 'offline_access'],
        })),
        findById: vi.fn(async () => ({
          id: 'realm-1',
          name: 'default',
          enabled: true,
          dynamicRegistrationAllowedScopes: ['openid', 'profile', 'email', 'offline_access'],
        })),
        update: vi.fn(),
        create: vi.fn(),
      },
      auditLogs: {
        create: vi.fn(async () => undefined),
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
    enabled: true,
    requirePkce: true,
    tokenEndpointAuthMethod: 'client_secret_post',
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    developerId: 'dev-A',
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

  it('registers requireJwt as the preHandler (401 for unauthenticated)', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);
    expect(ctx.handler).toBeDefined();
    expect(ctx.options?.preHandler).toBe(fastify.requireJwt);
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
          requirePkce: true,
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
    expect(route(ctx, 'POST /').options.preHandler).toBe(fastify.requireJwt);
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
        // `memory:admin` is not in the realm allowlist.
        scopes: ['openid', 'memory:admin'],
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
      body: { scopes: ['openid', 'akinon:write'] },
    });
    const { reply } = createReply();

    await expect(route(ctx, 'PATCH /:id').handler(request, reply)).rejects.toThrow(BadRequestError);
    expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
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

describe('audit logging is best-effort (one-time secret must survive #86/#90)', () => {
  it('still returns the created client + secret when the audit write throws', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.create as unknown as Mock).mockImplementation(
      async (data: Record<string, unknown>) => makeClientRow({ ...data })
    );
    (fastify.repositories.auditLogs.create as unknown as Mock).mockRejectedValue(
      new Error('audit sink down')
    );

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

  it('still returns the rotated secret when the audit write throws', async () => {
    const { fastify, ctx } = makeFastify();
    await clientsRoute(fastify);

    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(
      makeClientRow({ developerId: DEV_A, tokenEndpointAuthMethod: 'client_secret_post' })
    );
    (fastify.repositories.oauthClients.update as unknown as Mock).mockImplementation(
      async (_id: string, data: Record<string, unknown>) =>
        makeClientRow({ developerId: DEV_A, ...data })
    );
    (fastify.repositories.auditLogs.create as unknown as Mock).mockRejectedValue(
      new Error('audit sink down')
    );

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
