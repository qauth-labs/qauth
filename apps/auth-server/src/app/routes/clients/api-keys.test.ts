import { NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

// `index.ts` (which registers these routes) transitively imports `config/env`,
// which validates required env at module load. Stub it (matches clients.test.ts).
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

import { registerApiKeyRoutes } from './api-keys';

type RouteHandler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>;
interface RouteOptions {
  preHandler?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
}
interface RegisteredRoute {
  handler: RouteHandler;
  options: RouteOptions;
}
interface TestContext {
  routes: Map<string, RegisteredRoute>;
}

const DEV_A = '0190a000-0000-7000-8000-00000000000a';
const DEV_B = '0190a000-0000-7000-8000-00000000000b';
const CLIENT_ID = '0190a000-0000-7000-8000-0000000000c1';

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

/**
 * Build a Fastify test double. `clientEnvironment` / `realmLaxity` drive the
 * ADR-008 environment gate via the real `resolveEnvironmentPolicy` resolver
 * (the helper is NOT mocked — we exercise the genuine gate).
 */
function makeFastify(
  opts: { clientEnvironment?: string; realmLaxity?: string; clientOwner?: string } = {}
) {
  const ctx: TestContext = { routes: new Map() };
  const register = (method: string) => (url: string, o: RouteOptions, handler: RouteHandler) => {
    ctx.routes.set(`${method} ${url}`, { handler, options: o });
    return chain;
  };
  const chain: any = {
    get: register('GET'),
    post: register('POST'),
    patch: register('PATCH'),
    delete: register('DELETE'),
  };

  const clientRow = {
    id: CLIENT_ID,
    clientId: 'app-123',
    realmId: 'realm-1',
    enabled: true,
    developerId: opts.clientOwner ?? DEV_A,
    environment: opts.clientEnvironment ?? 'development',
  };
  const realmRow = { id: 'realm-1', maxEnvironmentLaxity: opts.realmLaxity ?? 'development' };

  const fastify: any = {
    withTypeProvider: () => chain,
    requireJwt: vi.fn(),
    passwordHasher: {
      hashPassword: vi.fn(async (plain: string) => `argon2id$${plain}`),
      verifyPassword: vi.fn(async (hash: string, plain: string) => hash === `argon2id$${plain}`),
    },
    repositories: {
      oauthClients: { findById: vi.fn(async () => clientRow) },
      realms: { findById: vi.fn(async () => realmRow) },
      apiKeys: {
        create: vi.fn(async (data: Record<string, unknown>) => ({
          id: 'key-1',
          createdAt: 1700,
          lastUsedAt: null,
          revokedAt: null,
          ...data,
        })),
        listByClient: vi.fn(async () => []),
        findById: vi.fn(),
        revoke: vi.fn(),
      },
      auditLogs: { create: vi.fn(async () => undefined) },
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx, clientRow };
}

function route(ctx: TestContext, key: string): RegisteredRoute {
  const r = ctx.routes.get(key);
  if (!r) throw new Error(`route not registered: ${key}`);
  return r;
}

function authedRequest(overrides: Record<string, unknown> = {}): FastifyRequest {
  return {
    jwtPayload: { sub: DEV_A },
    params: { clientId: CLIENT_ID },
    body: { name: 'laptop' },
    headers: { authorization: 'Bearer token', 'user-agent': 'vitest' },
    ip: '127.0.0.1',
    ...overrides,
  } as unknown as FastifyRequest;
}

describe('API key routes — registration & auth', () => {
  it('registers POST/GET/DELETE under the client-scoped paths, all behind requireJwt', async () => {
    const { fastify, ctx } = makeFastify();
    await registerApiKeyRoutes(fastify);

    const post = route(ctx, 'POST /:clientId/api-keys');
    const get = route(ctx, 'GET /:clientId/api-keys');
    const del = route(ctx, 'DELETE /:clientId/api-keys/:keyId');

    expect(post.options.preHandler).toBe(fastify.requireJwt);
    expect(get.options.preHandler).toBe(fastify.requireJwt);
    expect(del.options.preHandler).toBe(fastify.requireJwt);
  });
});

describe('POST create — development client (allowed)', () => {
  it('mints a key, stores the HASH (never plaintext), returns the plaintext ONCE with no-store', async () => {
    const { fastify, ctx } = makeFastify({ clientEnvironment: 'development' });
    await registerApiKeyRoutes(fastify);
    const { reply, state } = createReply();

    await route(ctx, 'POST /:clientId/api-keys').handler(authedRequest(), reply);

    expect(state.statusCode).toBe(201);
    const body = state.body as Record<string, unknown>;

    // Plaintext key returned exactly once, in the expected format.
    expect(body.key).toMatch(/^qauth_[0-9a-f]{16}_[0-9a-f]{64}$/);

    // The persisted row stored a HASH, not the plaintext, and no keyHash leaked
    // into the response.
    const createArg = (fastify.repositories.apiKeys.create as unknown as Mock).mock.calls[0][0];
    expect(createArg.keyHash).toBe(`argon2id$${body.key}`);
    expect(createArg.keyHash).not.toBe(body.key);
    expect(createArg.clientId).toBe(CLIENT_ID);
    expect(createArg.developerId).toBe(DEV_A);
    expect(body).not.toHaveProperty('keyHash');

    // One-time secret must not be cached.
    expect(state.headers['cache-control']).toBe('no-store');

    // Audit logged.
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'api_key.created', success: true })
    );
  });
});

describe('POST create — environment gate (refused with 403)', () => {
  it('refuses a PRODUCTION client and never hashes or persists', async () => {
    const { fastify, ctx } = makeFastify({ clientEnvironment: 'production' });
    await registerApiKeyRoutes(fastify);
    const { reply } = createReply();

    await expect(
      route(ctx, 'POST /:clientId/api-keys').handler(authedRequest(), reply)
    ).rejects.toMatchObject({ statusCode: 403 });

    expect(fastify.passwordHasher.hashPassword).not.toHaveBeenCalled();
    expect(fastify.repositories.apiKeys.create).not.toHaveBeenCalled();
  });

  it('refuses an UNSET-environment client with 403 (fail-safe to production)', async () => {
    const { fastify, ctx } = makeFastify({ clientEnvironment: undefined });
    // Force the resolver to see an absent client environment.
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue({
      id: CLIENT_ID,
      clientId: 'app-123',
      realmId: 'realm-1',
      enabled: true,
      developerId: DEV_A,
      // environment intentionally absent
    });
    await registerApiKeyRoutes(fastify);
    const { reply } = createReply();

    await expect(
      route(ctx, 'POST /:clientId/api-keys').handler(authedRequest(), reply)
    ).rejects.toMatchObject({ statusCode: 403 });
    expect(fastify.repositories.apiKeys.create).not.toHaveBeenCalled();
  });

  it('refuses a development client when the REALM ceiling forces production (gate is the stricter of the two)', async () => {
    const { fastify, ctx } = makeFastify({
      clientEnvironment: 'development',
      realmLaxity: 'production',
    });
    await registerApiKeyRoutes(fastify);
    const { reply } = createReply();

    await expect(
      route(ctx, 'POST /:clientId/api-keys').handler(authedRequest(), reply)
    ).rejects.toMatchObject({ statusCode: 403 });
  });
});

describe('POST create — ownership', () => {
  it('returns 404 (not 403) for a client owned by another developer', async () => {
    const { fastify, ctx } = makeFastify({ clientOwner: DEV_B });
    await registerApiKeyRoutes(fastify);
    const { reply } = createReply();

    await expect(
      route(ctx, 'POST /:clientId/api-keys').handler(authedRequest(), reply)
    ).rejects.toBeInstanceOf(NotFoundError);
    expect(fastify.repositories.apiKeys.create).not.toHaveBeenCalled();
  });

  it('returns 404 for a non-UUID subject (client_credentials token) with no client lookup', async () => {
    const { fastify, ctx } = makeFastify();
    await registerApiKeyRoutes(fastify);
    const { reply } = createReply();

    await expect(
      route(ctx, 'POST /:clientId/api-keys').handler(
        authedRequest({ jwtPayload: { sub: 'app-123' } }),
        reply
      )
    ).rejects.toBeInstanceOf(NotFoundError);
    expect(fastify.repositories.oauthClients.findById).not.toHaveBeenCalled();
  });
});

describe('GET list — masked', () => {
  it('lists keys with masked fields only (prefix + last4), never the hash', async () => {
    const { fastify, ctx } = makeFastify();
    (fastify.repositories.apiKeys.listByClient as unknown as Mock).mockResolvedValue([
      {
        id: 'key-1',
        realmId: 'realm-1',
        clientId: CLIENT_ID,
        developerId: DEV_A,
        name: 'laptop',
        keyHash: 'argon2id$super-secret',
        prefix: 'qauth_0123456789abcdef',
        last4: 'abcd',
        createdAt: 1700,
        lastUsedAt: 1800,
        revokedAt: null,
      },
    ]);
    await registerApiKeyRoutes(fastify);
    const { reply, state } = createReply();

    await route(ctx, 'GET /:clientId/api-keys').handler(authedRequest(), reply);

    const body = state.body as { apiKeys: Record<string, unknown>[] };
    expect(body.apiKeys).toHaveLength(1);
    expect(body.apiKeys[0]).toEqual({
      id: 'key-1',
      clientId: CLIENT_ID,
      name: 'laptop',
      prefix: 'qauth_0123456789abcdef',
      last4: 'abcd',
      createdAt: 1700,
      lastUsedAt: 1800,
      revokedAt: null,
    });
    expect(JSON.stringify(body)).not.toContain('argon2id');
    expect(body.apiKeys[0]).not.toHaveProperty('keyHash');
  });
});

describe('DELETE revoke', () => {
  const keyRow = {
    id: 'key-1',
    clientId: CLIENT_ID,
    realmId: 'realm-1',
    developerId: DEV_A,
    name: 'laptop',
    keyHash: 'argon2id$x',
    prefix: 'qauth_0123456789abcdef',
    last4: 'abcd',
    createdAt: 1700,
    lastUsedAt: null,
    revokedAt: null,
  };

  it('revokes a key the developer owns and audits it', async () => {
    const { fastify, ctx } = makeFastify();
    (fastify.repositories.apiKeys.findById as unknown as Mock).mockResolvedValue(keyRow);
    (fastify.repositories.apiKeys.revoke as unknown as Mock).mockResolvedValue({
      ...keyRow,
      revokedAt: 1900,
    });
    await registerApiKeyRoutes(fastify);
    const { reply, state } = createReply();

    await route(ctx, 'DELETE /:clientId/api-keys/:keyId').handler(
      authedRequest({ params: { clientId: CLIENT_ID, keyId: 'key-1' } }),
      reply
    );

    expect(fastify.repositories.apiKeys.revoke).toHaveBeenCalledWith('key-1');
    expect((state.body as Record<string, unknown>).revokedAt).toBe(1900);
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'api_key.revoked', success: true })
    );
  });

  it('returns 404 when the key belongs to a different client', async () => {
    const { fastify, ctx } = makeFastify();
    (fastify.repositories.apiKeys.findById as unknown as Mock).mockResolvedValue({
      ...keyRow,
      clientId: 'some-other-client',
    });
    await registerApiKeyRoutes(fastify);
    const { reply } = createReply();

    await expect(
      route(ctx, 'DELETE /:clientId/api-keys/:keyId').handler(
        authedRequest({ params: { clientId: CLIENT_ID, keyId: 'key-1' } }),
        reply
      )
    ).rejects.toBeInstanceOf(NotFoundError);
    expect(fastify.repositories.apiKeys.revoke).not.toHaveBeenCalled();
  });
});
