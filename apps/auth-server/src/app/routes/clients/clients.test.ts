import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

import clientsRoute, { autoPrefix } from './index';

interface TestContext {
  handler?: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>;
  options?: {
    preHandler?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  };
}

function createReply() {
  const state: { statusCode?: number; body?: unknown } = {};
  const reply: any = {
    code(n: number) {
      state.statusCode = n;
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
  const ctx: TestContext = {};
  const fastify: any = {
    withTypeProvider: () => ({
      get: (_url: string, opts: TestContext['options'], handler: TestContext['handler']) => {
        ctx.handler = handler;
        ctx.options = opts;
        return fastify;
      },
    }),
    requireJwt: vi.fn(),
    repositories: {
      oauthClients: {
        listByDeveloper: vi.fn(),
      },
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
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
      jwtPayload: { sub: 'dev-A' },
      headers: { authorization: 'Bearer token' },
    } as unknown as FastifyRequest;
    const { reply, state } = createReply();

    await ctx.handler!(request, reply);

    expect(fastify.repositories.oauthClients.listByDeveloper).toHaveBeenCalledWith('dev-A');
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
      jwtPayload: { sub: 'dev-A' },
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
        developerId === 'dev-A' ? [makeClientRow({ developerId: 'dev-A' })] : []
    );

    // Developer B is authenticated and must not receive developer A's client.
    const request = {
      jwtPayload: { sub: 'dev-B' },
      headers: { authorization: 'Bearer token' },
    } as unknown as FastifyRequest;
    const { reply, state } = createReply();

    await ctx.handler!(request, reply);

    expect(fastify.repositories.oauthClients.listByDeveloper).toHaveBeenCalledWith('dev-B');
    expect(fastify.repositories.oauthClients.listByDeveloper).not.toHaveBeenCalledWith('dev-A');
    expect(state.body).toEqual({ clients: [] });
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
