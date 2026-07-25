import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi } from 'vitest';

/**
 * Routing-level tests for `/oauth/authorize`.
 *
 * Every other authorize test drives the handler function directly through a
 * hand-rolled Fastify double, which by construction cannot observe ROUTER
 * behaviour or the real redirect a client would actually receive. These tests
 * boot a REAL Fastify with the same `routerOptions` as `main.ts` and inject
 * real requests, so routing, validation and the emitted `Location` header are
 * all in the loop.
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
    CIMD_ALLOW_PRIVATE_ADDRESSES: false,
  },
}));

import authorizeRoute from './authorize';

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

async function buildServer(): Promise<FastifyInstance> {
  // Same router configuration as apps/auth-server/src/main.ts.
  const fastify = Fastify({ logger: false, routerOptions: { ignoreTrailingSlash: true } });
  fastify.setValidatorCompiler(validatorCompiler);
  fastify.setSerializerCompiler(serializerCompiler);

  fastify.decorate('repositories', {
    realms: {
      findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'master', enabled: true }),
      create: vi.fn(),
    },
    oauthClients: { findByClientId: vi.fn().mockResolvedValue(CLIENT) },
    oauthConsents: { findActive: vi.fn(), upsertGrant: vi.fn() },
    authorizationCodes: { create: vi.fn() },
    auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
  } as never);
  fastify.decorate('jwtUtils', {
    extractFromHeader: vi.fn().mockReturnValue(null),
    verifyAccessToken: vi.fn(),
    getIssuer: () => 'https://auth.example.com',
  } as never);
  fastify.decorate('sessionUtils', {
    getSession: vi.fn().mockResolvedValue(null),
    setSession: vi.fn().mockResolvedValue(undefined),
    deleteSession: vi.fn().mockResolvedValue(undefined),
  } as never);

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

  it('returns login_required for an unauthenticated prompt=none instead of showing UI', async () => {
    // OIDC Core §3.1.2.1: `prompt=none` forbids any user-facing UI. These
    // requests come from a hidden silent-renewal iframe, where a redirect to
    // the login page renders a form nobody can see and the client just hangs
    // until its timeout.
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
});
