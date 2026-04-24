import { InvalidClientError, JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    INTROSPECT_RATE_LIMIT: 60,
    INTROSPECT_RATE_WINDOW: 60,
  },
}));

import errorHandler from '../../plugins/error-handler';
import introspectRoute from './introspect';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

function createFastifyStub() {
  const ctx: TestContext = {};

  const fastify: any = {
    withTypeProvider: () => ({
      post: (
        _url: string,
        _opts: unknown,
        handler: (request: any, reply: any) => Promise<unknown>
      ) => {
        ctx.handler = handler;
        return fastify;
      },
    }),
    repositories: {
      realms: {
        findByName: vi.fn().mockResolvedValue({
          id: 'realm-1',
          name: 'default',
          enabled: true,
        }),
        create: vi.fn().mockResolvedValue({
          id: 'realm-1',
          name: 'default',
          enabled: true,
        }),
      },
      oauthClients: {
        findByClientId: vi.fn(),
      },
      auditLogs: {
        create: vi.fn(),
      },
    },
    passwordHasher: {
      verifyPassword: vi.fn(),
    },
    jwtUtils: {
      verifyAccessToken: vi.fn(),
    },
    log: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  };

  return { fastify: fastify as FastifyInstance, ctx };
}

describe('POST /oauth/introspect route', () => {
  it('returns active: true for valid token and client', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
    };

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockResolvedValue({
      sub: 'user-1',
      email: 'user@example.com',
      email_verified: true,
      clientId: client.clientId,
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const request = {
      body: {
        token: 'valid-token',
        client_id: client.clientId,
        client_secret: 'secret',
      },
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'vitest',
      },
    };

    const replyBody: any[] = [];
    const reply = {
      send: (body: unknown) => {
        replyBody.push(body);
        return body;
      },
    };

    if (!handler) {
      throw new Error('Introspect handler was not registered');
    }

    const result = await handler(request, reply);

    expect(result).toEqual({
      active: true,
      sub: 'user-1',
      client_id: client.clientId,
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
      token_type: 'Bearer',
    });
  });

  it('writes a NULL user_id audit row for client_credentials tokens (sub === client_id)', async () => {
    // Regression: audit_logs.user_id is a uuid column. `client_credentials`
    // tokens have sub = clientId (a slug), which would fail the uuid cast.
    // The success path must set `userId: null` in that case and preserve
    // the token's sub in `metadata.tokenSub`.
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: 'client-rs-uuid',
      clientId: 'resource-server',
      clientSecretHash: 'hashed-secret',
      enabled: true,
      audience: ['api.example.com'],
    };
    const callerClientId = 'caller-machine';

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;
    const auditLogMock = fastify.repositories.auditLogs.create as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockResolvedValue({
      // sub === clientId is the hallmark of a client_credentials token.
      sub: callerClientId,
      clientId: callerClientId,
      scope: 'api:read',
      aud: 'api.example.com',
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const request = {
      body: { token: 'cc-token', client_id: client.clientId, client_secret: 'secret' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };
    const reply = { send: (body: unknown) => body };

    if (!handler) throw new Error('Introspect handler was not registered');

    const result = (await handler(request, reply)) as { active: boolean; sub: string };
    expect(result.active).toBe(true);
    expect(result.sub).toBe(callerClientId);

    expect(auditLogMock).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: null,
        oauthClientId: client.id,
        event: 'oauth.introspect.success',
        success: true,
        metadata: expect.objectContaining({
          tokenClientId: callerClientId,
          tokenSub: callerClientId,
        }),
      })
    );
  });

  it('returns active: false for expired token', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
    };

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;
    const auditLogMock = fastify.repositories.auditLogs.create as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockRejectedValue(new JWTExpiredError('JWT token has expired'));

    const request = {
      body: {
        token: 'expired-token',
        client_id: client.clientId,
        client_secret: 'secret',
      },
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'vitest',
      },
    };

    const replyBody: any[] = [];
    const reply = {
      send: (body: unknown) => {
        replyBody.push(body);
        return body;
      },
    };

    if (!handler) {
      throw new Error('Introspect handler was not registered');
    }

    const result = await handler(request, reply);

    expect(result).toEqual({ active: false });

    expect(auditLogMock).toHaveBeenCalledWith({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.introspect.failure',
      eventType: 'token',
      success: false,
      ipAddress: '127.0.0.1',
      userAgent: 'vitest',
      metadata: {
        error: 'JWT token has expired',
      },
    });
  });

  it('returns active: false for token issued to a different client', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
    };

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockResolvedValue({
      sub: 'user-1',
      email: 'user@example.com',
      email_verified: true,
      clientId: 'other-client',
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const request = {
      body: {
        token: 'cross-client-token',
        client_id: client.clientId,
        client_secret: 'secret',
      },
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'vitest',
      },
    };

    const replyBody: any[] = [];
    const reply = {
      send: (body: unknown) => {
        replyBody.push(body);
        return body;
      },
    };

    if (!handler) {
      throw new Error('Introspect handler was not registered');
    }

    const result = await handler(request, reply);

    expect(result).toEqual({ active: false });
  });

  it('returns active: true when the introspecting client is authoritative for the token audience (string aud)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    // Resource-server-style client: no minted scopes, but listed as
    // authoritative for "api.example.com".
    const client = {
      id: 'client-rs',
      clientId: 'resource-server',
      clientSecretHash: 'hashed-secret',
      enabled: true,
      audience: ['api.example.com'],
    };

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockResolvedValue({
      sub: 'user-1',
      clientId: 'caller-app',
      scope: 'api:read',
      aud: 'api.example.com',
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const request = {
      body: { token: 'caller-token', client_id: client.clientId, client_secret: 'secret' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = { send: (body: unknown) => body };

    if (!handler) throw new Error('Introspect handler was not registered');

    const result = await handler(request, reply);

    expect(result).toEqual({
      active: true,
      sub: 'user-1',
      client_id: 'caller-app',
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
      aud: 'api.example.com',
      scope: 'api:read',
      token_type: 'Bearer',
    });
  });

  it('returns active: true when every member of an array aud is in the client audience list', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: 'client-rs',
      clientId: 'resource-server',
      clientSecretHash: 'hashed-secret',
      enabled: true,
      audience: ['api.example.com', 'admin.example.com'],
    };

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockResolvedValue({
      sub: 'user-1',
      clientId: 'caller-app',
      aud: ['api.example.com', 'admin.example.com'],
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const request = {
      body: { token: 'caller-token', client_id: client.clientId, client_secret: 'secret' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = { send: (body: unknown) => body };

    if (!handler) throw new Error('Introspect handler was not registered');

    const result = (await handler(request, reply)) as { active: boolean };
    expect(result.active).toBe(true);
  });

  it('returns active: false when token aud is not in the introspecting client audience list', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    // Client is authoritative only for "other.example.com" — cross-audience
    // introspection must be rejected even though the client authenticates.
    const client = {
      id: 'client-rs',
      clientId: 'resource-server',
      clientSecretHash: 'hashed-secret',
      enabled: true,
      audience: ['other.example.com'],
    };

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockResolvedValue({
      sub: 'user-1',
      clientId: 'caller-app',
      aud: 'api.example.com',
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const request = {
      body: { token: 'caller-token', client_id: client.clientId, client_secret: 'secret' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = { send: (body: unknown) => body };

    if (!handler) throw new Error('Introspect handler was not registered');

    const result = await handler(request, reply);
    expect(result).toEqual({ active: false });
  });

  it('returns active: false for cross-client introspection when the client has no audience configured', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    // Regression guard: pre-audience-bound behaviour is preserved when a
    // client has no `audience` configured — cross-client is rejected.
    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
      audience: null,
    };

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockResolvedValue({
      sub: 'user-1',
      clientId: 'other-client',
      aud: 'api.example.com',
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const request = {
      body: { token: 'cross-client-token', client_id: client.clientId, client_secret: 'secret' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = { send: (body: unknown) => body };

    if (!handler) throw new Error('Introspect handler was not registered');

    const result = await handler(request, reply);
    expect(result).toEqual({ active: false });
  });

  it('throws InvalidClientError for invalid client credentials', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
    };

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(false);
    verifyAccessTokenMock.mockResolvedValue({
      sub: 'user-1',
      email: 'user@example.com',
      email_verified: true,
      clientId: client.clientId,
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const request = {
      body: {
        token: 'any-token',
        client_id: client.clientId,
        client_secret: 'wrong-secret',
      },
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'vitest',
      },
    };

    const reply = {
      send: () => {
        throw new Error('send should not be called on invalid credentials');
      },
    };

    if (!handler) {
      throw new Error('Introspect handler was not registered');
    }

    await expect(handler(request, reply)).rejects.toThrow(InvalidClientError);
  });

  it('returns active: false for invalid token format', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
    };

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;
    const auditLogMock = fastify.repositories.auditLogs.create as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockRejectedValue(new JWTInvalidError('Invalid JWT token'));

    const request = {
      body: {
        token: 'invalid-token',
        client_id: client.clientId,
        client_secret: 'secret',
      },
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'vitest',
      },
    };

    const replyBody: any[] = [];
    const reply = {
      send: (body: unknown) => {
        replyBody.push(body);
        return body;
      },
    };

    if (!handler) {
      throw new Error('Introspect handler was not registered');
    }

    const result = await handler(request, reply);

    expect(result).toEqual({ active: false });

    expect(auditLogMock).toHaveBeenCalledWith({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.introspect.failure',
      eventType: 'token',
      success: false,
      ipAddress: '127.0.0.1',
      userAgent: 'vitest',
      metadata: {
        error: 'Invalid JWT token',
      },
    });
  });

  it('returns active: false for invalid signature', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
    };

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;
    const auditLogMock = fastify.repositories.auditLogs.create as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockRejectedValue(
      new JWTInvalidError('Invalid JWT token: signature verification failed')
    );

    const request = {
      body: {
        token: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEifQ.fake-sig',
        client_id: client.clientId,
        client_secret: 'secret',
      },
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'vitest',
      },
    };

    const reply = {
      send: (body: unknown) => body,
    };

    if (!handler) {
      throw new Error('Introspect handler was not registered');
    }

    const result = await handler(request, reply);

    expect(result).toEqual({ active: false });

    expect(auditLogMock).toHaveBeenCalledWith({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.introspect.failure',
      eventType: 'token',
      success: false,
      ipAddress: '127.0.0.1',
      userAgent: 'vitest',
      metadata: {
        error: 'Invalid JWT token: signature verification failed',
      },
    });
  });

  it('returns 400 for missing or empty token', async () => {
    const app = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    app.decorate('repositories', {
      realms: { findByName: vi.fn(), create: vi.fn() },
      oauthClients: { findByClientId: vi.fn() },
      auditLogs: { create: vi.fn() },
    } as any);
    app.decorate('passwordHasher', { verifyPassword: vi.fn() } as any);
    app.decorate('jwtUtils', { verifyAccessToken: vi.fn() } as any);

    await app.register(introspectRoute);
    await app.register(errorHandler);

    try {
      const response = await app.inject({
        method: 'POST',
        url: '/introspect',
        headers: {
          'content-type': 'application/json',
        },
        payload: {
          token: '',
          client_id: 'client-123',
          client_secret: 'secret',
        },
      });

      expect(response.statusCode).toBe(400);

      const json = response.json();
      expect(json).toMatchObject({
        statusCode: 400,
      });
      expect(json.error).toBeDefined();
    } finally {
      await app.close();
    }
  });
});
