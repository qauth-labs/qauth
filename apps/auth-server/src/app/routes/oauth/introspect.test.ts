import { InvalidCredentialsError, JWTExpiredError, JWTInvalidError } from '@qauth/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
  },
}));

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

  it('throws InvalidCredentialsError for invalid client credentials', async () => {
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

    await expect(handler(request, reply)).rejects.toThrow(InvalidCredentialsError);
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
});
