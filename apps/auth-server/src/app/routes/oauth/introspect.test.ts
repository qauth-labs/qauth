import { InvalidCredentialsError, JWTExpiredError, JWTInvalidError } from '@qauth/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

import introspectRoute from './introspect';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

function createFastifyStub() {
  const ctx: TestContext = {};

  const fastify: Partial<FastifyInstance> & {
    repositories: any;
    passwordHasher: any;
    jwtUtils: any;
    log: any;
  } = {
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

    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(client);
    fastify.passwordHasher.verifyPassword.mockResolvedValue(true);
    fastify.jwtUtils.verifyAccessToken.mockResolvedValue({
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

    const result = await handler!(request, reply);

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

    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(client);
    fastify.passwordHasher.verifyPassword.mockResolvedValue(true);
    fastify.jwtUtils.verifyAccessToken.mockRejectedValue(
      new JWTExpiredError('JWT token has expired')
    );

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

    const result = await handler!(request, reply);

    expect(result).toEqual({ active: false });
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

    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(client);
    fastify.passwordHasher.verifyPassword.mockResolvedValue(true);
    fastify.jwtUtils.verifyAccessToken.mockResolvedValue({
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

    const result = await handler!(request, reply);

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

    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(client);
    fastify.passwordHasher.verifyPassword.mockResolvedValue(false);
    fastify.jwtUtils.verifyAccessToken.mockResolvedValue({
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
      send: (_body: unknown) => {
        throw new Error('send should not be called on invalid credentials');
      },
    };

    await expect(handler!(request, reply)).rejects.toThrow(InvalidCredentialsError);
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

    fastify.repositories.oauthClients.findByClientId.mockResolvedValue(client);
    fastify.passwordHasher.verifyPassword.mockResolvedValue(true);
    fastify.jwtUtils.verifyAccessToken.mockRejectedValue(new JWTInvalidError('Invalid JWT token'));

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

    const result = await handler!(request, reply);

    expect(result).toEqual({ active: false });
  });
});
