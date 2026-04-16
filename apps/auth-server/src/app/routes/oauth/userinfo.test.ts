import { JWTExpiredError, JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import Fastify from 'fastify';
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod';
import { describe, expect, it, type Mock, vi } from 'vitest';

import errorHandler from '../../plugins/error-handler';
import userinfoRoute from './userinfo';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    USERINFO_RATE_LIMIT: 60,
    USERINFO_RATE_WINDOW: 60,
  },
}));

interface TestContext {
  handler?: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>;
  options?: {
    preHandler?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  };
}

function createFastifyStub() {
  const ctx: TestContext = {};

  const fastify: FastifyInstance & {
    withTypeProvider: () => {
      get: (
        url: string,
        opts: TestContext['options'],
        handler: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
      ) => FastifyInstance;
    };
    requireJwt: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    repositories: {
      users: {
        findById: Mock;
      };
      auditLogs: {
        create: Mock;
      };
    };
  } = {
    withTypeProvider: () => ({
      get: (
        _url: string,
        opts: TestContext['options'],
        handler: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
      ) => {
        ctx.handler = handler;
        ctx.options = opts;
        return fastify;
      },
    }),
    requireJwt: vi.fn(),
    repositories: {
      users: {
        findById: vi.fn() as unknown as Mock,
      },
      auditLogs: {
        create: vi.fn() as unknown as Mock,
      },
    },
  } as unknown as FastifyInstance & {
    withTypeProvider: () => {
      get: (
        url: string,
        opts: TestContext['options'],
        handler: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
      ) => FastifyInstance;
    };
    requireJwt: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    repositories: {
      users: {
        findById: Mock;
      };
      auditLogs: {
        create: Mock;
      };
    };
  };

  return { fastify, ctx };
}

describe('GET /userinfo route', () => {
  it('registers route with requireJwt as preHandler', async () => {
    const { fastify, ctx } = createFastifyStub();

    await userinfoRoute(fastify);

    expect(ctx.handler).toBeDefined();
    expect(ctx.options?.preHandler).toBe(fastify.requireJwt);
  });

  it('returns userinfo for existing user and jwt payload', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      emailVerified: true,
    });

    const request = {
      jwtPayload: {
        sub: 'user-1',
        email: 'user@example.com',
        email_verified: true,
      },
      ip: '127.0.0.1',
      headers: {
        authorization: 'Bearer token',
        'user-agent': 'vitest',
      },
    } as unknown as FastifyRequest;

    const reply = {
      send: (body: unknown) => body,
    } as unknown as FastifyReply;

    if (!handler) {
      throw new Error('Userinfo handler was not registered');
    }

    const result = await handler(request, reply);

    expect(result).toEqual({
      sub: 'user-1',
      email: 'user@example.com',
      email_verified: true,
    });

    const auditLogMock = fastify.repositories.auditLogs.create as unknown as Mock;
    expect(auditLogMock).toHaveBeenCalledWith({
      userId: 'user-1',
      oauthClientId: null,
      event: 'oauth.userinfo.success',
      eventType: 'token',
      success: true,
      ipAddress: '127.0.0.1',
      userAgent: 'vitest',
      metadata: {},
    });
  });

  it('throws NotFoundError when user is not found', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue(null);

    const request = {
      jwtPayload: {
        sub: 'missing-user',
      },
      ip: '127.0.0.1',
      headers: {
        authorization: 'Bearer token',
        'user-agent': 'vitest',
      },
    } as unknown as FastifyRequest;

    const reply = {
      send: () => {
        throw new Error('send should not be called when user is missing');
      },
    } as unknown as FastifyReply;

    if (!handler) {
      throw new Error('Userinfo handler was not registered');
    }

    await expect(handler(request, reply)).rejects.toThrow(NotFoundError);

    const auditLogMock = fastify.repositories.auditLogs.create as unknown as Mock;
    expect(auditLogMock).toHaveBeenCalledWith({
      userId: 'missing-user',
      oauthClientId: null,
      event: 'oauth.userinfo.failure',
      eventType: 'token',
      success: false,
      ipAddress: '127.0.0.1',
      userAgent: 'vitest',
      metadata: {
        error: expect.stringContaining('missing-user'),
      },
    });
  });

  it('handles user without email gracefully', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue({
      id: 'user-2',
      email: null,
      emailVerified: false,
    });

    const request = {
      jwtPayload: {
        sub: 'user-2',
      },
      ip: '127.0.0.1',
      headers: {
        authorization: 'Bearer token',
        'user-agent': 'vitest',
      },
    } as unknown as FastifyRequest;

    const reply = {
      send: (body: unknown) => body,
    } as unknown as FastifyReply;

    if (!handler) {
      throw new Error('Userinfo handler was not registered');
    }

    const result = await handler(request, reply);

    expect(result).toEqual({
      sub: 'user-2',
      email_verified: false,
    });
  });

  it('throws JWTInvalidError when jwt payload is missing', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const request = {
      // No jwtPayload
      ip: '127.0.0.1',
      headers: {
        authorization: 'Bearer token',
        'user-agent': 'vitest',
      },
    } as unknown as FastifyRequest;

    const reply = {
      send: () => {
        throw new Error('send should not be called when jwt payload is missing');
      },
    } as unknown as FastifyReply;

    if (!handler) {
      throw new Error('Userinfo handler was not registered');
    }

    await expect(handler(request, reply)).rejects.toThrow(JWTInvalidError);

    const auditLogMock = fastify.repositories.auditLogs.create as unknown as Mock;
    expect(auditLogMock).toHaveBeenCalledWith({
      userId: null,
      oauthClientId: null,
      event: 'oauth.userinfo.failure',
      eventType: 'token',
      success: false,
      ipAddress: '127.0.0.1',
      userAgent: 'vitest',
      metadata: {
        error: 'Missing JWT payload',
      },
    });
  });

  it('returns 401 for invalid or malformed access token signature', async () => {
    const app = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    await app.register(errorHandler);

    app.get(
      '/oauth/userinfo',
      {
        preHandler: async () => {
          throw new JWTInvalidError('Invalid JWT token');
        },
      },
      async () => ({ sub: 'user-1' })
    );

    try {
      const response = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: {
          authorization: 'Bearer invalid-or-malformed-token',
          'user-agent': 'vitest',
        },
      });

      expect(response.statusCode).toBe(401);

      const json = response.json();
      expect(json).toMatchObject({
        statusCode: 401,
        error: expect.any(String),
        code: 'JWT_INVALID',
      });
    } finally {
      await app.close();
    }
  });

  it('returns 401 for expired token', async () => {
    const app = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    await app.register(errorHandler);

    app.get(
      '/oauth/userinfo',
      {
        preHandler: async () => {
          throw new JWTExpiredError('JWT token has expired');
        },
      },
      async () => ({ sub: 'user-1' })
    );

    try {
      const response = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: {
          authorization: 'Bearer expired-token',
          'user-agent': 'vitest',
        },
      });

      expect(response.statusCode).toBe(401);

      const json = response.json();
      expect(json).toMatchObject({
        statusCode: 401,
        error: 'JWT token has expired',
        code: 'JWT_EXPIRED',
      });
    } finally {
      await app.close();
    }
  });

  it('returns 401 for missing token', async () => {
    const app = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    await app.register(errorHandler);

    app.get(
      '/oauth/userinfo',
      {
        preHandler: async () => {
          throw new JWTInvalidError('Missing or malformed Authorization header');
        },
      },
      async () => ({ sub: 'user-1' })
    );

    try {
      const response = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: {
          'user-agent': 'vitest',
        },
      });

      expect(response.statusCode).toBe(401);

      const json = response.json();
      expect(json).toMatchObject({
        statusCode: 401,
        error: 'Missing or malformed Authorization header',
        code: 'JWT_INVALID',
      });
    } finally {
      await app.close();
    }
  });
});
