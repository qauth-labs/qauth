import { JWTInvalidError, NotFoundError } from '@qauth/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

import userinfoRoute from './userinfo';

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
  });
});
