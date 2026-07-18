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
      userAttributes: {
        findVerifiedByUserIdAndKey: Mock;
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
      // #229: email claims resolve from verified attributes under the email
      // scope; the default fixture mirrors the pre-#229 user values.
      userAttributes: {
        findVerifiedByUserIdAndKey: vi.fn().mockResolvedValue([
          {
            id: 'attr-1',
            userId: 'user-1',
            source: 'self_reported',
            attrKey: 'email',
            attrValue: 'user@example.com',
            verified: true,
            expiresAt: null,
            createdAt: 1,
            updatedAt: 1,
          },
        ]) as unknown as Mock,
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
      userAttributes: {
        findVerifiedByUserIdAndKey: Mock;
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
        // OIDC §5.4: email claims require the `email` scope on the token.
        scope: 'openid email',
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

  it('returns the name claim derived from first/last name', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue({
      id: 'user-3',
      email: 'ada@example.com',
      emailVerified: true,
      firstName: 'Ada',
      lastName: 'Lovelace',
    });
    // #229: the email claim is resolver-sourced from the verified attribute.
    (fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as Mock).mockResolvedValue([
      {
        id: 'attr-3',
        userId: 'user-3',
        source: 'self_reported',
        attrKey: 'email',
        attrValue: 'ada@example.com',
        verified: true,
        expiresAt: null,
        createdAt: 1,
        updatedAt: 1,
      },
    ]);

    const request = {
      // `profile` releases the name claim; `email` releases the email claims.
      jwtPayload: { sub: 'user-3', scope: 'openid profile email' },
      ip: '127.0.0.1',
      headers: { authorization: 'Bearer token', 'user-agent': 'vitest' },
    } as unknown as FastifyRequest;

    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;

    if (!handler) {
      throw new Error('Userinfo handler was not registered');
    }

    const result = await handler(request, reply);

    expect(result).toEqual({
      sub: 'user-3',
      email: 'ada@example.com',
      email_verified: true,
      name: 'Ada Lovelace',
    });
  });

  it('omits email and name when the token grants only openid (OIDC §5.4)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue({
      id: 'user-4',
      email: 'grace@example.com',
      emailVerified: true,
      firstName: 'Grace',
      lastName: 'Hopper',
    });

    const request = {
      jwtPayload: { sub: 'user-4', scope: 'openid' },
      ip: '127.0.0.1',
      headers: { authorization: 'Bearer token', 'user-agent': 'vitest' },
    } as unknown as FastifyRequest;
    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;

    if (!handler) throw new Error('Userinfo handler was not registered');
    const result = await handler(request, reply);

    // Only `sub` is released — no email, email_verified, or name.
    expect(result).toEqual({ sub: 'user-4' });
    // #229: without the `email` scope the resolver query is skipped entirely.
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).not.toHaveBeenCalled();
  });

  it('includes email but not name when the token grants openid email only', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue({
      id: 'user-5',
      email: 'katherine@example.com',
      emailVerified: true,
      firstName: 'Katherine',
      lastName: 'Johnson',
    });
    (fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as Mock).mockResolvedValue([
      {
        id: 'attr-5',
        userId: 'user-5',
        source: 'self_reported',
        attrKey: 'email',
        attrValue: 'katherine@example.com',
        verified: true,
        expiresAt: null,
        createdAt: 1,
        updatedAt: 1,
      },
    ]);

    const request = {
      jwtPayload: { sub: 'user-5', scope: 'openid email' },
      ip: '127.0.0.1',
      headers: { authorization: 'Bearer token', 'user-agent': 'vitest' },
    } as unknown as FastifyRequest;
    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;

    if (!handler) throw new Error('Userinfo handler was not registered');
    const result = await handler(request, reply);

    // #229: email present implies verified (presence IS the signal).
    expect(result).toEqual({
      sub: 'user-5',
      email: 'katherine@example.com',
      email_verified: true,
    });
  });

  it('includes name but not email when the token grants openid profile only', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue({
      id: 'user-6',
      email: 'dorothy@example.com',
      emailVerified: true,
      firstName: 'Dorothy',
      lastName: 'Vaughan',
    });

    const request = {
      jwtPayload: { sub: 'user-6', scope: 'openid profile' },
      ip: '127.0.0.1',
      headers: { authorization: 'Bearer token', 'user-agent': 'vitest' },
    } as unknown as FastifyRequest;
    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;

    if (!handler) throw new Error('Userinfo handler was not registered');
    const result = await handler(request, reply);

    expect(result).toEqual({ sub: 'user-6', name: 'Dorothy Vaughan' });
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

  it('omits BOTH email claims when no verified email attribute exists (email scope granted) — BREAKING #229', async () => {
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
    // No verified email attribute (covers both the unverified-only and the
    // zero-attribute user — the verified=true SQL filter is proven at the
    // repository integration layer).
    (fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as Mock).mockResolvedValue([]);

    const request = {
      jwtPayload: {
        sub: 'user-2',
        // The `email` scope IS granted, but with no verified attribute BOTH
        // claims are omitted entirely (never null) — OIDC Core §5.3.2.
        scope: 'openid email',
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

    expect(result).toEqual({ sub: 'user-2' });
    // Omitted means the KEYS are absent, not undefined/null-valued.
    expect('email' in (result as Record<string, unknown>)).toBe(false);
    expect('email_verified' in (result as Record<string, unknown>)).toBe(false);
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
