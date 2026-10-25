import { InvalidRequestError, JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import Fastify from 'fastify';
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

import { emitUserEvent } from '../../helpers/user-events';
import errorHandler from '../../plugins/error-handler';
import userinfoRoute from './userinfo';

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

const emitUserEventMock = vi.mocked(emitUserEvent);

beforeEach(() => {
  emitUserEventMock.mockClear();
});

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

const ISSUER = 'http://localhost:3000';
const USERINFO_URL = `${ISSUER}/oauth/userinfo`;
/**
 * The audience of a token from a client's own code flow with no `resource`:
 * `resolveAudience` falls back to the client_id. Every fixture that is not
 * about the audience rule carries it, so it reaches the claim logic.
 */
const OWN_AUDIENCE = { clientId: 'client-1', aud: 'client-1' };

interface TestContext {
  handler?: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>;
  options?: {
    preHandler?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  };
  postHandler?: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>;
  postOptions?: {
    preHandler?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  };
}

type RouteRegistrar = {
  get: (
    url: string,
    opts: TestContext['options'],
    handler: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
  ) => RouteRegistrar;
  post: (
    url: string,
    opts: TestContext['postOptions'],
    handler: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
  ) => RouteRegistrar;
};

function createFastifyStub() {
  const ctx: TestContext = {};

  const fastify: FastifyInstance & {
    withTypeProvider: () => RouteRegistrar;
    requireJwt: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    repositories: {
      users: {
        findById: Mock;
      };
      userAttributes: {
        findVerifiedByUserIdAndKey: Mock;
      };
    };
  } = {
    withTypeProvider: () => {
      const route: RouteRegistrar = {
        get: (
          _url: string,
          opts: TestContext['options'],
          handler: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
        ) => {
          ctx.handler = handler;
          ctx.options = opts;
          return route;
        },
        post: (
          _url: string,
          opts: TestContext['postOptions'],
          handler: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
        ) => {
          ctx.postHandler = handler;
          ctx.postOptions = opts;
          return route;
        },
      };
      return route;
    },
    requireJwt: vi.fn(),
    jwtUtils: {
      getIssuer: vi.fn().mockReturnValue(ISSUER),
    },
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
    },
  } as unknown as FastifyInstance & {
    withTypeProvider: () => RouteRegistrar;
    requireJwt: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    repositories: {
      users: {
        findById: Mock;
      };
      userAttributes: {
        findVerifiedByUserIdAndKey: Mock;
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

  it('returns userinfo for existing user and jwt payload — `sub` is unconditional (OIDC Core §5.3.2)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue({
      id: 'user-1',
      enabled: true,
      email: 'user@example.com',
      emailVerified: true,
    });

    const request = {
      jwtPayload: {
        ...OWN_AUDIENCE,
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

    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:userinfo.served:v1-rc.0',
      {},
      expect.objectContaining({ userId: 'user-1', clientId: 'client-1', actor: 'client' })
    );
  });

  it('returns the name claim derived from first/last name', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue({
      id: 'user-3',
      enabled: true,
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
      jwtPayload: { sub: 'user-3', scope: 'openid profile email', ...OWN_AUDIENCE },
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
      enabled: true,
      email: 'grace@example.com',
      emailVerified: true,
      firstName: 'Grace',
      lastName: 'Hopper',
    });

    const request = {
      jwtPayload: { sub: 'user-4', scope: 'openid', ...OWN_AUDIENCE },
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
      enabled: true,
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
      jwtPayload: { sub: 'user-5', scope: 'openid email', ...OWN_AUDIENCE },
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
      enabled: true,
      email: 'dorothy@example.com',
      emailVerified: true,
      firstName: 'Dorothy',
      lastName: 'Vaughan',
    });

    const request = {
      jwtPayload: { sub: 'user-6', scope: 'openid profile', ...OWN_AUDIENCE },
      ip: '127.0.0.1',
      headers: { authorization: 'Bearer token', 'user-agent': 'vitest' },
    } as unknown as FastifyRequest;
    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;

    if (!handler) throw new Error('Userinfo handler was not registered');
    const result = await handler(request, reply);

    expect(result).toEqual({ sub: 'user-6', name: 'Dorothy Vaughan' });
  });

  it('refuses a token whose subject names no user (401 invalid_token, RFC 6750 §3.1)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue(null);

    const request = {
      jwtPayload: {
        ...OWN_AUDIENCE,
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

    // A deleted user's token: not a 404, which RFC 6750 §3.1 does not define
    // for a protected resource, but the invalid-token refusal.
    await expect(handler(request, reply)).rejects.toThrow(
      new JWTInvalidError('Access token subject is not a user')
    );

    // An unconfirmed subject is not the event's subject: it names no user.
    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:userinfo.request_failed:v1-rc.0',
      { error: 'invalid_token', reason: 'subject_not_a_user' },
      expect.objectContaining({ userId: null })
    );
  });

  it('refuses the token of a user disabled since it was minted (401, no claims)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-7',
      enabled: false,
      firstName: 'Ada',
      lastName: null,
    });

    const request = {
      jwtPayload: { sub: 'user-7', scope: 'openid email profile', ...OWN_AUDIENCE },
      ip: '127.0.0.1',
      headers: { authorization: 'Bearer token', 'user-agent': 'vitest' },
    } as unknown as FastifyRequest;
    const reply = {
      send: () => {
        throw new Error('send should not be called for a disabled user');
      },
    } as unknown as FastifyReply;

    const handler = ctx.handler;
    if (!handler) throw new Error('Userinfo handler was not registered');

    await expect(handler(request, reply)).rejects.toThrow(JWTInvalidError);
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:userinfo.request_failed:v1-rc.0',
      { error: 'invalid_token', reason: 'user_disabled' },
      expect.objectContaining({ userId: 'user-7' })
    );
  });

  it('omits BOTH email claims when no verified email attribute exists (email scope granted) — BREAKING #229 (OIDC Core §5.3.2)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const findByIdMock = fastify.repositories.users.findById as unknown as Mock;
    findByIdMock.mockResolvedValue({
      id: 'user-2',
      enabled: true,
      email: null,
      emailVerified: false,
    });
    // No verified email attribute (covers both the unverified-only and the
    // zero-attribute user — the verified=true SQL filter is proven at the
    // repository integration layer).
    (fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as Mock).mockResolvedValue([]);

    const request = {
      jwtPayload: {
        ...OWN_AUDIENCE,
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

    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:userinfo.request_failed:v1-rc.0',
      { error: 'invalid_token', reason: 'missing_token' },
      expect.objectContaining({ userId: null })
    );
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

describe('POST /userinfo route (OIDC Core §5.3.1)', () => {
  const FORM = 'application/x-www-form-urlencoded';

  function withUser(fastify: FastifyInstance): void {
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-1',
      enabled: true,
      firstName: null,
      lastName: null,
    });
  }

  it('registers a POST route with a token-resolution preHandler and the shared handler', async () => {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);

    expect(ctx.postHandler).toBeDefined();
    expect(typeof ctx.postOptions?.preHandler).toBe('function');
    // The POST preHandler is NOT the bare requireJwt — it also accepts a
    // form-encoded body token — so it must be a distinct function.
    expect(ctx.postOptions?.preHandler).not.toBe(fastify.requireJwt);
    // Both methods share ONE handler reference.
    expect(ctx.postHandler).toBe(ctx.handler);
  });

  it('accepts the Bearer header and returns the same claims as GET', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as unknown as { jwtUtils: unknown }).jwtUtils = {
      getIssuer: vi.fn().mockReturnValue(ISSUER),
      extractCredentialFromHeader: vi
        .fn()
        .mockReturnValue({ scheme: 'Bearer', token: 'header.token' }),
    };
    (fastify.requireJwt as unknown as Mock).mockImplementation(
      async (req: { jwtPayload?: unknown }) => {
        req.jwtPayload = { sub: 'user-1', scope: 'openid email', ...OWN_AUDIENCE };
      }
    );
    withUser(fastify);
    await userinfoRoute(fastify);

    const request = {
      method: 'POST',
      headers: { authorization: 'Bearer header.token', 'content-type': FORM },
      body: {},
      query: {},
      ip: '127.0.0.1',
    } as unknown as FastifyRequest;
    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;

    await ctx.postOptions!.preHandler!(request, reply);
    const result = await ctx.postHandler!(request, reply);

    expect(fastify.requireJwt).toHaveBeenCalled();
    expect(result).toEqual({ sub: 'user-1', email: 'user@example.com', email_verified: true });
  });

  it('accepts a form-encoded access_token body and returns the same claims (RFC 6750 §2.2)', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as unknown as { jwtUtils: unknown }).jwtUtils = {
      getIssuer: vi.fn().mockReturnValue(ISSUER),
      // No Authorization header on the body-token path.
      extractCredentialFromHeader: vi.fn().mockReturnValue(null),
    };
    (fastify.requireJwt as unknown as Mock).mockImplementation(
      async (req: { headers: Record<string, string>; jwtPayload?: unknown }) => {
        // The body token MUST be normalised to a Bearer credential so the
        // shared verification path handles it identically to the header method.
        expect(req.headers.authorization).toBe('Bearer body.token');
        req.jwtPayload = { sub: 'user-1', scope: 'openid email', ...OWN_AUDIENCE };
      }
    );
    withUser(fastify);
    await userinfoRoute(fastify);

    const request = {
      method: 'POST',
      headers: { 'content-type': FORM },
      body: { access_token: 'body.token' },
      query: {},
      ip: '127.0.0.1',
    } as unknown as FastifyRequest;
    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;

    await ctx.postOptions!.preHandler!(request, reply);
    const result = await ctx.postHandler!(request, reply);

    expect(result).toEqual({ sub: 'user-1', email: 'user@example.com', email_verified: true });
  });

  it('rejects when neither a header nor a body token is present (missing token → 401)', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as unknown as { jwtUtils: unknown }).jwtUtils = {
      getIssuer: vi.fn().mockReturnValue(ISSUER),
      extractCredentialFromHeader: vi.fn().mockReturnValue(null),
    };
    (fastify.requireJwt as unknown as Mock).mockRejectedValue(
      new JWTInvalidError('Missing or malformed Authorization header')
    );
    await userinfoRoute(fastify);

    const request = {
      method: 'POST',
      headers: { 'content-type': FORM },
      body: {},
      query: {},
      ip: '127.0.0.1',
    } as unknown as FastifyRequest;
    const reply = {} as unknown as FastifyReply;

    await expect(ctx.postOptions!.preHandler!(request, reply)).rejects.toThrow(JWTInvalidError);
  });

  it('rejects the token being supplied by more than one method (RFC 6750 §2.2)', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as unknown as { jwtUtils: unknown }).jwtUtils = {
      getIssuer: vi.fn().mockReturnValue(ISSUER),
      extractCredentialFromHeader: vi
        .fn()
        .mockReturnValue({ scheme: 'Bearer', token: 'header.token' }),
    };
    await userinfoRoute(fastify);

    const request = {
      method: 'POST',
      headers: { authorization: 'Bearer header.token', 'content-type': FORM },
      body: { access_token: 'body.token' },
      query: {},
      ip: '127.0.0.1',
    } as unknown as FastifyRequest;
    const reply = {} as unknown as FastifyReply;

    await expect(ctx.postOptions!.preHandler!(request, reply)).rejects.toThrow(InvalidRequestError);
    expect(fastify.requireJwt).not.toHaveBeenCalled();
  });

  it('does not accept a token from the query string (RFC 6750 §2.3)', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as unknown as { jwtUtils: unknown }).jwtUtils = {
      getIssuer: vi.fn().mockReturnValue(ISSUER),
      extractCredentialFromHeader: vi.fn().mockReturnValue(null),
    };
    await userinfoRoute(fastify);

    const request = {
      method: 'POST',
      headers: { 'content-type': FORM },
      body: {},
      query: { access_token: 'query.token' },
      ip: '127.0.0.1',
    } as unknown as FastifyRequest;
    const reply = {} as unknown as FastifyReply;

    await expect(ctx.postOptions!.preHandler!(request, reply)).rejects.toThrow(InvalidRequestError);
    expect(fastify.requireJwt).not.toHaveBeenCalled();
  });

  it('ignores a body access_token when the content-type is not form-encoded', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as unknown as { jwtUtils: unknown }).jwtUtils = {
      getIssuer: vi.fn().mockReturnValue(ISSUER),
      extractCredentialFromHeader: vi.fn().mockReturnValue(null),
    };
    // With no valid token source, requireJwt throws the missing-token error.
    (fastify.requireJwt as unknown as Mock).mockImplementation(
      async (req: { headers: Record<string, string> }) => {
        // The JSON body token must NOT have been promoted to an Authorization
        // header (RFC 6750 §2.2 restricts the body method to form-encoding).
        expect(req.headers.authorization).toBeUndefined();
        throw new JWTInvalidError('Missing or malformed Authorization header');
      }
    );
    await userinfoRoute(fastify);

    const request = {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: { access_token: 'body.token' },
      query: {},
      ip: '127.0.0.1',
    } as unknown as FastifyRequest;
    const reply = {} as unknown as FastifyReply;

    await expect(ctx.postOptions!.preHandler!(request, reply)).rejects.toThrow(JWTInvalidError);
  });
});

/**
 * The audience rule (NOIEWQ7H): `requireJwt` proves only that this server issued
 * the token and that it is live. Userinfo must also refuse a token minted for
 * another resource server, or that server could read the user's claims with
 * the token it was handed (`docs/security/threat-model.md`, RFC 8707).
 */
describe('/userinfo — the token must be addressed to userinfo (RFC 8707)', () => {
  async function callWith(jwtPayload: Record<string, unknown>) {
    const { fastify, ctx } = createFastifyStub();
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-1',
      enabled: true,
      firstName: null,
      lastName: null,
    });
    await userinfoRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Userinfo handler was not registered');
    const request = {
      jwtPayload: { sub: 'user-1', scope: 'openid email', ...jwtPayload },
      ip: '127.0.0.1',
      headers: { authorization: 'Bearer token', 'user-agent': 'vitest' },
    } as unknown as FastifyRequest;
    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;
    return { fastify, run: () => handler(request, reply) };
  }

  function expectRefusedBeforeAnyLookup(fastify: FastifyInstance) {
    expect(fastify.repositories.users.findById).not.toHaveBeenCalled();
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:userinfo.request_failed:v1-rc.0',
      { error: 'invalid_token', reason: 'audience_mismatch' },
      expect.objectContaining({ userId: null })
    );
  }

  it('refuses a token bound by `resource` to another resource server', async () => {
    const { fastify, run } = await callWith({
      clientId: 'client-1',
      aud: 'https://mcp.example.com/',
    });

    await expect(run()).rejects.toThrow(JWTInvalidError);
    expectRefusedBeforeAnyLookup(fastify);
  });

  it('refuses a token minted for another client and held by it (the agent case)', async () => {
    // A front end's token, minted with `aud` = the agent it hands it to. The
    // agent is the audience, not userinfo, and the token's client is not the
    // agent; it must exchange the token instead (RFC 8693).
    const { fastify, run } = await callWith({
      clientId: 'workspace-app',
      aud: ['research-agent'],
    });

    await expect(run()).rejects.toThrow(JWTInvalidError);
    expectRefusedBeforeAnyLookup(fastify);
  });

  it('refuses a token with no audience or no client_id (fail closed)', async () => {
    const noAud = await callWith({ clientId: 'client-1', aud: undefined });
    await expect(noAud.run()).rejects.toThrow(JWTInvalidError);
    expectRefusedBeforeAnyLookup(noAud.fastify);

    const noClient = await callWith({ clientId: undefined, aud: 'client-1' });
    await expect(noClient.run()).rejects.toThrow(JWTInvalidError);
    expectRefusedBeforeAnyLookup(noClient.fastify);
  });

  it("accepts the token from a client's own code flow (`aud` = its client_id, OIDC Core §5.3)", async () => {
    const { run } = await callWith({ clientId: 'client-1', aud: 'client-1' });

    await expect(run()).resolves.toEqual({
      sub: 'user-1',
      email: 'user@example.com',
      email_verified: true,
    });
  });

  it('accepts the developer portal token from /auth/login (`aud` = `client_id` = system)', async () => {
    const { run } = await callWith({ clientId: 'system', aud: 'system', scope: undefined });

    await expect(run()).resolves.toEqual({ sub: 'user-1' });
  });

  it('accepts a token whose audience lists the userinfo endpoint beside a resource server', async () => {
    const { run } = await callWith({
      clientId: 'client-1',
      aud: ['https://mcp.example.com/', USERINFO_URL],
    });

    await expect(run()).resolves.toMatchObject({ sub: 'user-1', email: 'user@example.com' });
  });

  it('accepts a multi-audience token that includes the client itself', async () => {
    const { run } = await callWith({
      clientId: 'client-1',
      aud: ['client-1', 'https://mcp.example.com/'],
    });

    await expect(run()).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('refuses the userinfo URL of another issuer', async () => {
    const { fastify, run } = await callWith({
      clientId: 'client-1',
      aud: 'https://other-issuer.example.com/oauth/userinfo',
    });

    await expect(run()).rejects.toThrow(JWTInvalidError);
    expectRefusedBeforeAnyLookup(fastify);
  });

  it('applies the same rule to POST (shared handler)', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as unknown as { jwtUtils: unknown }).jwtUtils = {
      getIssuer: vi.fn().mockReturnValue(ISSUER),
      extractCredentialFromHeader: vi.fn().mockReturnValue(null),
    };
    (fastify.requireJwt as unknown as Mock).mockImplementation(
      async (req: { jwtPayload?: unknown }) => {
        req.jwtPayload = {
          sub: 'user-1',
          scope: 'openid email',
          clientId: 'client-1',
          aud: 'https://mcp.example.com/',
        };
      }
    );
    await userinfoRoute(fastify);

    const request = {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: { access_token: 'body.token' },
      query: {},
      ip: '127.0.0.1',
    } as unknown as FastifyRequest;
    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;

    const preHandler = ctx.postOptions?.preHandler;
    const postHandler = ctx.postHandler;
    if (!preHandler || !postHandler) throw new Error('POST /userinfo was not registered');
    await preHandler(request, reply);
    await expect(postHandler(request, reply)).rejects.toThrow(JWTInvalidError);
    expectRefusedBeforeAnyLookup(fastify);
  });
});

/**
 * #754: a `client_credentials` token carries `sub = client_id`. With no
 * `resource` and no client audience its `aud` is the client_id too, so it
 * passes the audience rule above — and userinfo then read the client_id as a
 * `users.id` (a 500 from PostgreSQL for a non-UUID id). `sub === client_id` is
 * the positive mark of a token with no end-user; it is refused before any
 * lookup, with the same 401 `invalid_token` as every other invalid token.
 */
describe('/userinfo — the token subject must be a user (#754)', () => {
  async function callWith(jwtPayload: Record<string, unknown>) {
    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Userinfo handler was not registered');
    const request = {
      jwtPayload: { scope: 'reports:read', ...jwtPayload },
      ip: '127.0.0.1',
      headers: { authorization: 'Bearer token', 'user-agent': 'vitest' },
    } as unknown as FastifyRequest;
    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;
    return { fastify, run: () => handler(request, reply) };
  }

  function expectRefusedAsNoUser(fastify: FastifyInstance, tokenSub: string) {
    expect(fastify.repositories.users.findById).not.toHaveBeenCalled();
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledTimes(1);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:userinfo.request_failed:v1-rc.0',
      { error: 'invalid_token', reason: 'subject_not_a_user' },
      // The machine token's subject is its own client: recorded as the client.
      expect.objectContaining({ userId: null, clientId: tokenSub })
    );
  }

  it('refuses a client_credentials token whose client_id is not a UUID, before any lookup', async () => {
    const { fastify, run } = await callWith({
      sub: 'reporting-service',
      clientId: 'reporting-service',
      aud: 'reporting-service',
    });

    await expect(run()).rejects.toThrow(new JWTInvalidError('Access token subject is not a user'));
    expectRefusedAsNoUser(fastify, 'reporting-service');
  });

  it('refuses a client_credentials token whose client_id is a UUID (the shape cannot decide)', async () => {
    const clientId = '019a0b9e-4c2f-7d31-9f6e-2b8c4d5e6f70';
    const { fastify, run } = await callWith({ sub: clientId, clientId, aud: clientId });

    await expect(run()).rejects.toThrow(JWTInvalidError);
    expectRefusedAsNoUser(fastify, clientId);
  });

  it('refuses a client_credentials token addressed to the userinfo endpoint', async () => {
    const { fastify, run } = await callWith({
      sub: 'reporting-service',
      clientId: 'reporting-service',
      aud: USERINFO_URL,
    });

    await expect(run()).rejects.toThrow(JWTInvalidError);
    expectRefusedAsNoUser(fastify, 'reporting-service');
  });

  it('applies the same rule to POST (shared handler)', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as unknown as { jwtUtils: unknown }).jwtUtils = {
      getIssuer: vi.fn().mockReturnValue(ISSUER),
      extractCredentialFromHeader: vi.fn().mockReturnValue(null),
    };
    (fastify.requireJwt as unknown as Mock).mockImplementation(
      async (req: { jwtPayload?: unknown }) => {
        req.jwtPayload = {
          sub: 'reporting-service',
          scope: 'reports:read',
          clientId: 'reporting-service',
          aud: 'reporting-service',
        };
      }
    );
    await userinfoRoute(fastify);

    const request = {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: { access_token: 'body.token' },
      query: {},
      ip: '127.0.0.1',
    } as unknown as FastifyRequest;
    const reply = { send: (body: unknown) => body } as unknown as FastifyReply;

    const preHandler = ctx.postOptions?.preHandler;
    const postHandler = ctx.postHandler;
    if (!preHandler || !postHandler) throw new Error('POST /userinfo was not registered');
    await preHandler(request, reply);
    await expect(postHandler(request, reply)).rejects.toThrow(JWTInvalidError);
    expectRefusedAsNoUser(fastify, 'reporting-service');
  });

  it('answers 401 with a Bearer invalid_token challenge on the wire', async () => {
    const app = Fastify({ logger: false });
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    await app.register(errorHandler);

    const { fastify, ctx } = createFastifyStub();
    await userinfoRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Userinfo handler was not registered');

    app.get(
      '/oauth/userinfo',
      {
        preHandler: async (request) => {
          (request as unknown as { jwtPayload: unknown }).jwtPayload = {
            sub: 'reporting-service',
            clientId: 'reporting-service',
            aud: 'reporting-service',
          };
        },
      },
      handler
    );

    try {
      const response = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: { authorization: 'Bearer machine.token' },
      });

      expect(response.statusCode).toBe(401);
      expect(response.headers['www-authenticate']).toBe(
        'Bearer realm="OAuth", error="invalid_token", error_description="Access token subject is not a user"'
      );
      expect(response.json()).toMatchObject({
        statusCode: 401,
        error: 'Access token subject is not a user',
        code: 'JWT_INVALID',
      });
    } finally {
      await app.close();
    }
  });

  it("still answers a user's token whose client_id differs from its subject", async () => {
    const { fastify, run } = await callWith({
      sub: '019a0b9e-4c2f-7d31-9f6e-2b8c4d5e6f71',
      clientId: 'client-1',
      aud: 'client-1',
      scope: 'openid',
    });
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: '019a0b9e-4c2f-7d31-9f6e-2b8c4d5e6f71',
      enabled: true,
      firstName: null,
      lastName: null,
    });

    await expect(run()).resolves.toEqual({ sub: '019a0b9e-4c2f-7d31-9f6e-2b8c4d5e6f71' });
    expect(fastify.repositories.users.findById).toHaveBeenCalledWith(
      '019a0b9e-4c2f-7d31-9f6e-2b8c4d5e6f71'
    );
  });
});
