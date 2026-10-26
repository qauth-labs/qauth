import { InvalidClientError, JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

import { supplyRequestRealm, testRealm } from '../../../testing/request-realm';
import { emitUserEvent } from '../../helpers/user-events';

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
    INTROSPECT_RATE_LIMIT: 60,
    INTROSPECT_RATE_WINDOW: 60,
  },
}));

import errorHandler from '../../plugins/error-handler';
import introspectRoute from './introspect';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

const REALM = testRealm({ id: 'realm-1' });

function createFastifyStub() {
  const ctx: TestContext = {};

  const fastify: any = {
    withTypeProvider: () => ({
      post: (
        _url: string,
        _opts: unknown,
        handler: (request: any, reply: any) => Promise<unknown>
      ) => {
        ctx.handler = (request, reply) => {
          // The realm resolver's decoration (#486): a request reaches its
          // handler with the realm of its host.
          request.realm ??= REALM;
          return handler(request, reply);
        };
        return fastify;
      },
    }),
    repositories: {
      oauthClients: {
        findByClientId: vi.fn(),
      },
      // A user subject is reported active only while its account is enabled.
      users: {
        findById: vi.fn(async (id: string) => ({ id, enabled: true })),
      },
    },
    passwordHasher: {
      verifyPassword: vi.fn(),
    },
    jwtUtils: {
      verifyAccessToken: vi.fn(),
      getIssuer: () => 'https://auth.example.com',
      // Classical deployment by default (#275): no PQC material is looked up
      // and no `pqc_signature` appears in the response.
      isHybridSigningEnabled: () => false,
    },
    redis: {
      // Default: nothing is revoked. Individual tests override `exists`.
      exists: vi.fn().mockResolvedValue(0),
      setex: vi.fn().mockResolvedValue('OK'),
      get: vi.fn().mockResolvedValue(null),
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
    const userUuid = '019dbc24-7a2d-724d-bf26-1923f21f2234';
    verifyAccessTokenMock.mockResolvedValue({
      sub: userUuid,
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
      sub: userUuid,
      client_id: client.clientId,
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
      token_type: 'Bearer',
    });

    // A user token: its confirmed user is the event's subject.
    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:token.introspected:v1-rc.0',
      { tokenClientId: client.clientId },
      expect.objectContaining({
        realmId: 'realm-1',
        userId: userUuid,
        clientId: client.clientId,
        actor: 'client',
      })
    );
  });

  it("authenticates the caller in the request's realm and records that realm (#487)", async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
    };
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: client.clientId,
      clientId: client.clientId,
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const handler = ctx.handler;
    if (!handler) throw new Error('Introspect handler was not registered');
    await handler(
      {
        body: { token: 'valid-token', client_id: client.clientId, client_secret: 'secret' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
        realm: testRealm({ id: 'realm-tenant' }),
      },
      { send: (body: unknown) => body }
    );

    expect(fastify.repositories.oauthClients.findByClientId).toHaveBeenCalledWith(
      'realm-tenant',
      client.clientId
    );
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:token.introspected:v1-rc.0',
      expect.anything(),
      expect.objectContaining({ realmId: 'realm-tenant', clientId: client.clientId })
    );
  });

  it('reports a DPoP-bound token as DPoP with its cnf.jkt (RFC 9449 §6.2, #480)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);
    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
    };
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    const jkt = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: '019dbc24-7a2d-724d-bf26-1923f21f2234',
      clientId: client.clientId,
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
      cnf: { jkt },
    });

    const result = await ctx.handler!(
      {
        body: { token: 'bound-token', client_id: client.clientId, client_secret: 'secret' },
        ip: '127.0.0.1',
        headers: {},
      },
      { send: (body: unknown) => body }
    );

    // The resource server checks the request's proof against it; introspection
    // itself checks none (RFC 9449 §6.2).
    expect(result).toMatchObject({ active: true, token_type: 'DPoP', cnf: { jkt } });
  });

  describe('disabled users', () => {
    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
    };
    const userUuid = '019dbc24-7a2d-724d-bf26-1923f21f2234';

    async function introspect(fastify: FastifyInstance, ctx: TestContext, sub: string) {
      await introspectRoute(fastify);
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        client
      );
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
        sub,
        clientId: client.clientId,
        exp: 1234567890,
        iat: 1234567800,
        iss: 'https://auth.example.com',
      });
      const handler = ctx.handler;
      if (!handler) throw new Error('Introspect handler was not registered');
      return handler(
        {
          body: { token: 'valid-token', client_id: client.clientId, client_secret: 'secret' },
          ip: '127.0.0.1',
          headers: { 'user-agent': 'vitest' },
        },
        { send: (body: unknown) => body }
      );
    }

    it('reports the token of a user disabled since it was minted as inactive', async () => {
      const { fastify, ctx } = createFastifyStub();
      (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
        id: userUuid,
        enabled: false,
      });

      await expect(introspect(fastify, ctx, userUuid)).resolves.toEqual({ active: false });
      expect(fastify.repositories.users.findById).toHaveBeenCalledWith(userUuid);
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        'urn:qauth:event:token.introspection_failed:v1-rc.0',
        { error: 'invalid_token', reason: 'user_disabled' },
        expect.objectContaining({ userId: userUuid, clientId: client.clientId })
      );
    });

    it('reports the token of a user that no longer exists as inactive', async () => {
      const { fastify, ctx } = createFastifyStub();
      (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(undefined);

      await expect(introspect(fastify, ctx, userUuid)).resolves.toEqual({ active: false });
      // An unknown subject names no user: the event has no subject.
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        'urn:qauth:event:token.introspection_failed:v1-rc.0',
        { error: 'invalid_token', reason: 'subject_unknown' },
        expect.objectContaining({ userId: null, clientId: client.clientId })
      );
    });

    it('never looks up a client_credentials subject (sub = client_id) as a user', async () => {
      // A dynamically registered client's id is a random UUID, so the UUID
      // shape alone does not mark a user subject.
      const { fastify, ctx } = createFastifyStub();
      client.clientId = userUuid;
      try {
        await expect(introspect(fastify, ctx, userUuid)).resolves.toMatchObject({
          active: true,
        });
        expect(fastify.repositories.users.findById).not.toHaveBeenCalled();
      } finally {
        client.clientId = 'client-123';
      }
    });
  });

  it('returns active: false for a signature-valid token whose jti is revoked (RFC 7009)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
      audience: null,
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: '019dbc24-7a2d-724d-bf26-1923f21f2234',
      clientId: client.clientId,
      jti: 'revoked-jti',
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });
    // The token's jti is on the denylist.
    (fastify.redis.exists as unknown as Mock).mockResolvedValue(1);

    const replyBody: any[] = [];
    const reply = { send: (b: unknown) => (replyBody.push(b), b) };

    const result = await ctx.handler!(
      {
        body: { token: 'revoked-token', client_id: client.clientId, client_secret: 'secret' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      },
      reply
    );

    expect(fastify.redis.exists).toHaveBeenCalledWith('revoked-access-token:revoked-jti');
    expect(result).toEqual({ active: false });
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:token.introspection_failed:v1-rc.0',
      { error: 'invalid_token', reason: 'token_revoked' },
      // Inactive before the user check: the event has no subject.
      { realmId: 'realm-1', clientId: client.clientId, actor: 'client' }
    );
  });

  it('records no user subject when sub is not UUID-shaped (client_credentials)', async () => {
    // client_credentials tokens have sub === clientId (a slug): the token
    // has no user, so the success event has no user subject. The token's
    // client is the event's `tokenClientId`.
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: '019dbc24-7bc9-725c-81c3-71bd0c78c4ad',
      clientId: 'resource-server',
      clientSecretHash: 'hashed-secret',
      enabled: true,
      audience: ['api.example.com'],
    };
    const callerClientId = 'caller-machine';

    const findByClientIdMock = fastify.repositories.oauthClients.findByClientId as unknown as Mock;
    const verifyPasswordMock = fastify.passwordHasher.verifyPassword as unknown as Mock;
    const verifyAccessTokenMock = fastify.jwtUtils.verifyAccessToken as unknown as Mock;

    findByClientIdMock.mockResolvedValue(client);
    verifyPasswordMock.mockResolvedValue(true);
    verifyAccessTokenMock.mockResolvedValue({
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

    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:token.introspected:v1-rc.0',
      { tokenClientId: callerClientId },
      expect.objectContaining({ userId: null, clientId: client.clientId, actor: 'client' })
    );
  });

  it('records no user subject when sub is non-UUID but differs from clientId (forward-compat: service-account / prefixed subs)', async () => {
    // Guards against a future grant type that emits sub !== clientId but
    // still non-UUID (service accounts, prefixed identifiers). The fix
    // must be shape-gated, not coupled to sub-equals-clientId.
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);

    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: '019dbc24-8aaa-7aaa-aaaa-aaaaaaaaaaaa',
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
      sub: 'svc:billing-reporter',
      clientId: 'caller-machine',
      scope: 'api:read',
      aud: 'api.example.com',
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const request = {
      body: { token: 'svc-token', client_id: client.clientId, client_secret: 'secret' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };
    const reply = { send: (body: unknown) => body };

    if (!handler) throw new Error('Introspect handler was not registered');

    const result = (await handler(request, reply)) as { active: boolean };
    expect(result.active).toBe(true);

    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:token.introspected:v1-rc.0',
      { tokenClientId: 'caller-machine' },
      expect.objectContaining({ userId: null, clientId: client.clientId })
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

    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:token.introspection_failed:v1-rc.0',
      { error: 'invalid_token', reason: 'token_expired' },
      { realmId: 'realm-1', clientId: client.clientId, actor: 'client' }
    );
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
    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:token.introspection_failed:v1-rc.0',
      { error: 'invalid_token', reason: 'client_not_authorized' },
      { realmId: 'realm-1', clientId: client.clientId, actor: 'client' }
    );
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

  // #509: QAuth itself is the only resource server for its API families, so a
  // family audience in a client's list never lets it read another client's
  // family token.
  it.each([
    ['the family audience alone', ['urn:qauth:aud:account:v1-rc.0']],
    ['the family audience beside its own', ['urn:qauth:aud:account:v1-rc.0', 'api.example.com']],
  ])(
    'returns active: false for another client’s family token when the client lists %s',
    async (_label, audience) => {
      const { fastify, ctx } = createFastifyStub();
      await introspectRoute(fastify);
      if (!ctx.handler) throw new Error('Introspect handler was not registered');

      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
        id: 'client-family',
        clientId: 'account-console',
        clientSecretHash: 'hashed-secret',
        enabled: true,
        audience,
      });
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
        sub: 'user-1',
        clientId: 'caller-app',
        aud: 'urn:qauth:aud:account:v1-rc.0',
        exp: 1234567890,
        iat: 1234567800,
        iss: 'https://auth.example.com',
      });

      const result = await ctx.handler(
        {
          body: { token: 'family-token', client_id: 'account-console', client_secret: 'secret' },
          ip: '127.0.0.1',
          headers: { 'user-agent': 'vitest' },
        },
        { send: (body: unknown) => body }
      );
      expect(result).toEqual({ active: false });
    }
  );

  it('still lets a client introspect its own family token', async () => {
    const { fastify, ctx } = createFastifyStub();
    await introspectRoute(fastify);
    if (!ctx.handler) throw new Error('Introspect handler was not registered');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'client-family',
      clientId: 'account-console',
      clientSecretHash: 'hashed-secret',
      enabled: true,
      audience: ['urn:qauth:aud:account:v1-rc.0'],
    });
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: 'user-1',
      clientId: 'account-console',
      aud: 'urn:qauth:aud:account:v1-rc.0',
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const result = (await ctx.handler(
      {
        body: { token: 'own-token', client_id: 'account-console', client_secret: 'secret' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      },
      { send: (body: unknown) => body }
    )) as { active: boolean };
    expect(result.active).toBe(true);
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
    // The caller did not authenticate: the event names no client, and the
    // catch-all records no second failure.
    expect(emitUserEventMock).toHaveBeenCalledTimes(1);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:token.introspection_failed:v1-rc.0',
      { error: 'invalid_client', reason: 'client_authentication_failed' },
      { realmId: 'realm-1', actor: 'client' }
    );
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

    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:token.introspection_failed:v1-rc.0',
      { error: 'invalid_token', reason: 'token_invalid' },
      { realmId: 'realm-1', clientId: client.clientId, actor: 'client' }
    );
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

    expect(emitUserEventMock).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:token.introspection_failed:v1-rc.0',
      { error: 'invalid_token', reason: 'token_invalid' },
      { realmId: 'realm-1', clientId: client.clientId, actor: 'client' }
    );
  });

  it('returns 400 for missing or empty token', async () => {
    const app = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    app.decorate('repositories', {
      oauthClients: { findByClientId: vi.fn() },
    } as any);
    app.decorate('passwordHasher', { verifyPassword: vi.fn() } as any);
    app.decorate('jwtUtils', { verifyAccessToken: vi.fn() } as any);

    supplyRequestRealm(app, REALM);
    // The error handler first, as the app registers it: a route registered
    // before it keeps Fastify's default handler (#365).
    await app.register(errorHandler);
    await app.register(introspectRoute);

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

      // RFC 7662 §2.3 / RFC 6749 §5.2: the OAuth error body, nothing QAuth adds.
      expect(response.statusCode).toBe(400);
      expect(response.headers['content-type']).toMatch(/^application\/json(?:;|$)/);
      const json = response.json() as Record<string, unknown>;
      expect(json).toMatchObject({ error: 'invalid_request' });
      for (const member of ['code', 'statusCode']) {
        expect(json).not.toHaveProperty(member);
      }
    } finally {
      await app.close();
    }
  });
});

describe('POST /oauth/introspect — PQC reference delivery (ADR-005 / #275)', () => {
  const userUuid = '019dbc24-7a2d-724d-bf26-1923f21f2234';

  /** Drive the route handler for an authorized, valid-token introspection. */
  /**
   * A compact JWS whose PROTECTED HEADER advertises `pqc_alg`. The PQC lookup
   * is gated on the token's (already-verified) header rather than on the
   * server's current issuance posture, so a stub token must carry a realistic
   * header for the hybrid path to be exercised at all.
   */
  function tokenWithHeader(header: Record<string, unknown>): string {
    const encode = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    return `${encode(header)}.${encode({ sub: userUuid })}.c2ln`;
  }

  const HYBRID_TOKEN = tokenWithHeader({ alg: 'EdDSA', pqc_alg: 'ML-DSA-65', pqc_kid: 'mldsa-1' });

  async function introspectValidToken(
    fastify: FastifyInstance,
    ctx: TestContext,
    token = 'valid-token'
  ) {
    const client = {
      id: 'client-1',
      clientId: 'client-123',
      clientSecretHash: 'hashed-secret',
      enabled: true,
    };
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: userUuid,
      clientId: client.clientId,
      jti: 'jti-1',
      exp: 1234567890,
      iat: 1234567800,
      iss: 'https://auth.example.com',
    });

    const request = {
      body: { token, client_id: client.clientId, client_secret: 'secret' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };
    const reply = { send: (body: unknown) => body };
    if (!ctx.handler) throw new Error('Introspect handler was not registered');
    return (await ctx.handler(request, reply)) as Record<string, unknown>;
  }

  it('returns the detached pqcSignature when the server issues hybrid tokens', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as any).jwtUtils.isHybridSigningEnabled = () => true;
    (fastify.redis.get as unknown as Mock).mockResolvedValue(
      JSON.stringify({ pqcSignature: 'BASE64URL_ML_DSA_SIG', pqcAlg: 'ML-DSA-65' })
    );
    await introspectRoute(fastify);

    const result = await introspectValidToken(fastify, ctx, HYBRID_TOKEN);

    expect(result['active']).toBe(true);
    expect(result['pqc_signature']).toBe('BASE64URL_ML_DSA_SIG');
    expect(result['pqc_alg']).toBe('ML-DSA-65');
    // Looked up by the VERIFIED token's jti, never by client-supplied input.
    expect(fastify.redis.get).toHaveBeenCalledWith('pqc-signature:jti-1');
  });

  it('omits the PQC fields entirely on a classical deployment', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify.redis.get as unknown as Mock).mockResolvedValue(null);
    await introspectRoute(fastify);

    const result = await introspectValidToken(fastify, ctx);

    expect(result['active']).toBe(true);
    expect(result).not.toHaveProperty('pqc_signature');
    expect(result).not.toHaveProperty('pqc_alg');
  });

  it('still serves stored PQC material after HYBRID_SIGNING_ENABLED is turned OFF', async () => {
    // Rollback safety. Since #248 F1 a signed `pqc_alg` is BINDING, so a token
    // minted while the flag was on is REJECTED by every PQC-aware verifier if
    // introspection stops returning its detached signature. Gating retrieval on
    // the current issuance posture would therefore make flipping the flag off a
    // hard outage for one full token lifetime, rather than a graceful rollback.
    // The TTL-bounded store drains on its own; retrieval must not be gated.
    const { fastify, ctx } = createFastifyStub();
    // Issuance is OFF...
    (fastify as any).jwtUtils.isHybridSigningEnabled = () => false;
    // ...but a token minted before the flip still has its signature stored.
    (fastify.redis.get as unknown as Mock).mockResolvedValue(
      JSON.stringify({ pqcSignature: 'BASE64URL_ML_DSA_SIG', pqcAlg: 'ML-DSA-65' })
    );
    await introspectRoute(fastify);

    const result = await introspectValidToken(fastify, ctx, HYBRID_TOKEN);

    expect(result['active']).toBe(true);
    expect(result['pqc_signature']).toBe('BASE64URL_ML_DSA_SIG');
    expect(result['pqc_alg']).toBe('ML-DSA-65');
  });

  it('a store miss degrades gracefully: still active, just no PQC material', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as any).jwtUtils.isHybridSigningEnabled = () => true;
    (fastify.redis.get as unknown as Mock).mockResolvedValue(null);
    await introspectRoute(fastify);

    const result = await introspectValidToken(fastify, ctx);

    expect(result['active']).toBe(true);
    expect(result).not.toHaveProperty('pqc_signature');
  });

  it('a Redis OUTAGE degrades to a miss rather than failing introspection', async () => {
    // The `active` decision does not depend on the store at all, so a store
    // outage must not turn a valid introspection into a 500. The PQC-aware
    // resource server still fails closed on its own: since #248 F1 a token
    // whose signed header advertises `pqc_alg` is rejected when the detached
    // signature is absent.
    const { fastify, ctx } = createFastifyStub();
    (fastify as any).jwtUtils.isHybridSigningEnabled = () => true;
    (fastify.redis.get as unknown as Mock).mockRejectedValue(
      new Error("READONLY You can't write against a read only replica.")
    );
    await introspectRoute(fastify);

    const result = await introspectValidToken(fastify, ctx, HYBRID_TOKEN);

    expect(result['active']).toBe(true);
    expect(result).not.toHaveProperty('pqc_signature');
  });

  it('a corrupt store entry is treated as a miss, never surfaced', async () => {
    const { fastify, ctx } = createFastifyStub();
    (fastify as any).jwtUtils.isHybridSigningEnabled = () => true;
    (fastify.redis.get as unknown as Mock).mockResolvedValue('{not json');
    await introspectRoute(fastify);

    const result = await introspectValidToken(fastify, ctx);

    expect(result['active']).toBe(true);
    expect(result).not.toHaveProperty('pqc_signature');
  });
});
