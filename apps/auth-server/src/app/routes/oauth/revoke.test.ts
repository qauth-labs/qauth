import { InvalidClientError } from '@qauth-labs/shared-errors';
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
    INTROSPECT_RATE_LIMIT: 60,
    INTROSPECT_RATE_WINDOW: 60,
  },
}));

import revokeRoute from './revoke';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

const ISSUER = 'https://auth.example.com';

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
        findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'default', enabled: true }),
        create: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'default', enabled: true }),
      },
      oauthClients: {
        findByClientId: vi.fn(),
      },
      refreshTokens: {
        findByTokenHashIncludingRevoked: vi.fn(),
        revokeFamily: vi.fn().mockResolvedValue(1),
      },
      auditLogs: {
        create: vi.fn(),
      },
    },
    passwordHasher: {
      verifyPassword: vi.fn().mockResolvedValue(true),
    },
    jwtUtils: {
      verifyAccessToken: vi.fn(),
      hashRefreshToken: (t: string) => `hash:${t}`,
      getIssuer: () => ISSUER,
    },
    redis: {
      setex: vi.fn().mockResolvedValue('OK'),
      exists: vi.fn().mockResolvedValue(0),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };

  return { fastify: fastify as FastifyInstance, ctx };
}

const client = {
  id: 'client-row-1',
  clientId: 'client-123',
  clientSecretHash: 'hashed-secret',
  enabled: true,
  audience: null,
};

function makeReply() {
  const replies: any[] = [];
  let statusCode = 200;
  const reply = {
    code(c: number) {
      statusCode = c;
      return reply;
    },
    send(body: unknown) {
      replies.push(body);
      return body;
    },
    get statusCode() {
      return statusCode;
    },
  };
  return { reply, replies };
}

describe('POST /oauth/revoke route (RFC 7009)', () => {
  it('revokes the family of an owned refresh token and returns 200', async () => {
    const { fastify, ctx } = createFastifyStub();
    await revokeRoute(fastify);

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({
      id: 'rt-1',
      oauthClientId: client.id,
      familyId: 'fam-1',
    });

    const { reply } = makeReply();
    await ctx.handler!(
      {
        body: { token: 'rt-token', client_id: client.clientId, client_secret: 'secret' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      },
      reply
    );

    expect(reply.statusCode).toBe(200);
    expect(fastify.repositories.refreshTokens.revokeFamily).toHaveBeenCalledWith(
      'fam-1',
      'client_revocation'
    );
  });

  it('is a no-op (still 200) when the refresh token belongs to a different client', async () => {
    const { fastify, ctx } = createFastifyStub();
    await revokeRoute(fastify);

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({
      id: 'rt-2',
      oauthClientId: 'some-other-client',
      familyId: 'fam-2',
    });
    // Not a JWT either, so the access-token fallback verify rejects.
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(new Error('bad'));

    const { reply } = makeReply();
    await ctx.handler!(
      {
        body: { token: 'rt-token', client_id: client.clientId, client_secret: 'secret' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      },
      reply
    );

    expect(reply.statusCode).toBe(200);
    // Cross-client revocation must NOT touch the family.
    expect(fastify.repositories.refreshTokens.revokeFamily).not.toHaveBeenCalled();
  });

  it('returns 200 with no revocation for an unknown/invalid token', async () => {
    const { fastify, ctx } = createFastifyStub();
    await revokeRoute(fastify);

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(undefined);
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(new Error('bad jwt'));

    const { reply } = makeReply();
    await ctx.handler!(
      {
        body: { token: 'garbage', client_id: client.clientId, client_secret: 'secret' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      },
      reply
    );

    expect(reply.statusCode).toBe(200);
    expect(fastify.repositories.refreshTokens.revokeFamily).not.toHaveBeenCalled();
    expect(fastify.redis.setex).not.toHaveBeenCalled();
  });

  it('denylists the jti of an owned access token with its remaining TTL', async () => {
    const { fastify, ctx } = createFastifyStub();
    await revokeRoute(fastify);

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    // No refresh-token row → falls through to the access-token path.
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(undefined);
    const futureExp = Math.floor(Date.now() / 1000) + 600;
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: 'user-1',
      clientId: client.clientId,
      jti: 'jti-123',
      exp: futureExp,
    });

    const { reply } = makeReply();
    await ctx.handler!(
      {
        body: {
          token: 'access-token',
          token_type_hint: 'access_token',
          client_id: client.clientId,
          client_secret: 'secret',
        },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      },
      reply
    );

    expect(reply.statusCode).toBe(200);
    expect(fastify.redis.setex).toHaveBeenCalledTimes(1);
    const [key, ttl] = (fastify.redis.setex as unknown as Mock).mock.calls[0];
    expect(key).toBe('revoked-access-token:jti-123');
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(600);
  });

  it('does NOT denylist an access token issued to a different client', async () => {
    const { fastify, ctx } = createFastifyStub();
    await revokeRoute(fastify);

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(undefined);
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: 'user-1',
      clientId: 'a-different-client',
      jti: 'jti-999',
      exp: Math.floor(Date.now() / 1000) + 600,
    });

    const { reply } = makeReply();
    await ctx.handler!(
      {
        body: {
          token: 'access-token',
          token_type_hint: 'access_token',
          client_id: client.clientId,
          client_secret: 'secret',
        },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      },
      reply
    );

    expect(reply.statusCode).toBe(200);
    expect(fastify.redis.setex).not.toHaveBeenCalled();
  });

  it('rejects with invalid_client when client authentication fails', async () => {
    const { fastify, ctx } = createFastifyStub();
    await revokeRoute(fastify);

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(false);

    const { reply } = makeReply();
    await expect(
      ctx.handler!(
        {
          body: { token: 'whatever', client_id: client.clientId, client_secret: 'wrong' },
          ip: '127.0.0.1',
          headers: { 'user-agent': 'vitest' },
        },
        reply
      )
    ).rejects.toBeInstanceOf(InvalidClientError);
  });
});
