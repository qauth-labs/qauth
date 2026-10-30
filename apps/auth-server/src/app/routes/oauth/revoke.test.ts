import { InvalidClientError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

import { testRealm } from '../../../testing/request-realm';
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

import revokeRoute from './revoke';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

const ISSUER = 'https://auth.example.com';
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
      refreshTokens: {
        findByTokenHashIncludingRevoked: vi.fn(),
        revokeFamily: vi.fn().mockResolvedValue(1),
      },
      users: {
        // The realm's users: `user-1` only.
        findById: vi.fn(async (_realmId: string, id: string) =>
          id === 'user-1' ? { id: 'user-1' } : undefined
        ),
      },
    },
    passwordHasher: {
      verifyPassword: vi.fn().mockResolvedValue(true),
    },
    jwtUtils: {
      verifyAccessToken: vi.fn(),
      hashRefreshToken: (t: string) => `hash:${t}`,
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
      userId: 'user-1',
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
    // No hint was sent, so the event carries none. The token's user is the
    // subject, which an SSF stream matches on (#540).
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:token.revoked:v1-rc.0',
      {},
      expect.objectContaining({
        realmId: 'realm-1',
        userId: 'user-1',
        clientId: client.clientId,
        actor: 'client',
      })
    );
  });

  it("authenticates the client in the request's realm and records that realm (#487)", async () => {
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

    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');
    const { reply } = makeReply();
    await handler(
      {
        body: { token: 'rt-token', client_id: client.clientId, client_secret: 'secret' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
        realm: testRealm({ id: 'realm-tenant' }),
      },
      reply
    );

    expect(fastify.repositories.oauthClients.findByClientId).toHaveBeenCalledWith(
      'realm-tenant',
      client.clientId
    );
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:token.revoked:v1-rc.0',
      {},
      expect.objectContaining({ realmId: 'realm-tenant' })
    );
  });

  it('revokes an owned refresh token even when the hint says access_token (§2.1)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await revokeRoute(fastify);

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    // Not a JWT, so the hinted access-token lookup finds nothing.
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTInvalidError('bad jwt')
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({
      id: 'rt-1',
      oauthClientId: client.id,
      familyId: 'fam-1',
    });

    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');
    const { reply } = makeReply();
    await handler(
      {
        body: {
          token: 'rt-token',
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
    expect(fastify.repositories.refreshTokens.revokeFamily).toHaveBeenCalledWith(
      'fam-1',
      'client_revocation'
    );
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:token.revoked:v1-rc.0',
      { typeHint: 'access_token' },
      expect.objectContaining({ clientId: client.clientId, actor: 'client' })
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
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTInvalidError('bad')
    );

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
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new JWTInvalidError('bad jwt')
    );

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

  it('fails, rather than answering 200, when the access token could not be checked (#491)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await revokeRoute(fastify);

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(undefined);
    // Verification reads the realm's keys from the key store; it is down.
    const outage = new Error('connection refused');
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(outage);

    const { reply } = makeReply();
    await expect(
      ctx.handler!(
        {
          body: { token: 'a.b.c', client_id: client.clientId, client_secret: 'secret' },
          ip: '127.0.0.1',
          headers: { 'user-agent': 'vitest' },
        },
        reply
      )
    ).rejects.toBe(outage);
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
    // Verified in the request's realm: its keys, its issuer pinned (#490, #491).
    expect(fastify.jwtUtils.verifyAccessToken).toHaveBeenCalledWith(
      { id: 'realm-1', issuer: ISSUER },
      'access-token'
    );
    expect(fastify.redis.setex).toHaveBeenCalledTimes(1);
    const [key, ttl] = (fastify.redis.setex as unknown as Mock).mock.calls[0];
    expect(key).toBe('revoked-access-token:jti-123');
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(600);
    // The token's `sub` is one of the realm's users: the event's subject.
    expect(fastify.repositories.users.findById).toHaveBeenCalledWith('realm-1', 'user-1');
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:token.revoked:v1-rc.0',
      { typeHint: 'access_token' },
      expect.objectContaining({ userId: 'user-1' })
    );
  });

  it.each([
    ['a client’s own token, whose sub is its client_id', () => client.clientId],
    ['a token whose sub names no user of the realm', () => 'someone-else'],
  ])('names no user for %s (#540)', async (_label, sub) => {
    const { fastify, ctx } = createFastifyStub();
    await revokeRoute(fastify);

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(undefined);
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: sub(),
      clientId: client.clientId,
      jti: 'jti-own',
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
    expect(fastify.redis.setex).toHaveBeenCalledTimes(1);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:token.revoked:v1-rc.0',
      { typeHint: 'access_token' },
      expect.objectContaining({ userId: null })
    );
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
    // The caller did not authenticate: the event names no client.
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:token.revocation_failed:v1-rc.0',
      { error: 'invalid_client', reason: 'client_authentication_failed' },
      { realmId: 'realm-1', actor: 'client' }
    );
  });
});
