import { InvalidTokenError, NotFoundError } from '@qauth-labs/shared-errors';
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
    REFRESH_RATE_LIMIT: 60,
    REFRESH_RATE_WINDOW: 60,
  },
}));

import refreshRoute from './refresh';

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

interface ReplyStub {
  header: (k: string, v: string) => ReplyStub;
  send: (body: unknown) => unknown;
  headers: Record<string, string>;
}

function createReply(): ReplyStub {
  const headers: Record<string, string> = {};
  const reply: ReplyStub = {
    headers,
    header(k, v) {
      headers[k] = v;
      return reply;
    },
    send(body) {
      return body;
    },
  };
  return reply;
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
      refreshTokens: {
        findByTokenHash: vi.fn(),
        revoke: vi.fn().mockResolvedValue(undefined),
        create: vi.fn().mockResolvedValue(undefined),
      },
      users: {
        findById: vi.fn(),
      },
      oauthClients: {
        findById: vi.fn(),
      },
      auditLogs: {
        create: vi.fn().mockResolvedValue(undefined),
      },
    },
    jwtUtils: {
      hashRefreshToken: vi.fn().mockReturnValue('hash'),
      signAccessToken: vi.fn().mockResolvedValue('new-jwt'),
      generateRefreshToken: vi.fn().mockReturnValue({ token: 'rt2', tokenHash: 'rth2' }),
      getAccessTokenLifespan: vi.fn().mockReturnValue(900),
      getRefreshTokenLifespan: vi.fn().mockReturnValue(604800),
    },
    sessionUtils: {
      setSession: vi.fn().mockResolvedValue(undefined),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };

  return { fastify: fastify as FastifyInstance, ctx };
}

const baseToken = {
  id: 'token-uuid',
  userId: 'user-1',
  oauthClientId: 'sc-uuid',
  scopes: ['read:foo'],
};
const baseUser = { id: 'user-1', email: 'u@example.com', emailVerified: true, enabled: true };
const baseClient = {
  id: 'sc-uuid',
  clientId: 'system',
  enabled: true,
  audience: ['https://api.example.com'],
};

describe('POST /auth/refresh', () => {
  it('rotates the token, propagates scope/aud, and sets Cache-Control: no-store', async () => {
    const { fastify, ctx } = createFastifyStub();
    await refreshRoute(fastify);
    const handler = ctx.handler;
    expect(handler).toBeDefined();

    (fastify.repositories.refreshTokens.findByTokenHash as unknown as Mock).mockResolvedValue(
      baseToken
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(baseUser);
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(baseClient);

    const request = {
      body: { refresh_token: 'rt' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    const result = await handler(request, reply);

    expect(fastify.repositories.refreshTokens.revoke).toHaveBeenCalledWith(baseToken.id, 'rotated');
    // Scope carries through rotation, aud collapses to single string.
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: baseUser.id,
        clientId: baseClient.clientId,
        scope: 'read:foo',
        aud: 'https://api.example.com',
      })
    );

    expect(reply.headers['Cache-Control']).toBe('no-store');
    expect(reply.headers['Pragma']).toBe('no-cache');

    expect(result).toMatchObject({
      access_token: 'new-jwt',
      refresh_token: 'rt2',
      token_type: 'Bearer',
      scope: 'read:foo',
    });
  });

  it('throws InvalidTokenError for unknown / expired / revoked refresh token', async () => {
    const { fastify, ctx } = createFastifyStub();
    await refreshRoute(fastify);
    const handler = ctx.handler;

    (fastify.repositories.refreshTokens.findByTokenHash as unknown as Mock).mockResolvedValue(null);

    const request = {
      body: { refresh_token: 'bogus' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(InvalidTokenError);
  });

  it('throws NotFoundError when the bound user has been deleted', async () => {
    const { fastify, ctx } = createFastifyStub();
    await refreshRoute(fastify);
    const handler = ctx.handler;

    (fastify.repositories.refreshTokens.findByTokenHash as unknown as Mock).mockResolvedValue(
      baseToken
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(null);

    const request = {
      body: { refresh_token: 'rt' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(NotFoundError);
  });

  it('rejects refresh for a disabled client and revokes the stored token (I-f)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await refreshRoute(fastify);
    const handler = ctx.handler;

    (fastify.repositories.refreshTokens.findByTokenHash as unknown as Mock).mockResolvedValue(
      baseToken
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(baseUser);
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue({
      ...baseClient,
      enabled: false,
    });

    const request = {
      body: { refresh_token: 'rt' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(InvalidTokenError);

    // Token is revoked with the disabled-state reason.
    expect(fastify.repositories.refreshTokens.revoke).toHaveBeenCalledWith(
      baseToken.id,
      'client_disabled'
    );
    // No new token minted.
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
  });

  it('rejects refresh for a disabled user and revokes the stored token (I-f)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await refreshRoute(fastify);
    const handler = ctx.handler;

    (fastify.repositories.refreshTokens.findByTokenHash as unknown as Mock).mockResolvedValue(
      baseToken
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      ...baseUser,
      enabled: false,
    });
    (fastify.repositories.oauthClients.findById as unknown as Mock).mockResolvedValue(baseClient);

    const request = {
      body: { refresh_token: 'rt' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };
    const reply = createReply();
    if (!handler) throw new Error('Handler missing');

    await expect(handler(request, reply)).rejects.toThrow(InvalidTokenError);

    expect(fastify.repositories.refreshTokens.revoke).toHaveBeenCalledWith(
      baseToken.id,
      'user_disabled'
    );
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });
});
