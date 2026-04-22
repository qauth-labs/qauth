import {
  BadRequestError,
  InvalidCredentialsError,
  InvalidTokenError,
  NotFoundError,
  UnauthorizedClientError,
} from '@qauth-labs/shared-errors';
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
    TOKEN_RATE_LIMIT: 60,
    TOKEN_RATE_WINDOW: 60,
  },
}));

import tokenRoute from './token';

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
        create: vi.fn(),
      },
      oauthClients: {
        findByClientId: vi.fn(),
      },
      authorizationCodes: {
        findByCode: vi.fn(),
        markUsed: vi.fn(),
      },
      users: {
        findById: vi.fn(),
      },
      refreshTokens: {
        create: vi.fn(),
      },
      auditLogs: {
        create: vi.fn(),
      },
    },
    passwordHasher: {
      verifyPassword: vi.fn(),
    },
    jwtUtils: {
      signAccessToken: vi.fn(),
      generateRefreshToken: vi.fn(),
      getAccessTokenLifespan: vi.fn().mockReturnValue(900),
      getRefreshTokenLifespan: vi.fn().mockReturnValue(604800),
    },
    pkceUtils: {
      verifyCodeChallenge: vi.fn(),
    },
    sessionUtils: {
      setSession: vi.fn().mockResolvedValue(undefined),
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

describe('POST /oauth/token route — client_credentials grant', () => {
  it('issues an access token for a valid client_credentials request (client_secret_post)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const client = {
      id: 'client-uuid-1',
      clientId: 'test-client-1',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo', 'write:foo'],
      audience: null,
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('signed.jwt.token');

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_secret: 'secret',
        scope: 'read:foo',
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const replyBody: unknown[] = [];
    const reply = {
      send: (body: unknown) => {
        replyBody.push(body);
        return body;
      },
    };

    if (!handler) throw new Error('Handler missing');
    const result = await handler(request, reply);

    // Verify JWT signed with client_id as sub, scope string, and aud falling back to client_id
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: client.clientId,
        clientId: client.clientId,
        scope: 'read:foo',
        aud: client.clientId,
      })
    );

    // No refresh token per RFC 6749 4.4.3
    expect(result).toMatchObject({
      access_token: 'signed.jwt.token',
      expires_in: 900,
      token_type: 'Bearer',
      scope: 'read:foo',
    });
    expect(result).not.toHaveProperty('refresh_token');

    // No refresh token persisted
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
  });

  it('authenticates client via Authorization: Basic header', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-2',
      clientId: 'test-client-2',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: ['https://api.example.com'],
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    const creds = Buffer.from('test-client-2:secret', 'utf8').toString('base64');

    const request = {
      body: {
        grant_type: 'client_credentials',
        scope: 'read:foo',
      },
      ip: '10.0.0.1',
      headers: {
        'user-agent': 'vitest',
        authorization: `Basic ${creds}`,
      },
    };

    const reply = { send: (b: unknown) => b };
    if (!handler) throw new Error('Handler missing');
    await handler(request, reply);

    // Verify Basic header decoded + client looked up by decoded client_id
    expect(fastify.repositories.oauthClients.findByClientId).toHaveBeenCalledWith(
      'realm-1',
      'test-client-2'
    );
    // Verify audience resolved from client.audience (single-item array collapses to string)
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        aud: 'https://api.example.com',
      })
    );
  });

  it('rejects when Basic header is combined with body client_secret (RFC 6749 2.3)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const creds = Buffer.from('test-client-dual:secret', 'utf8').toString('base64');

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_secret: 'another-secret', // present alongside Basic — must fail
        scope: 'read:foo',
      },
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'vitest',
        authorization: `Basic ${creds}`,
      },
    };

    const reply = { send: (b: unknown) => b };
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidCredentialsError);

    // Must reject before reaching the client lookup.
    expect(fastify.repositories.oauthClients.findByClientId).not.toHaveBeenCalled();
  });

  it('rejects requested scopes not in client.scopes allowlist', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-3',
      clientId: 'test-client-3',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: null,
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_secret: 'secret',
        scope: 'admin:all',
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = { send: (b: unknown) => b };
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(BadRequestError);
  });

  it('rejects client_credentials with unauthorized_client when grant not enabled for client', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-4',
      clientId: 'test-client-4',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['authorization_code'],
      scopes: [],
      audience: null,
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_secret: 'secret',
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = { send: (b: unknown) => b };
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(UnauthorizedClientError);
  });

  it('rejects when client authentication fails', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-5',
      clientId: 'test-client-5',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: null,
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(false);

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_secret: 'wrong-secret',
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = { send: (b: unknown) => b };
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidCredentialsError);
  });

  it('falls back to client_id as aud when client.audience is null', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-6',
      clientId: 'test-client-6',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: null,
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_secret: 'secret',
        scope: 'read:foo',
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = { send: (b: unknown) => b };
    if (!handler) throw new Error('Handler missing');
    await handler(request, reply);

    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ aud: client.clientId })
    );
  });

  it('preserves multi-audience array when client has >1 audiences', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-7',
      clientId: 'test-client-7',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: ['https://a.example.com', 'https://b.example.com'],
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_secret: 'secret',
        scope: 'read:foo',
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = { send: (b: unknown) => b };
    if (!handler) throw new Error('Handler missing');
    await handler(request, reply);

    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        aud: ['https://a.example.com', 'https://b.example.com'],
      })
    );
  });

  it('rejects client_credentials with no scope requested when client has scopes configured', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-8',
      clientId: 'test-client-8',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: null,
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_secret: 'secret',
        // scope deliberately omitted
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = { send: (b: unknown) => b };
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(BadRequestError);

    // No token should be signed when the grant fails at the scope guard.
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });
});

describe('POST /oauth/token route — authorization_code grant', () => {
  function setupAuthCodeStub() {
    const { fastify, ctx } = createFastifyStub();

    const client = {
      id: 'client-uuid-ac-1',
      clientId: 'test-client-1',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['authorization_code'],
      scopes: ['read:foo', 'write:foo'],
      audience: ['https://api.example.com'],
    };

    const user = {
      id: 'user-uuid-1',
      email: 'user@example.com',
      emailVerified: true,
    };

    const authCode = {
      id: 'authcode-uuid-1',
      oauthClientId: client.id,
      userId: user.id,
      redirectUri: 'https://app.example.com/callback',
      codeChallenge: 'challenge-value',
      scopes: ['read:foo'],
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue(
      authCode
    );
    (fastify.repositories.authorizationCodes.markUsed as unknown as Mock).mockResolvedValue(
      undefined
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(user);
    (fastify.repositories.refreshTokens.create as unknown as Mock).mockResolvedValue(undefined);
    (fastify.pkceUtils.verifyCodeChallenge as unknown as Mock).mockReturnValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('signed.jwt.token');
    (fastify.jwtUtils.generateRefreshToken as unknown as Mock).mockReturnValue({
      token: 'refresh-token-plain',
      tokenHash: 'refresh-token-hash',
    });

    return { fastify, ctx, client, user, authCode };
  }

  function baseRequest(overrides: Partial<Record<string, unknown>> = {}) {
    return {
      body: {
        grant_type: 'authorization_code',
        code: 'auth-code-plain',
        redirect_uri: 'https://app.example.com/callback',
        code_verifier: 'verifier-value',
        client_id: 'test-client-1',
        client_secret: 'secret',
        ...overrides,
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };
  }

  it('issues access + refresh tokens on a valid authorization_code exchange', async () => {
    const { fastify, ctx, client, user } = setupAuthCodeStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    expect(handler).toBeDefined();

    const request = baseRequest();
    const reply = { send: (b: unknown) => b };

    if (!handler) throw new Error('Handler missing');
    const result = await handler(request, reply);

    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        email: user.email,
        email_verified: user.emailVerified,
        clientId: client.clientId,
        scope: 'read:foo',
        aud: 'https://api.example.com',
      })
    );

    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: user.id,
        oauthClientId: client.id,
        tokenHash: 'refresh-token-hash',
        scopes: ['read:foo'],
      })
    );

    expect(result).toMatchObject({
      access_token: 'signed.jwt.token',
      refresh_token: 'refresh-token-plain',
      expires_in: 900,
      token_type: 'Bearer',
      scope: 'read:foo',
    });
  });

  it('rejects when authorization code was issued to a different client', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      id: 'authcode-uuid-1',
      oauthClientId: 'some-other-client-id',
      userId: 'user-uuid-1',
      redirectUri: 'https://app.example.com/callback',
      codeChallenge: 'challenge-value',
      scopes: ['read:foo'],
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = { send: (b: unknown) => b };
    await expect(handler(baseRequest(), reply)).rejects.toThrow(InvalidTokenError);
  });

  it('rejects when redirect_uri does not match the authorization request', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = { send: (b: unknown) => b };
    await expect(
      handler(baseRequest({ redirect_uri: 'https://evil.example.com/callback' }), reply)
    ).rejects.toThrow(InvalidTokenError);
  });

  it('rejects when PKCE verification fails', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.pkceUtils.verifyCodeChallenge as unknown as Mock).mockReturnValue(false);
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = { send: (b: unknown) => b };
    await expect(handler(baseRequest(), reply)).rejects.toThrow(InvalidTokenError);
  });

  it('rejects when the user bound to the code cannot be found', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(null);
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = { send: (b: unknown) => b };
    await expect(handler(baseRequest(), reply)).rejects.toThrow(NotFoundError);
  });

  it('rejects with unauthorized_client when the client is not authorized for the authorization_code grant', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'client-uuid-ac-1',
      clientId: 'test-client-1',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: null,
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = { send: (b: unknown) => b };
    await expect(handler(baseRequest(), reply)).rejects.toThrow(UnauthorizedClientError);
  });
});
