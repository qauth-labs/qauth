import {
  InvalidClientError,
  InvalidGrantError,
  InvalidScopeError,
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

/** Minimal reply stub supporting chainable .header() and .send(). */
function createReply(onSend?: (body: unknown) => void): {
  header: (k: string, v: string) => any;
  send: (b: unknown) => unknown;
} {
  const reply = {
    header(_k: string, _v: string) {
      return reply;
    },
    send(body: unknown) {
      onSend?.(body);
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
        findByTokenHashIncludingRevoked: vi.fn(),
        revoke: vi.fn().mockResolvedValue(undefined),
        revokeFamily: vi.fn().mockResolvedValue(0),
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
      hashRefreshToken: vi.fn().mockImplementation((t: string) => `hash:${t}`),
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
    const reply = createReply((body) => replyBody.push(body));

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

    const reply = createReply();
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

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidClientError);

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

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidScopeError);
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

    const reply = createReply();
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

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidClientError);
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

    const reply = createReply();
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

    const reply = createReply();
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

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidScopeError);

    // No token should be signed when the grant fails at the scope guard.
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects client_credentials when the client is disabled', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-disabled',
      clientId: 'test-client-disabled',
      clientSecretHash: 'hash',
      enabled: false,
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
        scope: 'read:foo',
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidClientError);
    // Secret must not be verified for a disabled client.
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });

  it('rejects client_credentials when the client_id is unknown', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(null);

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: 'does-not-exist',
        client_secret: 'secret',
        scope: 'read:foo',
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidClientError);
  });

  it('rejects client_credentials when no credentials are supplied', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const request = {
      body: {
        grant_type: 'client_credentials',
        scope: 'read:foo',
        // no client_id, no client_secret, no Basic header
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidClientError);
    expect(fastify.repositories.oauthClients.findByClientId).not.toHaveBeenCalled();
  });

  it('rejects when Basic header is combined with conflicting body client_id (no body secret)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const creds = Buffer.from('real-client:secret', 'utf8').toString('base64');

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: 'different-client', // contradicts Basic
        scope: 'read:foo',
      },
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'vitest',
        authorization: `Basic ${creds}`,
      },
    };

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidClientError);
    expect(fastify.repositories.oauthClients.findByClientId).not.toHaveBeenCalled();
  });

  it('URL-decodes Basic auth credentials per RFC 6749 §2.3.1', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-encoded',
      clientId: 'client id with space',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: null,
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    // `+` encodes a space in application/x-www-form-urlencoded; `%40` encodes `@`.
    // Credentials: clientId="client id with space", secret="p@ss:word"
    const raw = 'client+id+with+space:p%40ss%3Aword';
    const encoded = Buffer.from(raw, 'utf8').toString('base64');

    const request = {
      body: { grant_type: 'client_credentials', scope: 'read:foo' },
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'vitest',
        authorization: `Basic ${encoded}`,
      },
    };

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await handler(request, reply);

    expect(fastify.repositories.oauthClients.findByClientId).toHaveBeenCalledWith(
      'realm-1',
      'client id with space'
    );
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledWith('hash', 'p@ss:word');
  });

  it('accepts Basic auth with a matching body client_id (non-conflicting)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-match',
      clientId: 'match-client',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: null,
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

    const creds = Buffer.from('match-client:secret', 'utf8').toString('base64');

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: 'match-client', // same as Basic
        scope: 'read:foo',
      },
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'vitest',
        authorization: `Basic ${creds}`,
      },
    };

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    const result = await handler(request, reply);

    expect(result).toMatchObject({ access_token: 'jwt', token_type: 'Bearer' });
    expect(fastify.repositories.oauthClients.findByClientId).toHaveBeenCalledWith(
      'realm-1',
      'match-client'
    );
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
    const reply = createReply();

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

    const reply = createReply();
    await expect(handler(baseRequest(), reply)).rejects.toThrow(InvalidGrantError);
  });

  it('rejects when redirect_uri does not match the authorization request', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(
      handler(baseRequest({ redirect_uri: 'https://evil.example.com/callback' }), reply)
    ).rejects.toThrow(InvalidGrantError);
  });

  it('rejects when PKCE verification fails', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.pkceUtils.verifyCodeChallenge as unknown as Mock).mockReturnValue(false);
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(handler(baseRequest(), reply)).rejects.toThrow(InvalidGrantError);
  });

  it('rejects when the user bound to the code cannot be found', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(null);
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
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

    const reply = createReply();
    await expect(handler(baseRequest(), reply)).rejects.toThrow(UnauthorizedClientError);
  });
});

describe('POST /oauth/token route — refresh_token grant', () => {
  const REFRESH_TOKEN_HEX = 'a'.repeat(64);
  const OTHER_REFRESH_HEX = 'b'.repeat(64);

  function setupRefreshStub() {
    const { fastify, ctx } = createFastifyStub();

    const confidentialClient = {
      id: 'client-uuid-rt-1',
      clientId: 'confidential-client',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['authorization_code', 'refresh_token'],
      scopes: ['read:foo', 'write:foo'],
      audience: ['https://api.example.com'],
      tokenEndpointAuthMethod: 'client_secret_post',
    };
    const publicClient = {
      id: 'client-uuid-rt-pub',
      clientId: 'public-client',
      clientSecretHash: '',
      enabled: true,
      grantTypes: ['authorization_code', 'refresh_token'],
      scopes: ['read:foo'],
      audience: null,
      tokenEndpointAuthMethod: 'none',
    };
    const user = {
      id: 'user-uuid-rt',
      email: 'rt@example.com',
      emailVerified: true,
      enabled: true,
    };
    const storedToken = {
      id: 'token-uuid-rt-1',
      userId: user.id,
      oauthClientId: confidentialClient.id,
      familyId: 'family-uuid-1',
      scopes: ['read:foo', 'write:foo'],
      expiresAt: Date.now() + 60_000,
      revoked: false,
    };

    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('new.access.jwt');
    (fastify.jwtUtils.generateRefreshToken as unknown as Mock).mockReturnValue({
      token: 'new-refresh-token',
      tokenHash: 'new-refresh-token-hash',
    });
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(user);

    return { fastify, ctx, confidentialClient, publicClient, user, storedToken };
  }

  function refreshRequest(overrides: Record<string, unknown> = {}, headers = {}) {
    return {
      body: {
        grant_type: 'refresh_token',
        refresh_token: REFRESH_TOKEN_HEX,
        client_id: 'confidential-client',
        client_secret: 'secret',
        ...overrides,
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest', ...headers },
    };
  }

  it('rotates the token and returns new access+refresh for a confidential client', async () => {
    const { fastify, ctx, confidentialClient, storedToken, user } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(storedToken);

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const result = await handler(refreshRequest(), reply);

    // Old token revoked as 'rotated' BEFORE new token persisted.
    expect(fastify.repositories.refreshTokens.revoke).toHaveBeenCalledWith(
      storedToken.id,
      'rotated'
    );
    // New token inherits the same family_id.
    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: user.id,
        oauthClientId: confidentialClient.id,
        tokenHash: 'new-refresh-token-hash',
        familyId: storedToken.familyId,
        previousTokenHash: `hash:${REFRESH_TOKEN_HEX}`,
        scopes: ['read:foo', 'write:foo'],
      })
    );
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        email: user.email,
        scope: 'read:foo write:foo',
        aud: 'https://api.example.com',
      })
    );
    expect(result).toMatchObject({
      access_token: 'new.access.jwt',
      refresh_token: 'new-refresh-token',
      token_type: 'Bearer',
      scope: 'read:foo write:foo',
    });
  });

  it('detects replay and revokes the whole family when a revoked token is presented', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, revoked: true });
    (fastify.repositories.refreshTokens.revokeFamily as unknown as Mock).mockResolvedValue(3);

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(handler(refreshRequest(), reply)).rejects.toThrow(InvalidGrantError);

    // Family-wide revocation triggered with the correct family_id + reason.
    expect(fastify.repositories.refreshTokens.revokeFamily).toHaveBeenCalledWith(
      storedToken.familyId,
      'replay_detected'
    );
    // Replay path must NOT mint a new token.
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
  });

  it('rejects when the refresh token is bound to a different client (cross-client)', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, oauthClientId: 'some-other-client' });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(handler(refreshRequest(), reply)).rejects.toThrow(InvalidGrantError);

    // Ownership check fires BEFORE family revocation — must never touch
    // the other client's family.
    expect(fastify.repositories.refreshTokens.revokeFamily).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.revoke).not.toHaveBeenCalled();
  });

  it('honours scope down-scoping when a subset is requested', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(storedToken);

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const result = await handler(refreshRequest({ scope: 'read:foo' }), reply);

    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ scope: 'read:foo' })
    );
    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({ scopes: ['read:foo'] })
    );
    expect(result).toMatchObject({ scope: 'read:foo' });
  });

  it('rejects upscoping with invalid_scope', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(storedToken);

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(handler(refreshRequest({ scope: 'read:foo admin:all' }), reply)).rejects.toThrow(
      InvalidScopeError
    );

    // No rotation when the grant fails validation.
    expect(fastify.repositories.refreshTokens.revoke).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
  });

  it('accepts a public client with client_id only (no client_secret)', async () => {
    const { fastify, ctx, publicClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      publicClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, oauthClientId: publicClient.id, scopes: ['read:foo'] });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const request = {
      body: {
        grant_type: 'refresh_token',
        refresh_token: REFRESH_TOKEN_HEX,
        client_id: 'public-client',
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const result = await handler(request, reply);

    // Secret verification must be skipped for a 'none' auth method.
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      access_token: 'new.access.jwt',
      refresh_token: 'new-refresh-token',
    });
  });

  it('rejects a confidential client presenting client_id without secret', async () => {
    const { fastify, ctx, confidentialClient } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const request = {
      body: {
        grant_type: 'refresh_token',
        refresh_token: REFRESH_TOKEN_HEX,
        client_id: 'confidential-client',
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    await expect(handler(request, reply)).rejects.toThrow(InvalidClientError);

    // Token lookup must not occur before client auth succeeds.
    expect(
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked
    ).not.toHaveBeenCalled();
  });

  it('rejects with invalid_grant when the refresh token is unknown', async () => {
    const { fastify, ctx, confidentialClient } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(undefined);

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(
      handler(refreshRequest({ refresh_token: OTHER_REFRESH_HEX }), reply)
    ).rejects.toThrow(InvalidGrantError);
  });

  it('rejects with invalid_grant when the refresh token is expired', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, expiresAt: Date.now() - 1000 });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(handler(refreshRequest(), reply)).rejects.toThrow(InvalidGrantError);
    expect(fastify.repositories.refreshTokens.revoke).not.toHaveBeenCalled();
  });

  it('rejects with unauthorized_client when the client lacks refresh_token grant', async () => {
    const { fastify, ctx, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'client-uuid-rt-norefresh',
      clientId: 'confidential-client',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['authorization_code'], // refresh_token intentionally absent
      scopes: ['read:foo'],
      audience: null,
      tokenEndpointAuthMethod: 'client_secret_post',
    });
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(storedToken);

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(handler(refreshRequest(), reply)).rejects.toThrow(UnauthorizedClientError);
    // Unauthorized grant must short-circuit before hitting the token table.
    expect(
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked
    ).not.toHaveBeenCalled();
  });
});
