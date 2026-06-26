import {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
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
      signIdToken: vi.fn(),
      verifyAccessToken: vi.fn(),
      generateRefreshToken: vi.fn(),
      hashRefreshToken: vi.fn().mockImplementation((t: string) => `hash:${t}`),
      getAccessTokenLifespan: vi.fn().mockReturnValue(900),
      getRefreshTokenLifespan: vi.fn().mockReturnValue(604800),
      getIssuer: vi.fn().mockReturnValue('https://auth.example.com'),
    },
    pkceUtils: {
      verifyCodeChallenge: vi.fn(),
    },
    sessionUtils: {
      setSession: vi.fn().mockResolvedValue(undefined),
    },
    db: {
      transaction: vi.fn(async (cb: (tx: unknown) => Promise<unknown>) => cb({})),
    },
    log: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
    metrics: {
      loginAttempts: { inc: vi.fn() },
      tokensIssued: { inc: vi.fn() },
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

  it('issues a client_credentials token with aud = requested resource when inside audience allowlist (RFC 8707)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-ccr-1',
      clientId: 'machine-client',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: ['https://api.example.com/v1', 'https://api2.example.com/v1'],
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('cc.jwt');

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_secret: 'secret',
        scope: 'read:foo',
        resource: ['https://api.example.com/v1'],
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await handler(request, reply);

    // aud must be the requested resource, narrowing from the allowlist.
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ aud: 'https://api.example.com/v1' })
    );
  });

  it('rejects client_credentials with resource outside the client audience allowlist (RFC 8707 §2.2)', async () => {
    // Security: without this check, a compromised machine credential could
    // mint tokens for arbitrary resource servers it was never configured to reach.
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;

    const client = {
      id: 'client-uuid-ccr-2',
      clientId: 'machine-client-2',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: ['https://api.example.com/v1'],
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    const request = {
      body: {
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_secret: 'secret',
        scope: 'read:foo',
        // Client asks for a resource NOT in its audience allowlist.
        resource: ['https://unauthorized.example.com/v1'],
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };

    const reply = createReply();
    if (!handler) throw new Error('Handler missing');
    await expect(handler(request, reply)).rejects.toThrow(InvalidTargetError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
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

  // ADR-007 §2 (#184): agent scope-mode cap on the client_credentials path.
  // The cap is enforced via validateScopes(..., toAgentScopeContext(client))
  // and is deny-by-default — a non-agent client (or one without/over its
  // server-side max_agent_mode) can never mint a machine token carrying a
  // reserved agent-mode scope, even when that scope is in its raw allowlist.
  describe('agent scope-mode cap (#184 wiring)', () => {
    function ccAgentClient(opts: { isAgent?: boolean; maxAgentMode?: string | null }) {
      return {
        id: 'cc-agent-uuid',
        clientId: 'cc-agent',
        clientSecretHash: 'hash',
        enabled: true,
        grantTypes: ['client_credentials'],
        // Raw allowlist deliberately INCLUDES agent:exec to prove the cap, not
        // the allowlist, is what blocks an over-mode request.
        scopes: ['read:foo', 'agent:readonly', 'agent:exec'],
        audience: null,
        isAgent: opts.isAgent ?? true,
        maxAgentMode: opts.maxAgentMode ?? null,
      };
    }

    function ccRequest(scope: string) {
      return {
        body: {
          grant_type: 'client_credentials',
          client_id: 'cc-agent',
          client_secret: 'secret',
          scope,
        },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      };
    }

    it('issues an agent-mode scope within the cap (readonly ⊆ admin)', async () => {
      const { fastify, ctx } = createFastifyStub();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        ccAgentClient({ maxAgentMode: 'admin' })
      );
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

      if (!handler) throw new Error('Handler missing');
      const result = await handler(ccRequest('agent:readonly'), createReply());

      expect(result).toMatchObject({ scope: 'agent:readonly', token_type: 'Bearer' });
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ scope: 'agent:readonly' })
      );
    });

    it('per-agent audit (#186): agent client_credentials success attributes actor + scope mode', async () => {
      const { fastify, ctx } = createFastifyStub();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        ccAgentClient({ maxAgentMode: 'exec' })
      );
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

      if (!handler) throw new Error('Handler missing');
      await handler(ccRequest('agent:exec'), createReply());

      // No subject user (machine token) and no delegation chain, but the agent
      // and its effective scope mode are attributed for the agent-activity view.
      expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'oauth.token.exchange.success',
          success: true,
          userId: null,
          actorClientId: 'cc-agent',
          scopeMode: 'exec',
        })
      );
    });

    it('per-agent audit (#186): client_credentials success persists no secret/token material', async () => {
      const { fastify, ctx } = createFastifyStub();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        ccAgentClient({ maxAgentMode: 'exec' })
      );
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('cc-access.jwt');

      if (!handler) throw new Error('Handler missing');
      await handler(
        {
          body: {
            grant_type: 'client_credentials',
            client_id: 'cc-agent',
            client_secret: 'cc-super-secret',
            scope: 'agent:exec',
          },
          ip: '127.0.0.1',
          headers: { 'user-agent': 'vitest' },
        },
        createReply()
      );

      const successCall = (
        fastify.repositories.auditLogs.create as unknown as Mock
      ).mock.calls.find(([arg]) => arg?.event === 'oauth.token.exchange.success');
      expect(successCall).toBeDefined();
      const serialized = JSON.stringify(successCall?.[0]);
      expect(serialized).not.toContain('cc-super-secret');
      expect(serialized).not.toContain('cc-access.jwt');
    });

    it('per-agent audit (#186): NON-agent client_credentials success records no agent attribution', async () => {
      const { fastify, ctx } = createFastifyStub();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      const plainClient = {
        id: 'plain-uuid',
        clientId: 'plain-machine',
        clientSecretHash: 'hash',
        enabled: true,
        grantTypes: ['client_credentials'],
        scopes: ['read:foo'],
        audience: null,
        isAgent: false,
      };
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        plainClient
      );
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('jwt');

      if (!handler) throw new Error('Handler missing');
      await handler(
        {
          body: {
            grant_type: 'client_credentials',
            client_id: 'plain-machine',
            client_secret: 'secret',
            scope: 'read:foo',
          },
          ip: '127.0.0.1',
          headers: { 'user-agent': 'vitest' },
        },
        createReply()
      );

      expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'oauth.token.exchange.success',
          actorClientId: null,
          scopeMode: null,
        })
      );
    });

    it('rejects an agent-mode scope above the cap (exec > readonly) with invalid_scope', async () => {
      const { fastify, ctx } = createFastifyStub();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        ccAgentClient({ maxAgentMode: 'readonly' })
      );
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

      if (!handler) throw new Error('Handler missing');
      await expect(handler(ccRequest('agent:exec'), createReply())).rejects.toThrow(
        InvalidScopeError
      );
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    });

    it('rejects ANY agent-mode scope for a non-agent client (default-deny, fail-closed)', async () => {
      const { fastify, ctx } = createFastifyStub();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      // isAgent:false even though a cap is set and the scope is allowlisted.
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        ccAgentClient({ isAgent: false, maxAgentMode: 'exec' })
      );
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

      if (!handler) throw new Error('Handler missing');
      await expect(handler(ccRequest('agent:readonly'), createReply())).rejects.toThrow(
        InvalidScopeError
      );
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    });

    it('rejects an agent-mode scope when the agent has no cap configured (null = deny)', async () => {
      const { fastify, ctx } = createFastifyStub();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        ccAgentClient({ isAgent: true, maxAgentMode: null })
      );
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

      if (!handler) throw new Error('Handler missing');
      await expect(handler(ccRequest('agent:readonly'), createReply())).rejects.toThrow(
        InvalidScopeError
      );
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    });
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
      firstName: 'Ada',
      lastName: 'Lovelace',
    };

    const authCode = {
      id: 'authcode-uuid-1',
      oauthClientId: client.id,
      userId: user.id,
      redirectUri: 'https://app.example.com/callback',
      codeChallenge: 'challenge-value',
      scopes: ['read:foo'],
      nonce: null,
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
    (fastify.jwtUtils.signIdToken as unknown as Mock).mockResolvedValue('signed.id.token');
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

    // No `openid` scope was granted → no ID token issued (OIDC Core §3.1.3.3).
    expect(fastify.jwtUtils.signIdToken).not.toHaveBeenCalled();
    expect(result).not.toHaveProperty('id_token');
  });

  it('issues an id_token when the granted scope includes openid (OIDC Core §3.1.3.3)', async () => {
    const { fastify, ctx, client, user, authCode } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      scopes: ['openid', 'email'],
      nonce: 'n-0S6_WzA2Mj',
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const result = await handler(baseRequest(), reply);

    // ID token `aud` is the client_id (NOT the resource audience). Nonce from
    // the authorization request is echoed; name derives from first/last name.
    expect(fastify.jwtUtils.signIdToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        audience: client.clientId,
        email: user.email,
        email_verified: user.emailVerified,
        name: 'Ada Lovelace',
        nonce: 'n-0S6_WzA2Mj',
      })
    );
    expect(result).toMatchObject({
      access_token: 'signed.jwt.token',
      id_token: 'signed.id.token',
      scope: 'openid email',
    });
  });

  it('issues an id_token with no nonce when the authorization request omitted it', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      scopes: ['openid'],
      nonce: null,
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const result = await handler(baseRequest(), reply);

    expect(fastify.jwtUtils.signIdToken).toHaveBeenCalledWith(
      expect.objectContaining({ nonce: undefined })
    );
    expect(result).toHaveProperty('id_token', 'signed.id.token');
  });

  it('omits the name claim from the id_token when the user has no name set', async () => {
    const { fastify, ctx, authCode, user } = setupAuthCodeStub();
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      ...user,
      firstName: null,
      lastName: null,
    });
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      scopes: ['openid'],
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await handler(baseRequest(), reply);

    const call = (fastify.jwtUtils.signIdToken as unknown as Mock).mock.calls[0][0];
    expect(call.name).toBeUndefined();
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

  it('issues access token with aud = resource bound to the auth code (RFC 8707)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    // Simulate the authorize step having stored `resource` on the auth code.
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      resource: ['https://api.example.com/v1'],
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await handler(baseRequest(), reply);

    const signArg = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock.calls[0][0];
    expect(signArg.aud).toBe('https://api.example.com/v1');
    const rtArg = (fastify.repositories.refreshTokens.create as unknown as Mock).mock.calls[0][0];
    expect(rtArg.resource).toEqual(['https://api.example.com/v1']);
  });

  it('rejects authorization_code exchange when request resource is outside code binding', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      resource: ['https://api.example.com/v1'],
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    // Client tries to request a different resource at token time — must fail
    // with RFC 8707 §2.2 `invalid_target` (not invalid_grant).
    await expect(
      handler(baseRequest({ resource: ['https://api2.example.com/v1'] }), reply)
    ).rejects.toThrow(InvalidTargetError);
  });

  it('authenticates a public client (token_endpoint_auth_method=none) by client_id alone', async () => {
    // PKCE-capable public client — OAuth 2.1 §4.1.3. No client_secret sent;
    // PKCE code_verifier + client_id is sufficient to bind the code to the
    // client. Previously failed with invalid_client because the token route
    // only accepted the public-client path for refresh_token.
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'client-uuid-ac-1',
      clientId: 'test-client-1',
      clientSecretHash: null,
      enabled: true,
      grantTypes: ['authorization_code', 'refresh_token'],
      scopes: ['read:foo'],
      audience: null,
      tokenEndpointAuthMethod: 'none',
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const request = baseRequest({ client_secret: undefined });
    // No Authorization header, no client_secret — just client_id + PKCE verifier.
    const reply = createReply();
    const result = (await handler(request, reply)) as Record<string, unknown>;

    expect(result.access_token).toBe('signed.jwt.token');
    expect(result.refresh_token).toBe('refresh-token-plain');
    // Password hasher MUST NOT have been called — public client, no secret to verify.
    expect(fastify.passwordHasher.verifyPassword as unknown as Mock).not.toHaveBeenCalled();
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

    // Old token revoked as 'rotated' BEFORE new token persisted. Third
    // arg is the tx handle propagated from fastify.db.transaction.
    expect(fastify.repositories.refreshTokens.revoke).toHaveBeenCalledWith(
      storedToken.id,
      'rotated',
      expect.anything()
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
      }),
      expect.anything()
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

  it('returns expires_in from the configured access-token lifespan on rotation', async () => {
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
    const result = await handler(refreshRequest(), reply);

    // expires_in mirrors getAccessTokenLifespan() (900s in the stub), not the
    // refresh-token lifespan.
    expect(fastify.jwtUtils.getAccessTokenLifespan).toHaveBeenCalled();
    expect(result).toMatchObject({ expires_in: 900 });
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

  it('carries RFC 8707 resource binding across a refresh rotation', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, resource: ['https://api.example.com/v1'] });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await handler(refreshRequest(), reply);

    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ aud: 'https://api.example.com/v1' })
    );
    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({ resource: ['https://api.example.com/v1'] }),
      expect.anything()
    );
  });

  it('rejects refresh with resource outside the refresh-token binding (RFC 8707)', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, resource: ['https://api.example.com/v1'] });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(
      handler(refreshRequest({ resource: ['https://api2.example.com/v1'] }), reply)
    ).rejects.toThrow(InvalidTargetError);
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
      expect.objectContaining({ scopes: ['read:foo'] }),
      expect.anything()
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

describe('POST /oauth/token route — token-exchange grant (RFC 8693, ADR-007 §2)', () => {
  const GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
  const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

  const ISSUER = 'https://auth.example.com';
  const AGENT_CLIENT_ID = 'agent-client';

  /**
   * Set up a confidential AGENT client (is_agent: true) authorised for the
   * token-exchange grant, plus a verifiable subject token and an enabled user.
   *
   * The subject token defaults to a QAuth-issued access token whose `aud`
   * includes the requesting agent's `client_id` (so the agent-binding GATE 3c
   * passes by default). `confidential: false` simulates a PUBLIC agent
   * (token_endpoint_auth_method=none, no secret on the request).
   */
  function setupExchangeStub(
    opts: {
      isAgent?: boolean;
      confidential?: boolean;
      grantTypes?: string[];
      maxAgentMode?: string | null;
      subjectScope?: string;
      subjectAud?: string | string[] | undefined;
      subjectAct?: unknown;
      subjectIss?: string | undefined;
      subjectTokenUse?: string | undefined;
      subjectExp?: number;
      bindAgentInAud?: boolean;
      userEnabled?: boolean;
      userFound?: boolean;
    } = {}
  ) {
    const { fastify, ctx } = createFastifyStub();

    const client = {
      id: 'client-uuid-agent-1',
      clientId: AGENT_CLIENT_ID,
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: opts.grantTypes ?? [GRANT],
      scopes: [] as string[],
      audience: null,
      isAgent: opts.isAgent ?? true,
      maxAgentMode: opts.maxAgentMode ?? null,
      tokenEndpointAuthMethod: opts.confidential === false ? 'none' : 'client_secret_post',
    };

    const user = {
      id: 'user-uuid-subject',
      email: 'subject@example.com',
      emailVerified: true,
      enabled: opts.userEnabled ?? true,
    };

    // Resolve the subject audience, ensuring the agent's client_id is present
    // unless the test explicitly opts out (to exercise the binding failure).
    const baseAud = opts.subjectAud === undefined ? 'https://api.example.com' : opts.subjectAud;
    const bindAgent = opts.bindAgentInAud ?? true;
    let aud: string | string[] | undefined;
    if (!bindAgent) {
      aud = baseAud;
    } else {
      const arr = baseAud === undefined ? [] : Array.isArray(baseAud) ? baseAud : [baseAud];
      aud = arr.includes(AGENT_CLIENT_ID) ? baseAud : [...arr, AGENT_CLIENT_ID];
    }

    const subjectPayload = {
      sub: user.id,
      clientId: 'original-app-client',
      scope: opts.subjectScope ?? 'read:docs write:docs',
      aud,
      iss: opts.subjectIss === undefined ? ISSUER : opts.subjectIss,
      token_use: 'subjectTokenUse' in opts ? opts.subjectTokenUse : 'access',
      exp: opts.subjectExp ?? Math.floor(Date.now() / 1000) + 600,
      ...(opts.subjectAct ? { act: opts.subjectAct } : {}),
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    // Issuer is now enforced INSIDE verifyAccessToken (RFC 9700). Model that:
    // when the route pins `issuer` and it does not match the token's `iss`, the
    // mock rejects exactly as jose would, instead of the route doing a manual
    // post-verification issuer comparison.
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockImplementation(
      (_token: string, options?: { issuer?: string }) => {
        if (options?.issuer !== undefined && subjectPayload.iss !== options.issuer) {
          return Promise.reject(new Error('unexpected "iss" claim value'));
        }
        return Promise.resolve(subjectPayload);
      }
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(
      opts.userFound === false ? null : user
    );
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('delegated.jwt');

    return { fastify, ctx, client, user, subjectPayload };
  }

  function exchangeRequest(overrides: Record<string, unknown> = {}) {
    return {
      body: {
        grant_type: GRANT,
        client_id: AGENT_CLIENT_ID,
        client_secret: 'secret',
        subject_token: 'subject.jwt.token',
        subject_token_type: ACCESS_TOKEN_TYPE,
        ...overrides,
      },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    };
  }

  async function invoke(fastify: FastifyInstance, ctx: TestContext, req: unknown) {
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');
    return handler(req, createReply());
  }

  it('mints a delegated token: sub=user, act.sub=agent, preserved scope+aud', async () => {
    // Subject token minted for both a resource and the agent (so GATE 3c binds);
    // with no narrowing requested the delegated aud is preserved verbatim.
    const { fastify, ctx, client, user } = setupExchangeStub({
      subjectAud: ['https://api.example.com', AGENT_CLIENT_ID],
    });
    const result = await invoke(fastify, ctx, exchangeRequest());

    // sub is the end-user; act identifies the acting agent (RFC 8693 §4.1).
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        clientId: client.clientId,
        scope: 'read:docs write:docs',
        aud: ['https://api.example.com', AGENT_CLIENT_ID],
        act: { sub: AGENT_CLIENT_ID },
      })
    );
    expect(result).toMatchObject({
      access_token: 'delegated.jwt',
      issued_token_type: ACCESS_TOKEN_TYPE,
      token_type: 'Bearer',
      scope: 'read:docs write:docs',
    });
    // RFC 8693: no refresh token issued on delegation.
    expect(result).not.toHaveProperty('refresh_token');
  });

  it('nests the prior act chain for chained delegation', async () => {
    // Subject token already carries an act (a previous agent delegation).
    const { fastify, ctx } = setupExchangeStub({ subjectAct: { sub: 'prior-agent' } });
    await invoke(fastify, ctx, exchangeRequest());

    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        act: { sub: 'agent-client', act: { sub: 'prior-agent' } },
      })
    );
  });

  it('rejects an over-deep delegation chain (invalid_request)', async () => {
    // Subject token already carries 4 nested actors; this exchange would make 5,
    // exceeding MAX_DELEGATION_DEPTH (4) → invalid_request, no token minted.
    const deepAct = { sub: 'a3', act: { sub: 'a2', act: { sub: 'a1', act: { sub: 'a0' } } } };
    const { fastify, ctx } = setupExchangeStub({ subjectAct: deepAct });
    await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(InvalidRequestError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('per-agent audit (#186): success row carries actor + subject + act chain + scope mode', async () => {
    // Agent capped at exec, subject token grants agent:exec; on-behalf-of of the
    // end-user with a prior actor already in the chain.
    const { fastify, ctx, client, user } = setupExchangeStub({
      maxAgentMode: 'exec',
      subjectScope: 'read:docs agent:exec',
      subjectAct: { sub: 'prior-agent' },
    });

    await invoke(fastify, ctx, exchangeRequest());

    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'oauth.token.exchange.success',
        eventType: 'token',
        success: true,
        // Subject = the end-user the agent acted on behalf of.
        userId: user.id,
        // Actor = the authenticated agent's client_id (denormalized, queryable).
        actorClientId: client.clientId,
        // Flattened RFC 8693 `act` chain: outermost (this agent) first.
        delegationChain: [client.clientId, 'prior-agent'],
        // Highest agent scope mode present in the granted set.
        scopeMode: 'exec',
      })
    );
  });

  it('per-agent audit (#186): never persists token/secret material in audit fields', async () => {
    const { fastify, ctx } = setupExchangeStub({ subjectScope: 'read:docs' });

    await invoke(fastify, ctx, exchangeRequest({ client_secret: 'super-secret' }));

    const successCall = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls.find(
      ([arg]) => arg?.event === 'oauth.token.exchange.success'
    );
    expect(successCall).toBeDefined();
    const serialized = JSON.stringify(successCall?.[0]);
    // No subject/actor token, no client secret, no raw delegated token.
    expect(serialized).not.toContain('subject.jwt.token');
    expect(serialized).not.toContain('super-secret');
    expect(serialized).not.toContain('delegated.jwt');
  });

  it('narrows scope to a subset of the subject token scope', async () => {
    const { fastify, ctx } = setupExchangeStub({ subjectScope: 'read:docs write:docs' });
    await invoke(fastify, ctx, exchangeRequest({ scope: 'read:docs' }));

    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ scope: 'read:docs' })
    );
  });

  it('rejects scope widening beyond the subject token (invalid_scope)', async () => {
    const { fastify, ctx } = setupExchangeStub({ subjectScope: 'read:docs' });
    await expect(
      invoke(fastify, ctx, exchangeRequest({ scope: 'read:docs admin:all' }))
    ).rejects.toThrow(InvalidScopeError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('narrows aud to a requested resource within the subject token audience', async () => {
    const { fastify, ctx } = setupExchangeStub({
      subjectAud: ['https://api.example.com/v1', 'https://api2.example.com/v1'],
    });
    await invoke(fastify, ctx, exchangeRequest({ resource: ['https://api.example.com/v1'] }));
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ aud: 'https://api.example.com/v1' })
    );
  });

  it('rejects a resource/audience outside the subject token audience (invalid_target)', async () => {
    const { fastify, ctx } = setupExchangeStub({ subjectAud: 'https://api.example.com/v1' });
    await expect(
      invoke(fastify, ctx, exchangeRequest({ resource: ['https://evil.example.com/v1'] }))
    ).rejects.toThrow(InvalidTargetError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects a non-agent client (unauthorized_client, default-deny)', async () => {
    // Self-asserted is_agent omitted/false → fail-closed rejection (epic #181).
    const { fastify, ctx } = setupExchangeStub({ isAgent: false });
    await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(UnauthorizedClientError);
    expect(fastify.jwtUtils.verifyAccessToken).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects an agent client not allowed the token-exchange grant', async () => {
    const { fastify, ctx } = setupExchangeStub({ grantTypes: ['authorization_code'] });
    await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(UnauthorizedClientError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects an unsupported subject_token_type (invalid_request)', async () => {
    const { fastify, ctx } = setupExchangeStub();
    await expect(
      invoke(
        fastify,
        ctx,
        exchangeRequest({ subject_token_type: 'urn:ietf:params:oauth:token-type:saml2' })
      )
    ).rejects.toThrow(InvalidRequestError);
    expect(fastify.jwtUtils.verifyAccessToken).not.toHaveBeenCalled();
  });

  it('rejects an unsupported requested_token_type (invalid_request)', async () => {
    const { fastify, ctx } = setupExchangeStub();
    await expect(
      invoke(
        fastify,
        ctx,
        exchangeRequest({ requested_token_type: 'urn:ietf:params:oauth:token-type:refresh_token' })
      )
    ).rejects.toThrow(InvalidRequestError);
  });

  it('rejects an unverifiable subject_token (invalid_request)', async () => {
    const { fastify, ctx } = setupExchangeStub();
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockRejectedValue(
      new Error('bad signature')
    );
    await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(InvalidRequestError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects when actor_token is present without actor_token_type (invalid_request)', async () => {
    const { fastify, ctx } = setupExchangeStub();
    await expect(
      invoke(fastify, ctx, exchangeRequest({ actor_token: 'actor.jwt' }))
    ).rejects.toThrow(InvalidRequestError);
  });

  it('rejects when the subject user is disabled (invalid_request)', async () => {
    const { fastify, ctx } = setupExchangeStub({ userEnabled: false });
    await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(InvalidRequestError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('accepts and verifies an actor_token, recording the actor subject in audit', async () => {
    const { fastify, ctx } = setupExchangeStub();
    // Subject + actor tokens both verify; actor identity in `act` is still the
    // authenticated agent's client_id, not the actor token's self-declaration.
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock)
      .mockResolvedValueOnce({
        sub: 'user-uuid-subject',
        clientId: 'original-app-client',
        scope: 'read:docs',
        aud: ['https://api.example.com', AGENT_CLIENT_ID],
        iss: ISSUER,
        token_use: 'access',
        exp: Math.floor(Date.now() / 1000) + 600,
      })
      .mockResolvedValueOnce({
        sub: 'actor-service',
        clientId: 'actor-service',
        aud: 'x',
        iss: ISSUER,
        token_use: 'access',
        exp: Math.floor(Date.now() / 1000) + 600,
      });

    await invoke(
      fastify,
      ctx,
      exchangeRequest({ actor_token: 'actor.jwt', actor_token_type: ACCESS_TOKEN_TYPE })
    );

    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ act: { sub: 'agent-client' } })
    );
    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'oauth.token.exchange.success',
        success: true,
        metadata: expect.objectContaining({
          grantType: 'token-exchange',
          actor: 'agent-client',
          hasActorToken: true,
          actorTokenSubject: 'actor-service',
        }),
      })
    );
  });

  it('rejects when the subject_token was not minted for this agent (binding, invalid_request)', async () => {
    // Subject token aud does NOT contain the requesting agent's client_id.
    // Closes "any user's token + any agent client_id mints delegation".
    const { fastify, ctx } = setupExchangeStub({
      subjectAud: 'https://api.example.com',
      bindAgentInAud: false,
    });
    await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(InvalidRequestError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects a PUBLIC agent client — token-exchange requires confidential auth (invalid_client)', async () => {
    // Public client (token_endpoint_auth_method=none) presents no secret; the
    // confidential auth path rejects it before any exchange logic runs.
    const { fastify, ctx } = setupExchangeStub({ confidential: false });
    const req = exchangeRequest();
    delete (req.body as Record<string, unknown>).client_secret; // public: no secret
    await expect(invoke(fastify, ctx, req)).rejects.toThrow(InvalidClientError);
    expect(fastify.jwtUtils.verifyAccessToken).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects a QAuth-signed JWT that is not an access token (token confusion, invalid_request)', async () => {
    // An ID-token-shaped JWT (no token_use marker, no client_id) verifies by
    // signature but must NOT be accepted as a subject token.
    const { fastify, ctx } = setupExchangeStub();
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: 'user-uuid-subject',
      aud: ['https://api.example.com', AGENT_CLIENT_ID],
      iss: ISSUER,
      token_use: 'id', // positively NOT an access token
      exp: Math.floor(Date.now() / 1000) + 600,
    });
    await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(InvalidRequestError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects a subject_token from a foreign issuer (invalid_request)', async () => {
    const { fastify, ctx } = setupExchangeStub({ subjectIss: 'https://evil.example.com' });
    await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(InvalidRequestError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('clamps the delegated token lifespan to the subject token remaining lifetime', async () => {
    // Subject token expires in 120s; configured lifespan is 900s → clamp to 120.
    const exp = Math.floor(Date.now() / 1000) + 120;
    const { fastify, ctx } = setupExchangeStub({ subjectExp: exp });
    const result = await invoke(fastify, ctx, exchangeRequest());

    const signArg = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock.calls[0][0];
    expect(signArg.expiresInOverride).toBeGreaterThan(110);
    expect(signArg.expiresInOverride).toBeLessThanOrEqual(120);
    expect((result as { expires_in: number }).expires_in).toBe(signArg.expiresInOverride);
  });

  it('does NOT extend lifespan beyond the configured default when the subject lives longer', async () => {
    // Subject token expires in 10000s; configured lifespan is 900s → cap at 900.
    const exp = Math.floor(Date.now() / 1000) + 10000;
    const { fastify, ctx } = setupExchangeStub({ subjectExp: exp });
    await invoke(fastify, ctx, exchangeRequest());
    const signArg = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock.calls[0][0];
    expect(signArg.expiresInOverride).toBe(900);
  });

  it('emits the bare `invalid_request` error code via InvalidRequestError (RFC 6749 §5.2)', async () => {
    // The wire `error` field must be the bare token; detail goes in
    // error_description. InvalidRequestError.message is exactly "invalid_request".
    const { fastify, ctx } = setupExchangeStub();
    try {
      await invoke(
        fastify,
        ctx,
        exchangeRequest({ subject_token_type: 'urn:ietf:params:oauth:token-type:saml2' })
      );
      throw new Error('expected rejection');
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidRequestError);
      expect((err as InvalidRequestError).message).toBe('invalid_request');
      expect((err as InvalidRequestError).errorDescription).toBeTruthy();
    }
  });

  // ADR-007 §2 (#184): GATE 4c — the (narrowed) delegated scope is additionally
  // clamped to the agent's server-side max_agent_mode. A capped agent must not
  // be able to launder a higher-mode reserved scope through delegation even
  // when the subject token (issued under a broader prior grant) still carries
  // it. Fail-closed via toAgentScopeContext.
  describe('agent scope-mode cap (#184 wiring)', () => {
    it('mints a delegated agent-mode scope within the cap (readonly ⊆ exec)', async () => {
      const { fastify, ctx } = setupExchangeStub({
        maxAgentMode: 'exec',
        subjectScope: 'read:docs agent:readonly',
      });
      const result = await invoke(fastify, ctx, exchangeRequest());
      expect(result).toMatchObject({ scope: 'read:docs agent:readonly' });
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ scope: 'read:docs agent:readonly' })
      );
    });

    it('rejects a delegated agent-mode scope above the cap (subject has exec, agent capped readonly)', async () => {
      // The subject token legitimately carries agent:exec (minted under a broader
      // grant), but THIS agent is capped at readonly — the clamp must reject it
      // rather than mint an exec delegated token.
      const { fastify, ctx } = setupExchangeStub({
        maxAgentMode: 'readonly',
        subjectScope: 'read:docs agent:exec',
      });
      await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(InvalidScopeError);
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    });

    it('rejects a delegated agent-mode scope when the agent has no cap (null = deny)', async () => {
      const { fastify, ctx } = setupExchangeStub({
        maxAgentMode: null,
        subjectScope: 'agent:readonly',
      });
      await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(InvalidScopeError);
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    });

    it('still rejects when the request narrows to an over-cap agent-mode scope', async () => {
      // Subject carries both readonly+exec; the request explicitly narrows to
      // exec, which exceeds the readonly cap → invalid_scope.
      const { fastify, ctx } = setupExchangeStub({
        maxAgentMode: 'readonly',
        subjectScope: 'agent:readonly agent:exec',
      });
      await expect(invoke(fastify, ctx, exchangeRequest({ scope: 'agent:exec' }))).rejects.toThrow(
        InvalidScopeError
      );
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    });
  });
});
