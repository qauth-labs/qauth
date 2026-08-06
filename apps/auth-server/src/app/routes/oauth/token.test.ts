import { generateKeyPairSync } from 'node:crypto';

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
import {
  type CryptoKey,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importPKCS8,
  type JWK,
  SignJWT,
} from 'jose';
import { afterEach, beforeAll, describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

/** A fresh Ed25519 pair in the PKCS#8 / SPKI PEM form the config carries. */
function generateEd25519Pem(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

/** This server's own signing key — used by the ADR-011 ID-JAG MINT path. */
const SERVER_KEYS = generateEd25519Pem();
/** The enterprise IdP's signing key — used to mint ID-JAG fixtures to CONSUME. */
const IDP_KEYS = generateEd25519Pem();

/**
 * Mutable env stand-in. The pre-ADR-011 values are the DEFAULTS and are restored
 * after every test, so the ID-JAG flag is off unless a test turns it on — which
 * is exactly the production posture the deny-path tests below assert.
 */
const { mockEnv } = vi.hoisted(() => ({
  mockEnv: {} as Record<string, unknown>,
}));

function resetMockEnv(): void {
  for (const key of Object.keys(mockEnv)) delete mockEnv[key];
  Object.assign(mockEnv, {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    TOKEN_RATE_LIMIT: 60,
    TOKEN_RATE_WINDOW: 60,
    JWT_PRIVATE_KEY: SERVER_KEYS.privateKeyPem,
    // ADR-011 defaults: OFF, and an EMPTY allowlist.
    ID_JAG_ENABLED: false,
    ID_JAG_TRUSTED_ISSUERS: [] as string[],
    ID_JAG_FETCH_TIMEOUT_MS: 5000,
    ID_JAG_JWKS_CACHE_TTL: 300,
    ID_JAG_MAX_DOCUMENT_BYTES: 65536,
    ID_JAG_ALLOW_PRIVATE_ADDRESSES: false,
    ID_JAG_CLOCK_SKEW_LEEWAY: 60,
    ID_JAG_MAX_ASSERTION_LIFETIME: 300,
    ID_JAG_ISSUED_LIFETIME: 300,
  });
}
resetMockEnv();

vi.mock('../../../config/env', () => ({ env: mockEnv }));

const { ssrfSafeGet } = vi.hoisted(() => ({ ssrfSafeGet: vi.fn() }));

vi.mock('../../helpers/ssrf-safe-fetch', async () => {
  const actual = await vi.importActual<typeof import('../../helpers/ssrf-safe-fetch')>(
    '../../helpers/ssrf-safe-fetch'
  );
  return { ...actual, ssrfSafeGet };
});

import tokenRoute from './token';

afterEach(() => {
  resetMockEnv();
  ssrfSafeGet.mockReset();
});

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
  const redisStore = new Map<string, string>();

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
      userCredentials: {
        // #230: the authorization_code session block fetches the password
        // credential for the session display address.
        findByUserIdAndType: vi.fn().mockResolvedValue({
          id: 'cred-1',
          userId: 'user-1',
          realmId: 'realm-1',
          providerType: 'password',
          externalSub: 'user@example.com',
          credentialData: { password_hash: 'hash', email_verified: true },
        }),
        // ADR-011 subject resolution: an ID-JAG `sub` is linked to a QAuth user
        // through `(realm, oidc_<issuer>, external_sub)`. Deny-by-default here —
        // an unlinked subject is rejected, never provisioned — so the ID-JAG
        // tests opt IN by overriding this mock.
        findByRealmProviderSub: vi.fn().mockResolvedValue(undefined),
      },
      userAttributes: {
        // #229 claim resolution: default fixture is ONE verified self_reported
        // email attribute matching the auth-code user fixture, so pre-#229
        // presence assertions keep their exact values. Omission / trust-order
        // cases override this mock per test.
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
        ]),
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
      // #275: classical posture — issueAccessToken takes the non-hybrid branch.
      isHybridSigningEnabled: () => false,
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
    // In-memory `fastify.redis` with real SET NX semantics — the ID-JAG replay
    // store depends on NX returning null for an already-present key, so a stub
    // that always says 'OK' would make every replay test pass vacuously.
    redis: {
      get: vi.fn(async (key: string) => redisStore.get(key) ?? null),
      set: vi.fn(async (key: string, value: string, _ex?: string, _ttl?: number, nx?: string) => {
        if (nx === 'NX' && redisStore.has(key)) return null;
        redisStore.set(key, value);
        return 'OK';
      }),
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

  return { fastify: fastify as FastifyInstance, ctx, redisStore };
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

  it('threads the code auth_time (epoch ms) into the id_token (OIDC Core §2)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    // A fixed session establishment time captured on the code at authorize time.
    const authTimeMs = 1_700_000_000_000;
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      scopes: ['openid'],
      authTime: authTimeMs,
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    // The route passes epoch ms; signIdToken (jwt plugin) floors to seconds.
    expect(fastify.jwtUtils.signIdToken).toHaveBeenCalledWith(
      expect.objectContaining({ authTime: authTimeMs })
    );
  });

  it('omits auth_time when the code carries none (legacy in-flight code)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      scopes: ['openid'],
      authTime: null,
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    const idClaims = (fastify.jwtUtils.signIdToken as unknown as Mock).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect(idClaims['authTime']).toBeUndefined();
  });

  it('threads the code assurance level into the id_token as acr (#237)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      scopes: ['openid'],
      assuranceLevel: 'high',
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    // Rendered into the deployment's vocabulary at ISSUANCE, from the internal
    // level stored on the code (ADR-010).
    expect(fastify.jwtUtils.signIdToken).toHaveBeenCalledWith(
      expect.objectContaining({ acr: 'http://eidas.europa.eu/LoA/high' })
    );
  });

  it('omits acr entirely when the code records no assurance — the password-login invariant (#237/#240)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      scopes: ['openid'],
      // What /oauth/authorize writes for a password session: ADR-003 makes a
      // password credential `'low'`, and `'low'` bears no `acr`.
      assuranceLevel: null,
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    const idClaims = (fastify.jwtUtils.signIdToken as unknown as Mock).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    // Not "present and low" — ABSENT. An RP may gate on presence, so the two
    // are not interchangeable.
    expect('acr' in idClaims).toBe(false);
  });

  it.each([
    ['low', 'low'],
    ['an unreadable value', 'medium'],
  ])('omits acr when the code carries %s', async (_label, assuranceLevel) => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      scopes: ['openid'],
      assuranceLevel,
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    const idClaims = (fastify.jwtUtils.signIdToken as unknown as Mock).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect('acr' in idClaims).toBe(false);
  });

  it('gates ID-token email claims on the email scope: openid-only omits them even for a verified user — BREAKING #259', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      // openid WITHOUT email: the default stub fixture has a VERIFIED email
      // attribute, so only the scope gate can explain the omission.
      scopes: ['openid'],
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    const idClaims = (fastify.jwtUtils.signIdToken as unknown as Mock).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect('email' in idClaims).toBe(false);
    expect('email_verified' in idClaims).toBe(false);
    // The access-token convenience claims are NOT scope-gated (unchanged).
    const accessClaims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect(accessClaims['email']).toBe('user@example.com');
  });

  it('omits BOTH email claims from access AND id token when no verified attribute exists — BREAKING #229', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
      ...authCode,
      scopes: ['openid', 'email'],
    });
    (
      fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue([]);
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    // Omitted means the KEYS are absent — never null (proof standard: `in`).
    const accessClaims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect('email' in accessClaims).toBe(false);
    expect('email_verified' in accessClaims).toBe(false);
    const idClaims = (fastify.jwtUtils.signIdToken as unknown as Mock).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect('email' in idClaims).toBe(false);
    expect('email_verified' in idClaims).toBe(false);
  });

  it('omits the email claims when the only verified attribute has expired (#229)', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (
      fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue([
      {
        id: 'attr-expired',
        userId: 'user-1',
        source: 'wallet',
        attrKey: 'email',
        attrValue: 'expired@example.com',
        verified: true,
        expiresAt: Date.now() - 1000,
        createdAt: 1,
        updatedAt: 1,
      },
    ]);
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    const accessClaims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect('email' in accessClaims).toBe(false);
    expect('email_verified' in accessClaims).toBe(false);
  });

  it('applies the ADR-002 trust order across sources at emission (#229)', async () => {
    const attrRow = (source: string, attrValue: string) => ({
      id: `attr-${source}`,
      userId: 'user-1',
      source,
      attrKey: 'email',
      attrValue,
      verified: true,
      expiresAt: null,
      createdAt: 1,
      updatedAt: 1,
    });
    const wallet = attrRow('wallet', 'wallet@example.com');
    const oidc = attrRow('oidc_google', 'oidc@example.com');
    const self = attrRow('self_reported', 'self@example.com');

    // Real selector, mocked storage: the chain walks down as higher-trust
    // sources disappear (the repository's verified-only SQL filter is proven
    // separately at the integration layer).
    for (const [rows, expected] of [
      [[self, oidc, wallet], 'wallet@example.com'],
      [[self, oidc], 'oidc@example.com'],
      [[self], 'self@example.com'],
    ] as const) {
      const { fastify, ctx, authCode } = setupAuthCodeStub();
      (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
        ...authCode,
        scopes: ['openid', 'email'],
      });
      (
        fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
      ).mockResolvedValue(rows);
      await tokenRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');

      await ctx.handler(baseRequest(), createReply());

      // ONE shared resolution: access token and ID token agree by construction.
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ email: expected, email_verified: true })
      );
      expect(fastify.jwtUtils.signIdToken).toHaveBeenCalledWith(
        expect.objectContaining({ email: expected, email_verified: true })
      );
    }
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

  it('rejects a used / expired / unknown code (findByCode filters them out → invalid_grant)', async () => {
    // Single-use + expiry are enforced at the repository layer: findByCode
    // returns ONLY codes that are `used = false` AND unexpired (see the
    // repository integration tests for the markUsed CAS + expiry filter). So a
    // second redemption of an already-used code — and an expired one — both
    // surface to the route as `findByCode` → undefined. The token endpoint must
    // map that to invalid_grant (RFC 6749 §5.2), not a 500.
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue(
      undefined
    );
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(handler(baseRequest(), reply)).rejects.toThrow(InvalidGrantError);
    // No token issued, and the code was never (re-)marked used.
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.authorizationCodes.markUsed).not.toHaveBeenCalled();
  });

  it('marks the authorization code used before issuing tokens (single-use)', async () => {
    // The route MUST consume the code via markUsed (the atomic CAS that makes a
    // replay of the same code fail on the second exchange — see the repository
    // integration test for the race). Assert the consume happens AND precedes
    // token signing on a successful exchange.
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await handler(baseRequest(), reply);

    expect(fastify.repositories.authorizationCodes.markUsed).toHaveBeenCalledWith(authCode.id);
    const markUsedOrder = (fastify.repositories.authorizationCodes.markUsed as unknown as Mock).mock
      .invocationCallOrder[0];
    const signOrder = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .invocationCallOrder[0];
    expect(markUsedOrder).toBeLessThan(signOrder);
  });

  it('rejects replay via the markUsed CAS losing the race (NotFoundError → no token)', async () => {
    // Models the concurrent-redemption window: a code passes findByCode (it was
    // still live when read), but a parallel exchange consumed it first, so the
    // atomic markUsed CAS (`WHERE used = false`) matches no row and throws
    // NotFoundError. The route must surface that and issue NO token, rather than
    // minting a second access token for the same code.
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.repositories.authorizationCodes.markUsed as unknown as Mock).mockRejectedValue(
      new NotFoundError('AuthorizationCode', 'authcode-uuid-1')
    );
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(handler(baseRequest(), reply)).rejects.toThrow(NotFoundError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
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
    // #229: the attribute fixture DELIBERATELY diverges from the users-row
    // email (rt@example.com) so the rotation assertion is sourcing-decisive —
    // a revert to users-row claim sourcing emits the wrong value and fails.
    (
      fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue([
      {
        id: 'attr-rt',
        userId: user.id,
        source: 'self_reported',
        attrKey: 'email',
        attrValue: 'rt-attr@example.com',
        verified: true,
        expiresAt: null,
        createdAt: 1,
        updatedAt: 1,
      },
    ]);
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
    // #229: the emitted email is the ATTRIBUTE value, not the users row's.
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        email: 'rt-attr@example.com',
        email_verified: true,
        scope: 'read:foo write:foo',
        aud: 'https://api.example.com',
      })
    );
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).toHaveBeenCalledWith(
      user.id,
      'email'
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
    // #229 sourcing-decisive email check: the default attribute fixture
    // resolves user@example.com while the subject users row carries
    // subject@example.com — a users-row revert emits the wrong value.
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        clientId: client.clientId,
        email: 'user@example.com',
        email_verified: true,
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

  it('omits BOTH email claims from the delegated token when no verified attribute exists — BREAKING #229', async () => {
    const { fastify, ctx } = setupExchangeStub({
      subjectAud: ['https://api.example.com', AGENT_CLIENT_ID],
    });
    (
      fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue([]);

    await invoke(fastify, ctx, exchangeRequest());

    const claims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect('email' in claims).toBe(false);
    expect('email_verified' in claims).toBe(false);
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

/* -------------------------------------------------------------------------- */
/*      ADR-011 — MCP Enterprise-Managed Authorization (ID-JAG), both sides     */
/* -------------------------------------------------------------------------- */

const ID_JAG_TYP = 'oauth-id-jag+jwt';
const JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ID_JAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag';
const ACCESS_TOKEN_URN = 'urn:ietf:params:oauth:token-type:access_token';

const AS_ISSUER = 'https://auth.example.com';
const IDP_ISSUER = 'https://idp.example.com';
const MCP_SERVER = 'https://mcp.example.com/';
const TARGET_AS = 'https://auth.chat.example';
const EMA_CLIENT_ID = 'mcp-client-1';

/**
 * Serve the trusted IdP's OIDC discovery document and JWK Set through the
 * SSRF-guarded fetcher, so the ID-JAG consume tests exercise the REAL key
 * resolution chain (allowlist → discovery → jwks_uri → JWK import) rather than
 * a mocked-out resolver.
 */
async function wireTrustedIdp(): Promise<CryptoKey> {
  const { exportJWK, importSPKI } = await import('jose');
  const publicKey = await importSPKI(IDP_KEYS.publicKeyPem, 'EdDSA');
  const jwk = await exportJWK(publicKey);

  ssrfSafeGet.mockImplementation(async (url: string) => {
    if (url === `${IDP_ISSUER}/.well-known/openid-configuration`) {
      return {
        status: 200,
        body: JSON.stringify({ issuer: IDP_ISSUER, jwks_uri: `${IDP_ISSUER}/jwks.json` }),
        headers: {},
      };
    }
    if (url === `${IDP_ISSUER}/jwks.json`) {
      return {
        status: 200,
        body: JSON.stringify({ keys: [{ ...jwk, kid: 'idp-1' }] }),
        headers: {},
      };
    }
    throw new Error(`unexpected fetch: ${url}`);
  });

  return (await importPKCS8(IDP_KEYS.privateKeyPem, 'EdDSA')) as CryptoKey;
}

let idJagJtiCounter = 0;

async function signIdJag(
  privateKey: CryptoKey,
  overrides: Record<string, unknown> = {},
  header: Record<string, unknown> = {}
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    jti: `route-jti-${++idJagJtiCounter}`,
    iss: IDP_ISSUER,
    sub: 'U019488227',
    aud: AS_ISSUER,
    resource: MCP_SERVER,
    client_id: EMA_CLIENT_ID,
    iat: now,
    exp: now + 120,
    ...overrides,
  };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete payload[key];
  }
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'EdDSA', typ: ID_JAG_TYP, kid: 'idp-1', ...header })
    .sign(privateKey);
}

describe('POST /oauth/token — ID-JAG CONSUME (jwt-bearer grant, ADR-011)', () => {
  /**
   * A confidential client provisioned for the jwt-bearer grant, with the MCP
   * server on its operator-set audience allowlist and a linked enterprise
   * subject. Every ID-JAG deny-path test starts from this and removes one thing.
   */
  function setupConsumeStub(
    opts: {
      grantTypes?: string[];
      audience?: string[] | null;
      scopes?: string[];
      confidential?: boolean;
      linked?: boolean;
      userEnabled?: boolean;
      maxAgentMode?: string | null;
      isAgent?: boolean;
    } = {}
  ) {
    const { fastify, ctx, redisStore } = createFastifyStub();

    const client = {
      id: 'client-uuid-ema-1',
      clientId: EMA_CLIENT_ID,
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: opts.grantTypes ?? [JWT_BEARER_GRANT],
      scopes: opts.scopes ?? ['chat.read', 'chat.history'],
      audience: opts.audience === undefined ? [MCP_SERVER] : opts.audience,
      isAgent: opts.isAgent ?? true,
      maxAgentMode: opts.maxAgentMode ?? null,
      tokenEndpointAuthMethod: opts.confidential === false ? 'none' : 'client_secret_post',
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (
      fastify.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
    ).mockResolvedValue(
      opts.linked === false
        ? undefined
        : {
            id: 'cred-ema-1',
            userId: 'user-uuid-enterprise',
            realmId: 'realm-1',
            providerType: `oidc_${IDP_ISSUER}`,
            externalSub: 'U019488227',
            credentialData: {},
          }
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-uuid-enterprise',
      enabled: opts.userEnabled ?? true,
    });
    (
      fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue([]);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('ema.access.jwt');

    return { fastify, ctx, client, redisStore };
  }

  function bearerRequest(assertion: string, overrides: Record<string, unknown> = {}) {
    return {
      body: {
        grant_type: JWT_BEARER_GRANT,
        assertion,
        client_id: EMA_CLIENT_ID,
        client_secret: 'secret',
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

  function enableIdJag() {
    mockEnv['ID_JAG_ENABLED'] = true;
    mockEnv['ID_JAG_TRUSTED_ISSUERS'] = [IDP_ISSUER];
  }

  it('issues an access token audience-restricted to the assertion `resource` (EMA §5.1)', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    const result = (await invoke(
      fastify,
      ctx,
      bearerRequest(await signIdJag(idpKey, { scope: 'chat.read chat.history' }))
    )) as Record<string, unknown>;

    expect(result['token_type']).toBe('Bearer');
    expect(result['access_token']).toBe('ema.access.jwt');
    expect(result['scope']).toBe('chat.read chat.history');
    // THE central MUST: `aud` is the MCP server the assertion names — a single
    // value, not the client's default audience and not an array.
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ sub: 'user-uuid-enterprise', aud: MCP_SERVER })
    );
    // EMA §5.2 is a plain access-token response: no refresh token, no
    // `issued_token_type`.
    expect(result).not.toHaveProperty('refresh_token');
    expect(result).not.toHaveProperty('issued_token_type');
  });

  it('resolves the subject through (realm, oidc_<issuer>, sub)', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    await invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)));

    expect(fastify.repositories.userCredentials.findByRealmProviderSub).toHaveBeenCalledWith(
      'realm-1',
      `oidc_${IDP_ISSUER}`,
      'U019488227'
    );
  });

  it('rejects the grant entirely when ID_JAG_ENABLED is false', async () => {
    // Flag left at its default (false) — no allowlist, no IdP wired.
    const { fastify, ctx } = setupConsumeStub();
    const idpKey = (await importPKCS8(IDP_KEYS.privateKeyPem, 'EdDSA')) as CryptoKey;

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(Error);
    // Refused BEFORE client authentication, so nothing was looked up.
    expect(fastify.repositories.oauthClients.findByClientId).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects every assertion when the trusted-issuer allowlist is EMPTY', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    mockEnv['ID_JAG_TRUSTED_ISSUERS'] = [];
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(InvalidGrantError);
    // Fail-closed BEFORE any network call.
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('rejects an issuer that is not on the allowlist, without fetching anything', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey, { iss: 'https://evil.example' })))
    ).rejects.toBeInstanceOf(InvalidGrantError);
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('rejects an `aud` that is not this authorization server', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey, { aud: 'https://other.example' })))
    ).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('rejects an expired assertion', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();
    const now = Math.floor(Date.now() / 1000);

    await expect(
      invoke(
        fastify,
        ctx,
        bearerRequest(await signIdJag(idpKey, { iat: now - 900, exp: now - 800 }))
      )
    ).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('rejects `alg: none`', async () => {
    enableIdJag();
    await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: ID_JAG_TYP })).toString(
      'base64url'
    );
    const payload = Buffer.from(
      JSON.stringify({
        jti: 'none-1',
        iss: IDP_ISSUER,
        sub: 'U019488227',
        aud: AS_ISSUER,
        resource: MCP_SERVER,
        client_id: EMA_CLIENT_ID,
        iat: now,
        exp: now + 120,
      })
    ).toString('base64url');

    await expect(
      invoke(fastify, ctx, bearerRequest(`${header}.${payload}.`))
    ).rejects.toBeInstanceOf(InvalidGrantError);
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('rejects a MAC-algorithm assertion', async () => {
    enableIdJag();
    await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();
    const now = Math.floor(Date.now() / 1000);
    const macAssertion = await new SignJWT({
      jti: 'hs-1',
      iss: IDP_ISSUER,
      sub: 'U019488227',
      aud: AS_ISSUER,
      resource: MCP_SERVER,
      client_id: EMA_CLIENT_ID,
      iat: now,
      exp: now + 120,
    })
      .setProtectedHeader({ alg: 'HS256', typ: ID_JAG_TYP })
      .sign(new Uint8Array(32).fill(9));

    await expect(invoke(fastify, ctx, bearerRequest(macAssertion))).rejects.toBeInstanceOf(
      InvalidGrantError
    );
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('rejects a REPLAYED assertion (same jti twice)', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();
    const assertion = await signIdJag(idpKey, { jti: 'replay-me' });

    await expect(invoke(fastify, ctx, bearerRequest(assertion))).resolves.toBeDefined();
    await expect(invoke(fastify, ctx, bearerRequest(assertion))).rejects.toBeInstanceOf(
      InvalidGrantError
    );
    // The token was issued exactly once.
    expect((fastify.jwtUtils.signAccessToken as unknown as Mock).mock.calls).toHaveLength(1);
  });

  it('rejects an assertion with NO `resource` claim', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey, { resource: undefined })))
    ).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('rejects a `resource` the client is not configured to reach', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub({ audience: ['https://other-mcp.example/'] });

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(InvalidTargetError);
  });

  it('rejects every resource when the client has NO configured audience (deny by default)', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub({ audience: null });

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(InvalidTargetError);
  });

  it('rejects a `resource` PARAMETER that disagrees with the assertion claim', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    await expect(
      invoke(
        fastify,
        ctx,
        bearerRequest(await signIdJag(idpKey), { resource: ['https://elsewhere.example/'] })
      )
    ).rejects.toBeInstanceOf(InvalidTargetError);
  });

  it('rejects an assertion whose `client_id` names a different client', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey, { client_id: 'someone-else' })))
    ).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('rejects a client not registered for the jwt-bearer grant', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub({ grantTypes: ['authorization_code'] });

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(UnauthorizedClientError);
  });

  it('rejects a PUBLIC client (no secret presented)', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub({ confidential: false });

    await expect(
      invoke(fastify, ctx, {
        body: {
          grant_type: JWT_BEARER_GRANT,
          assertion: await signIdJag(idpKey),
          client_id: EMA_CLIENT_ID,
        },
        ip: '127.0.0.1',
        headers: {},
      })
    ).rejects.toBeInstanceOf(InvalidClientError);
  });

  it('rejects an UNLINKED subject rather than provisioning one', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub({ linked: false });

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(InvalidGrantError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects a linked-but-DISABLED user', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub({ userEnabled: false });

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('rejects a requested scope wider than the assertion authorized', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    await expect(
      invoke(
        fastify,
        ctx,
        bearerRequest(await signIdJag(idpKey, { scope: 'chat.read' }), {
          scope: 'chat.read chat.history',
        })
      )
    ).rejects.toBeInstanceOf(InvalidScopeError);
  });

  it('rejects an assertion scope the CLIENT may not hold, even when the IdP authorized it', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub({ scopes: ['chat.read'] });

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey, { scope: 'chat.read admin.all' })))
    ).rejects.toBeInstanceOf(InvalidScopeError);
  });

  it('applies the agent scope-mode cap to an assertion-granted agent scope', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    // The client is allowed `agent:exec` in its raw allowlist but is capped at
    // `readonly` — the cap wins (fail-closed), exactly as on every other grant.
    const { fastify, ctx } = setupConsumeStub({
      scopes: ['agent:exec'],
      maxAgentMode: 'readonly',
    });

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey, { scope: 'agent:exec' })))
    ).rejects.toBeInstanceOf(InvalidScopeError);
  });

  it('narrows the granted scope when the request asks for a subset', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    const result = (await invoke(
      fastify,
      ctx,
      bearerRequest(await signIdJag(idpKey, { scope: 'chat.read chat.history' }), {
        scope: 'chat.read',
      })
    )) as Record<string, unknown>;

    expect(result['scope']).toBe('chat.read');
  });

  it('audit-logs both the accept and the reject', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();

    const accepted = setupConsumeStub();
    await invoke(accepted.fastify, accepted.ctx, bearerRequest(await signIdJag(idpKey)));
    expect(accepted.fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'oauth.token.exchange.success',
        success: true,
        metadata: expect.objectContaining({ grantType: 'jwt-bearer', resource: MCP_SERVER }),
      })
    );

    const rejected = setupConsumeStub({ linked: false });
    await expect(
      invoke(rejected.fastify, rejected.ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(InvalidGrantError);
    expect(rejected.fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'oauth.token.exchange.failure',
        success: false,
        metadata: expect.objectContaining({ grantType: 'jwt-bearer' }),
      })
    );
  });
});

describe('POST /oauth/token — ID-JAG MINT (token exchange, ADR-011)', () => {
  const AGENT_CLIENT_ID = 'agent-client';

  function setupMintStub(
    opts: {
      audience?: string[] | null;
      isAgent?: boolean;
      grantTypes?: string[];
      subjectScope?: string;
      subjectAct?: unknown;
    } = {}
  ) {
    const { fastify, ctx } = createFastifyStub();

    const client = {
      id: 'client-uuid-agent-1',
      clientId: AGENT_CLIENT_ID,
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: opts.grantTypes ?? [TOKEN_EXCHANGE_GRANT],
      scopes: [] as string[],
      audience: opts.audience === undefined ? [TARGET_AS, MCP_SERVER] : opts.audience,
      isAgent: opts.isAgent ?? true,
      maxAgentMode: null,
      tokenEndpointAuthMethod: 'client_secret_post',
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
      sub: 'user-uuid-subject',
      clientId: 'original-app-client',
      scope: opts.subjectScope ?? 'chat.read chat.history',
      aud: [AGENT_CLIENT_ID],
      iss: AS_ISSUER,
      token_use: 'access',
      exp: Math.floor(Date.now() / 1000) + 600,
      ...(opts.subjectAct ? { act: opts.subjectAct } : {}),
    });
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-uuid-subject',
      enabled: true,
    });

    return { fastify, ctx, client };
  }

  function mintRequest(overrides: Record<string, unknown> = {}) {
    return {
      body: {
        grant_type: TOKEN_EXCHANGE_GRANT,
        client_id: AGENT_CLIENT_ID,
        client_secret: 'secret',
        subject_token: 'subject.jwt.token',
        subject_token_type: ACCESS_TOKEN_URN,
        requested_token_type: ID_JAG_TOKEN_TYPE,
        // Arrays, because the Zod body schema coerces both parameters to arrays
        // before the handler ever sees them; these tests call the handler
        // directly, so they supply the post-parse shape.
        audience: [TARGET_AS],
        resource: [MCP_SERVER],
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

  it('mints an ID-JAG with the exact spec claim set and `token_type: "N_A"`', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub();

    const result = (await invoke(fastify, ctx, mintRequest())) as Record<string, unknown>;

    expect(result['token_type']).toBe('N_A');
    expect(result['issued_token_type']).toBe(ID_JAG_TOKEN_TYPE);
    expect(result['expires_in']).toBe(300);
    expect(result['scope']).toBe('chat.read chat.history');
    expect(result).not.toHaveProperty('refresh_token');

    const assertion = result['access_token'] as string;
    expect(decodeProtectedHeader(assertion)).toEqual({ alg: 'EdDSA', typ: ID_JAG_TYP });

    const claims = decodeJwt(assertion) as Record<string, unknown>;
    expect(Object.keys(claims).sort()).toEqual(
      ['aud', 'client_id', 'exp', 'iat', 'iss', 'jti', 'resource', 'scope', 'sub'].sort()
    );
    expect(claims['iss']).toBe(AS_ISSUER);
    expect(claims['sub']).toBe('user-uuid-subject');
    expect(claims['aud']).toBe(TARGET_AS);
    expect(claims['resource']).toBe(MCP_SERVER);
    expect(claims['client_id']).toBe(AGENT_CLIENT_ID);
    // No `act`, and no identity claims crossing the trust boundary.
    expect(claims).not.toHaveProperty('act');
    expect(claims).not.toHaveProperty('email');
    // An ID-JAG is NOT an access token: no access token was signed on this path.
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects the ID-JAG token type when ID_JAG_ENABLED is false', async () => {
    // Flag at its default — the pre-ADR-011 access_token-only gate must stand.
    const { fastify, ctx } = setupMintStub();

    await expect(invoke(fastify, ctx, mintRequest())).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it('rejects a MISSING audience', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub();

    await expect(invoke(fastify, ctx, mintRequest({ audience: undefined }))).rejects.toBeInstanceOf(
      InvalidRequestError
    );
  });

  it('rejects a MULTI-VALUED audience rather than picking the first', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub();

    await expect(
      invoke(fastify, ctx, mintRequest({ audience: [TARGET_AS, 'https://other-as.example'] }))
    ).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it('rejects a missing or multi-valued resource', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;

    const missing = setupMintStub();
    await expect(
      invoke(missing.fastify, missing.ctx, mintRequest({ resource: undefined }))
    ).rejects.toBeInstanceOf(InvalidRequestError);

    const multiple = setupMintStub({ audience: [TARGET_AS, MCP_SERVER, 'https://mcp2.example/'] });
    await expect(
      invoke(
        multiple.fastify,
        multiple.ctx,
        mintRequest({ resource: [MCP_SERVER, 'https://mcp2.example/'] })
      )
    ).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it('rejects an audience outside the client policy allowlist', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub({ audience: [MCP_SERVER] });

    await expect(invoke(fastify, ctx, mintRequest())).rejects.toBeInstanceOf(InvalidTargetError);
  });

  it('rejects everything when the client has NO configured audience (deny by default)', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub({ audience: null });

    await expect(invoke(fastify, ctx, mintRequest())).rejects.toBeInstanceOf(InvalidTargetError);
  });

  it('keeps the agent gate in force on the mint path', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const nonAgent = setupMintStub({ isAgent: false });
    await expect(invoke(nonAgent.fastify, nonAgent.ctx, mintRequest())).rejects.toBeInstanceOf(
      UnauthorizedClientError
    );

    const notGranted = setupMintStub({ grantTypes: ['authorization_code'] });
    await expect(invoke(notGranted.fastify, notGranted.ctx, mintRequest())).rejects.toBeInstanceOf(
      UnauthorizedClientError
    );
  });

  it('rejects a PUBLIC client attempting to mint', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub();

    await expect(
      invoke(fastify, ctx, {
        body: {
          grant_type: TOKEN_EXCHANGE_GRANT,
          client_id: AGENT_CLIENT_ID,
          subject_token: 'subject.jwt.token',
          subject_token_type: ACCESS_TOKEN_URN,
          requested_token_type: ID_JAG_TOKEN_TYPE,
          audience: [TARGET_AS],
          resource: [MCP_SERVER],
        },
        ip: '127.0.0.1',
        headers: {},
      })
    ).rejects.toBeInstanceOf(InvalidClientError);
  });

  it('rejects an up-scoped mint (scope wider than the subject token)', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub({ subjectScope: 'chat.read' });

    await expect(
      invoke(fastify, ctx, mintRequest({ scope: 'chat.read chat.history' }))
    ).rejects.toBeInstanceOf(InvalidScopeError);
  });

  it('keeps the delegation-depth bound in force', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    // A chain already at the maximum depth; adding this agent exceeds it.
    const deepChain = { sub: 'a1', act: { sub: 'a2', act: { sub: 'a3', act: { sub: 'a4' } } } };
    const { fastify, ctx } = setupMintStub({ subjectAct: deepChain });

    await expect(invoke(fastify, ctx, mintRequest())).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it('does NOT regress the ordinary access_token exchange when ID-JAG is enabled', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub();
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('delegated.jwt');

    const result = (await invoke(
      fastify,
      ctx,
      mintRequest({
        requested_token_type: ACCESS_TOKEN_URN,
        audience: undefined,
        resource: undefined,
      })
    )) as Record<string, unknown>;

    expect(result['token_type']).toBe('Bearer');
    expect(result['issued_token_type']).toBe(ACCESS_TOKEN_URN);
    expect(result['access_token']).toBe('delegated.jwt');
  });

  it('audit-logs the mint with the assertion id, never the assertion itself', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub();

    const result = (await invoke(fastify, ctx, mintRequest())) as Record<string, unknown>;
    const claims = decodeJwt(result['access_token'] as string);

    expect(fastify.repositories.auditLogs.create).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'oauth.token.exchange.success',
        metadata: expect.objectContaining({
          issuedTokenType: ID_JAG_TOKEN_TYPE,
          idJagId: claims.jti,
          audience: TARGET_AS,
          resource: MCP_SERVER,
        }),
      })
    );
    const logged = (fastify.repositories.auditLogs.create as unknown as Mock).mock.calls
      .map((call) => JSON.stringify(call[0]))
      .join('');
    expect(logged).not.toContain(result['access_token']);
  });
});

describe('POST /oauth/token — response serialization (union schema, ADR-011)', () => {
  const AGENT_CLIENT_ID = 'agent-client';

  /**
   * Boot the REAL route on a REAL Fastify instance with the Zod type provider,
   * so the `response: { 200: ... }` schema is actually applied.
   *
   * This is the one thing the handler-level tests above cannot check: they call
   * the route handler directly and never touch the serializer. Before ADR-011
   * the response schema pinned `token_type: z.literal('Bearer')`, which would
   * reject an ID-JAG's mandatory `N_A` at serialization time — a failure that
   * only appears once a response is actually written.
   */
  async function buildApp(overrides: (fastify: FastifyInstance) => void) {
    const { serializerCompiler, validatorCompiler } = await import('fastify-type-provider-zod');
    const Fastify = (await import('fastify')).default;

    const app = Fastify({ logger: false });
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    await app.register(async (instance) => {
      const { fastify: stub } = createFastifyStub();
      for (const [key, value] of Object.entries(stub)) {
        if (key === 'withTypeProvider') continue;
        instance.decorate(key as never, value as never);
      }
      overrides(instance as unknown as FastifyInstance);
      await instance.register(tokenRoute);
    });
    await app.ready();
    return app;
  }

  function mintingApp() {
    return buildApp((instance) => {
      const client = {
        id: 'client-uuid-agent-1',
        clientId: AGENT_CLIENT_ID,
        clientSecretHash: 'hash',
        enabled: true,
        grantTypes: [TOKEN_EXCHANGE_GRANT],
        scopes: [] as string[],
        audience: [TARGET_AS, MCP_SERVER],
        isAgent: true,
        maxAgentMode: null,
        tokenEndpointAuthMethod: 'client_secret_post',
      };
      (instance.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        client
      );
      (instance.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (instance.jwtUtils.verifyAccessToken as unknown as Mock).mockResolvedValue({
        sub: 'user-uuid-subject',
        clientId: 'original-app-client',
        scope: 'chat.read',
        aud: [AGENT_CLIENT_ID],
        iss: AS_ISSUER,
        token_use: 'access',
        exp: Math.floor(Date.now() / 1000) + 600,
      });
      (instance.repositories.users.findById as unknown as Mock).mockResolvedValue({
        id: 'user-uuid-subject',
        enabled: true,
      });
      (instance.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('delegated.jwt');
      (
        instance.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
      ).mockResolvedValue([]);
    });
  }

  it('serializes an ID-JAG response with token_type "N_A" intact', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const app = await mintingApp();

    const response = await app.inject({
      method: 'POST',
      url: '/token',
      payload: {
        grant_type: TOKEN_EXCHANGE_GRANT,
        client_id: AGENT_CLIENT_ID,
        client_secret: 'secret',
        subject_token: 'subject.jwt.token',
        subject_token_type: ACCESS_TOKEN_URN,
        requested_token_type: ID_JAG_TOKEN_TYPE,
        audience: TARGET_AS,
        resource: MCP_SERVER,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as Record<string, unknown>;
    expect(body['token_type']).toBe('N_A');
    expect(body['issued_token_type']).toBe(ID_JAG_TOKEN_TYPE);
    expect(decodeProtectedHeader(body['access_token'] as string).typ).toBe(ID_JAG_TYP);

    await app.close();
  });

  it('still serializes an authorization_code response with refresh_token + id_token', async () => {
    // The 200 schema changed shape in ADR-011; the richest existing response
    // must survive it unchanged, including the members the ID-JAG variant does
    // not declare (`refresh_token`, `id_token`).
    const app = await buildApp((instance) => {
      const client = {
        id: 'client-uuid-1',
        clientId: 'web-app',
        clientSecretHash: 'hash',
        enabled: true,
        grantTypes: ['authorization_code'],
        scopes: [] as string[],
        audience: null,
        tokenEndpointAuthMethod: 'client_secret_post',
      };
      (instance.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        client
      );
      (instance.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (instance.repositories.authorizationCodes.findByCode as unknown as Mock).mockResolvedValue({
        id: 'code-1',
        oauthClientId: 'client-uuid-1',
        userId: 'user-1',
        redirectUri: 'https://app.example.com/cb',
        codeChallenge: 'challenge',
        scopes: ['openid', 'email'],
        resource: [],
        nonce: null,
        authTime: null,
        assuranceLevel: null,
      });
      (instance.pkceUtils.verifyCodeChallenge as unknown as Mock).mockReturnValue(true);
      (instance.repositories.users.findById as unknown as Mock).mockResolvedValue({
        id: 'user-1',
        enabled: true,
        firstName: 'Ada',
        lastName: 'Lovelace',
      });
      (instance.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('access.jwt');
      (instance.jwtUtils.signIdToken as unknown as Mock).mockResolvedValue('id.jwt');
      (instance.jwtUtils.generateRefreshToken as unknown as Mock).mockReturnValue({
        token: 'a'.repeat(64),
        tokenHash: 'hash',
      });
    });

    const response = await app.inject({
      method: 'POST',
      url: '/token',
      payload: {
        grant_type: 'authorization_code',
        client_id: 'web-app',
        client_secret: 'secret',
        code: 'the-code',
        redirect_uri: 'https://app.example.com/cb',
        code_verifier: 'v'.repeat(43),
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as Record<string, unknown>;
    expect(body['token_type']).toBe('Bearer');
    expect(body['access_token']).toBe('access.jwt');
    expect(body['refresh_token']).toBe('a'.repeat(64));
    expect(body['id_token']).toBe('id.jwt');
    expect(body['scope']).toBe('openid email');

    await app.close();
  });

  it('still serializes an ordinary Bearer exchange response unchanged', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const app = await mintingApp();

    const response = await app.inject({
      method: 'POST',
      url: '/token',
      payload: {
        grant_type: TOKEN_EXCHANGE_GRANT,
        client_id: AGENT_CLIENT_ID,
        client_secret: 'secret',
        subject_token: 'subject.jwt.token',
        subject_token_type: ACCESS_TOKEN_URN,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as Record<string, unknown>;
    expect(body['token_type']).toBe('Bearer');
    expect(body['access_token']).toBe('delegated.jwt');
    expect(body['issued_token_type']).toBe(ACCESS_TOKEN_URN);

    await app.close();
  });
});

/**
 * ROUTE-LEVEL wiring for `private_key_jwt` (#384, RFC 7523 §2.2).
 *
 * The helper-level suite in `client-assertion.test.ts` proves the VERIFIER is
 * correct. These tests prove the token endpoint actually CALLS it — a distinction
 * that matters, because the feature originally shipped with a complete, correct,
 * fully-tested verifier that no route ever invoked, leaving every assertion
 * rejected as `invalid_client` while discovery advertised the method as supported.
 * Nothing below reaches into a helper: each case drives the real route handler.
 */
describe('POST /oauth/token — private_key_jwt client authentication (#384 wiring)', () => {
  const PKJWT_CLIENT_ID = 'pkjwt-route-client';
  const AS_ISSUER_URL = 'https://auth.example.com';
  const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

  let clientKeys: { publicKey: CryptoKey; privateKey: CryptoKey };
  let clientPublicJwk: JWK;

  beforeAll(async () => {
    clientKeys = await generateKeyPair('ES256', { extractable: true });
    clientPublicJwk = { ...(await exportJWK(clientKeys.publicKey)), kid: 'client-key-1' };
  });

  /** A client row provisioned for `private_key_jwt` with an inline key set. */
  function pkjwtClient(overrides: Record<string, unknown> = {}) {
    return {
      id: 'client-uuid-pkjwt',
      clientId: PKJWT_CLIENT_ID,
      // A REAL-looking secret hash, exactly as the seed script writes for every
      // client regardless of method. The `private_key_jwt` client must not be
      // authenticable with it.
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: null,
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwks: { keys: [clientPublicJwk as unknown as Record<string, unknown>] },
      jwksUri: null,
      ...overrides,
    };
  }

  async function signAssertion(
    overrides: { aud?: string; jti?: string; iss?: string; sub?: string } = {}
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: 'client-key-1' })
      .setIssuer(overrides.iss ?? PKJWT_CLIENT_ID)
      .setSubject(overrides.sub ?? PKJWT_CLIENT_ID)
      .setAudience(overrides.aud ?? `${AS_ISSUER_URL}/oauth/token`)
      .setJti(overrides.jti ?? `jti-${Math.random().toString(36).slice(2)}`)
      .setIssuedAt(now)
      .setExpirationTime(now + 120)
      .sign(clientKeys.privateKey);
  }

  async function runToken(
    handler: (request: unknown, reply: unknown) => Promise<unknown>,
    body: Record<string, unknown>,
    headers: Record<string, string> = {}
  ) {
    const request = {
      body,
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest', ...headers },
    };
    return handler(request, createReply());
  }

  it('authenticates a private_key_jwt client and issues a token (the wiring itself)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient()
    );
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('signed.jwt.token');

    const result = await runToken(handler, {
      grant_type: 'client_credentials',
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await signAssertion(),
      scope: 'read:foo',
    });

    expect(result).toMatchObject({
      access_token: 'signed.jwt.token',
      token_type: 'Bearer',
      scope: 'read:foo',
    });
    // The shared secret was never consulted — the assertion is what authenticated.
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });

  it('accepts the issuer identifier as `aud` as well as the token endpoint URL', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient()
    );
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('signed.jwt.token');

    const result = await runToken(handler, {
      grant_type: 'client_credentials',
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await signAssertion({ aud: AS_ISSUER_URL }),
      scope: 'read:foo',
    });

    expect(result).toMatchObject({ access_token: 'signed.jwt.token' });
  });

  it('rejects an assertion whose `aud` names a different authorization server', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient()
    );

    await expect(
      runToken(handler, {
        grant_type: 'client_credentials',
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: await signAssertion({ aud: 'https://evil.example.com/oauth/token' }),
      })
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects a replayed assertion — the `jti` is burned at the route', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient()
    );
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('signed.jwt.token');

    const assertion = await signAssertion({ jti: 'replay-me-once' });
    const body = {
      grant_type: 'client_credentials',
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion,
      scope: 'read:foo',
    };

    await expect(runToken(handler, body)).resolves.toMatchObject({
      access_token: 'signed.jwt.token',
    });
    // Byte-identical second presentation.
    await expect(runToken(handler, body)).rejects.toThrow(InvalidClientError);
  });

  it('rejects a private_key_jwt client that falls back to its shared secret', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient()
    );
    // The hasher would say YES — the registered-method gate is what must refuse.
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    await expect(
      runToken(handler, {
        grant_type: 'client_credentials',
        client_id: PKJWT_CLIENT_ID,
        client_secret: 'secret',
      })
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects a client_secret_post client that presents an assertion', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient({ tokenEndpointAuthMethod: 'client_secret_post' })
    );

    await expect(
      runToken(handler, {
        grant_type: 'client_credentials',
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: await signAssertion(),
      })
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects a request presenting BOTH a secret and an assertion (RFC 6749 §2.3)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient()
    );
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    await expect(
      runToken(handler, {
        grant_type: 'client_credentials',
        client_id: PKJWT_CLIENT_ID,
        client_secret: 'secret',
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: await signAssertion(),
      })
    ).rejects.toThrow(InvalidClientError);
    // Refused BEFORE any lookup — never "try each until one passes".
    expect(fastify.repositories.oauthClients.findByClientId).not.toHaveBeenCalled();
  });

  it('rejects an assertion presented with a Basic authorization header', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient()
    );
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

    const basic = Buffer.from(`${PKJWT_CLIENT_ID}:secret`).toString('base64');
    await expect(
      runToken(
        handler,
        {
          grant_type: 'client_credentials',
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: await signAssertion(),
        },
        { authorization: `Basic ${basic}` }
      )
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.repositories.oauthClients.findByClientId).not.toHaveBeenCalled();
  });

  it('rejects half an assertion pair rather than downgrading to the public path', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient({ tokenEndpointAuthMethod: 'none', grantTypes: ['authorization_code'] })
    );

    await expect(
      runToken(handler, {
        grant_type: 'authorization_code',
        client_id: PKJWT_CLIENT_ID,
        code: 'some-code',
        redirect_uri: 'https://app.example.com/cb',
        code_verifier: 'a'.repeat(64),
        client_assertion_type: CLIENT_ASSERTION_TYPE,
      })
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.repositories.oauthClients.findByClientId).not.toHaveBeenCalled();
  });

  it('rejects an assertion signed by a key outside the registered JWK Set', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const attacker = await generateKeyPair('ES256', { extractable: true });
    const now = Math.floor(Date.now() / 1000);
    const forged = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: 'client-key-1' })
      .setIssuer(PKJWT_CLIENT_ID)
      .setSubject(PKJWT_CLIENT_ID)
      .setAudience(`${AS_ISSUER_URL}/oauth/token`)
      .setJti('forged-1')
      .setIssuedAt(now)
      .setExpirationTime(now + 120)
      .sign(attacker.privateKey);

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient()
    );

    await expect(
      runToken(handler, {
        grant_type: 'client_credentials',
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: forged,
      })
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('keeps the pre-#384 client_secret_post path byte-identical', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    // A row with NO `token_endpoint_auth_method` at all — the pre-#384 shape.
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'client-uuid-legacy',
      clientId: 'legacy-client',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: null,
    });
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('signed.jwt.token');

    const result = await runToken(handler, {
      grant_type: 'client_credentials',
      client_id: 'legacy-client',
      client_secret: 'secret',
      scope: 'read:foo',
    });

    expect(result).toMatchObject({ access_token: 'signed.jwt.token', scope: 'read:foo' });
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalled();
  });
});
