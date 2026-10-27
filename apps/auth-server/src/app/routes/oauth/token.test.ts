import { generateKeyPairSync } from 'node:crypto';

import {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
  NotFoundError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
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
import { afterEach, beforeAll, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

// The access-token records of a grant (#627) live in Redis; their own suite
// covers them. Here: what the route asks of them, and when.
vi.mock('../../helpers/grant-access-tokens', () => ({
  recordGrantAccessToken: vi.fn(async () => undefined),
  revokeGrantAccessTokens: vi.fn(async () => 0),
}));

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

// Whether a wallet row's issuer is still trusted is `email-claims.test.ts`'s and
// `wallet-verification.test.ts`'s subject; here every one is.
vi.mock('../../helpers/wallet-verification', () => ({
  isWalletAttributeIssuerStillTrusted: vi.fn().mockResolvedValue(true),
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
    ID_JAG_JWKS_REFRESH_COOLDOWN: 30,
    ID_JAG_JWKS_NEGATIVE_CACHE_TTL: 30,
    ID_JAG_MAX_DOCUMENT_BYTES: 65536,
    ID_JAG_CLOCK_SKEW_LEEWAY: 60,
    ID_JAG_MAX_ASSERTION_LIFETIME: 300,
    ID_JAG_ISSUED_LIFETIME: 300,
  });
}
resetMockEnv();

vi.mock('../../../config/env', () => ({ env: mockEnv }));

const { egressGet } = vi.hoisted(() => ({ egressGet: vi.fn() }));

vi.mock('../../helpers/egress-get', () => ({ egressGet }));

import { createFakeSessionService } from '../../../testing/browser-sessions';
import { blockedEgress } from '../../../testing/egress';
import { supplyRequestRealm, testRealm } from '../../../testing/request-realm';
import { recordGrantAccessToken, revokeGrantAccessTokens } from '../../helpers/grant-access-tokens';
import { emitUserEvent, userEventFor } from '../../helpers/user-events';
import tokenRoute from './token';

const emitUserEventMock = vi.mocked(emitUserEvent);
const recordGrantAccessTokenMock = vi.mocked(recordGrantAccessToken);
const revokeGrantAccessTokensMock = vi.mocked(revokeGrantAccessTokens);

/** The realm every request of this file reaches the route in (#487). */
const REALM = testRealm({ id: 'realm-1', name: 'default' });

const TOKEN_ISSUED = 'urn:qauth:event:token.issued:v1-rc.0';
const TOKEN_REQUEST_FAILED = 'urn:qauth:event:token.request_failed:v1-rc.0';

/** The `data` of every event of the given type the route emitted. */
function emittedData(type: string): unknown[] {
  return emitUserEventMock.mock.calls.filter(([, t]) => t === type).map(([, , data]) => data);
}

beforeEach(() => {
  emitUserEventMock.mockClear();
  recordGrantAccessTokenMock.mockClear();
  revokeGrantAccessTokensMock.mockClear();
});

afterEach(() => {
  resetMockEnv();
  egressGet.mockReset();
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
  // The browser-session service (#488): no grant may reach it.
  const sessionService = createFakeSessionService();

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
      authorizationCodes: {
        findByCodeIncludingUsed: vi.fn(),
        markUsed: vi.fn(),
      },
      users: {
        findById: vi.fn(),
      },
      userCredentials: {
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
        // Rotation's compare-and-set: resolves the revoked row when this
        // request won the race, undefined when the token was already rotated.
        revokeIfActive: vi.fn().mockResolvedValue({ id: 'rotated-row' }),
        revokeFamily: vi.fn().mockResolvedValue(0),
        revokeFamilyByAuthorizationCode: vi
          .fn()
          .mockResolvedValue({ familyId: null, revokedCount: 0 }),
      },
      oauthConsents: {
        // Deny-by-default: no stored consent means no refresh token on the
        // authorization_code grant, so those tests opt IN by overriding this.
        findActive: vi.fn().mockResolvedValue(undefined),
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
    sessionService,
    // In-memory `fastify.redis` with real SET NX semantics — the ID-JAG replay
    // store depends on NX returning null for an already-present key, so a stub
    // that always says 'OK' would make every replay test pass vacuously.
    redis: {
      get: vi.fn(async (key: string) => redisStore.get(key) ?? null),
      // RFC 7009 jti denylist lookups (`isJtiRevoked`).
      exists: vi.fn(async (key: string) => (redisStore.has(key) ? 1 : 0)),
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

  return { fastify: fastify as FastifyInstance, ctx, redisStore, sessionService };
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

  describe('a QAuth API audience (#509)', () => {
    const ADMIN_AUDIENCE = 'urn:qauth:aud:admin:v1-rc.0';

    async function issue(client: Record<string, unknown>, resource?: string[]) {
      const { fastify, ctx } = createFastifyStub();
      await tokenRoute(fastify);
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
        id: 'client-uuid-family',
        clientSecretHash: 'hash',
        enabled: true,
        grantTypes: ['client_credentials'],
        scopes: ['read:foo'],
        ...client,
      });
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('signed.jwt.token');
      if (!ctx.handler) throw new Error('Handler missing');
      const request = {
        body: {
          grant_type: 'client_credentials',
          client_id: client['clientId'],
          client_secret: 'secret',
          scope: 'read:foo',
          ...(resource ? { resource } : {}),
        },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      };
      const result = ctx.handler(request, createReply());
      return { fastify, result };
    }

    it('maps the resource value to the audience of a client that lists it', async () => {
      const { fastify, result } = await issue(
        { clientId: 'family-client', audience: [ADMIN_AUDIENCE, 'https://api.example.com'] },
        [ADMIN_AUDIENCE]
      );
      await expect(result).resolves.toMatchObject({ access_token: 'signed.jwt.token' });
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ aud: ADMIN_AUDIENCE })
      );
    });

    it('never falls back to a client id in the reserved namespace', async () => {
      const { fastify, result } = await issue({ clientId: ADMIN_AUDIENCE, audience: null });
      await expect(result).rejects.toThrow(InvalidTargetError);
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    });

    // No user consents to client_credentials: the client's default audience
    // stands, a listed family audience included (#509).
    it("keeps a listed family audience in the client's default audience", async () => {
      const { fastify, result } = await issue({
        clientId: 'family-client',
        audience: [ADMIN_AUDIENCE, 'https://api.example.com'],
      });
      await expect(result).resolves.toMatchObject({ access_token: 'signed.jwt.token' });
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ aud: [ADMIN_AUDIENCE, 'https://api.example.com'] })
      );
    });

    // A self-registered client lists no reserved audience, whatever its row
    // holds: the allowlist check lets the resource through, the gate refuses.
    it.each([
      ['a dynamically registered client', { metadata: { registrationType: 'dynamic' } }],
      ['a CIMD client', { metadata: { registrationType: 'cimd' } }],
    ])('refuses it to %s whose row lists it', async (_label, origin) => {
      const { fastify, result } = await issue(
        { clientId: 'self-registered', audience: [ADMIN_AUDIENCE], ...origin },
        [ADMIN_AUDIENCE]
      );
      await expect(result).rejects.toThrow(InvalidTargetError);
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
      expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
        expect.objectContaining({
          error: 'invalid_target',
          reason: 'reserved_audience_not_listed',
        }),
      ]);
    });
  });

  it('authenticates the client in the realm of the request, and records the token there (#487)', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      id: 'client-uuid-tenant',
      clientId: 'tenant-client',
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: ['client_credentials'],
      scopes: ['read:foo'],
      audience: null,
    });
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('signed.jwt.token');

    await handler(
      {
        // A request to another realm's host: the resolver found that realm.
        realm: testRealm({ id: 'realm-tenant', name: 'tenant' }),
        body: {
          grant_type: 'client_credentials',
          client_id: 'tenant-client',
          client_secret: 'secret',
          scope: 'read:foo',
        },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      },
      createReply()
    );

    expect(fastify.repositories.oauthClients.findByClientId).toHaveBeenCalledWith(
      'realm-tenant',
      'tenant-client'
    );
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_ISSUED,
      expect.anything(),
      expect.objectContaining({ realmId: 'realm-tenant' })
    );
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

  // #434: ID-JAG targets are a separate column precisely so that listing a
  // foreign authorization server there grants no QAuth access token naming it.
  describe('client_credentials ignores the ID-JAG targets (ADR-011, #434)', () => {
    const FOREIGN_AS = 'https://as.partner.example';

    function setupTargetsClient(audience: string[] | null) {
      const { fastify, ctx } = createFastifyStub();
      const client = {
        id: 'client-uuid-ccr-idjag',
        clientId: 'machine-client-idjag',
        clientSecretHash: 'hash',
        enabled: true,
        grantTypes: ['client_credentials'],
        scopes: ['read:foo'],
        audience,
        idJagTargets: [FOREIGN_AS, 'https://mcp.partner.example/mcp'],
      };
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        client
      );
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
      (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('cc.jwt');
      return { fastify, ctx, client };
    }

    function ccRequest(clientId: string, resource?: string[]) {
      return {
        body: {
          grant_type: 'client_credentials',
          client_id: clientId,
          client_secret: 'secret',
          scope: 'read:foo',
          ...(resource ? { resource } : {}),
        },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'vitest' },
      };
    }

    it.each([
      ['an audience of its own', ['https://api.example.com/v1']],
      ['no audience', null],
    ])(
      'refuses a resource listed only among the ID-JAG targets, for a client with %s',
      async (_label, audience) => {
        const { fastify, ctx, client } = setupTargetsClient(audience);
        await tokenRoute(fastify);
        if (!ctx.handler) throw new Error('Handler missing');

        await expect(
          ctx.handler(ccRequest(client.clientId, [FOREIGN_AS]), createReply())
        ).rejects.toThrow(InvalidTargetError);
        expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
      }
    );

    it('never defaults the token audience to an ID-JAG target', async () => {
      const { fastify, ctx, client } = setupTargetsClient(null);
      await tokenRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');

      await ctx.handler(ccRequest(client.clientId), createReply());

      // The light-mode default (the client's own id), not the targets.
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ aud: client.clientId })
      );
    });
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
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledWith('hash', 'p@ss:word', {
      shedWhenQueueFull: true,
    });
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
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        TOKEN_ISSUED,
        expect.objectContaining({ grantType: 'client_credentials', scopeMode: 'exec' }),
        expect.objectContaining({ clientId: 'cc-agent', actor: 'client' })
      );
      const options = emitUserEventMock.mock.calls[0][3];
      expect(options?.userId).toBeUndefined();
      expect(options?.act).toBeUndefined();
    });

    it('per-agent audit (#186): client_credentials success records no secret/token material', async () => {
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

      const successCall = emitUserEventMock.mock.calls.find(([, type]) => type === TOKEN_ISSUED);
      expect(successCall).toBeDefined();
      const serialized = JSON.stringify(successCall?.slice(2));
      expect(serialized).not.toContain('cc-super-secret');
      expect(serialized).not.toContain('cc-access.jwt');
    });

    it('per-agent audit (#186): NON-agent client_credentials success records no scope mode', async () => {
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

      // The client is the actor, as on every token request; no scope mode.
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        TOKEN_ISSUED,
        {
          grantType: 'client_credentials',
          scopes: ['read:foo'],
          audience: ['plain-machine'],
          expiresIn: 900,
        },
        expect.objectContaining({ clientId: 'plain-machine', actor: 'client' })
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
    const { fastify, ctx, sessionService } = createFastifyStub();

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
      enabled: true,
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
      used: false,
      expiresAt: Date.now() + 60_000,
    };

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(client);
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue(authCode);
    (fastify.repositories.authorizationCodes.markUsed as unknown as Mock).mockResolvedValue(
      undefined
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(user);
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      id: 'consent-uuid-1',
      userId: user.id,
      oauthClientId: client.id,
      scopes: ['read:foo'],
      revokedAt: null,
    });
    (fastify.repositories.refreshTokens.create as unknown as Mock).mockResolvedValue(undefined);
    (fastify.pkceUtils.verifyCodeChallenge as unknown as Mock).mockReturnValue(true);
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('signed.jwt.token');
    (fastify.jwtUtils.signIdToken as unknown as Mock).mockResolvedValue('signed.id.token');
    (fastify.jwtUtils.generateRefreshToken as unknown as Mock).mockReturnValue({
      token: 'refresh-token-plain',
      tokenHash: 'refresh-token-hash',
    });

    return { fastify, ctx, client, user, authCode, sessionService };
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
        clientId: client.clientId,
        scope: 'read:foo',
        aud: 'https://api.example.com',
      })
    );
    // ANT-2026-2O0T72HY: the grant has no `email` scope, so the access token
    // carries no email claim although the user has a verified address, and
    // the attribute is not even looked up.
    const accessClaims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect('email' in accessClaims).toBe(false);
    expect('email_verified' in accessClaims).toBe(false);
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).not.toHaveBeenCalled();

    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: user.id,
        oauthClientId: client.id,
        tokenHash: 'refresh-token-hash',
        scopes: ['read:foo'],
      }),
      expect.anything()
    );
    // The exchange starts the family (#552). The realm sets no
    // sso_max_lifespan, so the token gets the whole refresh lifespan.
    const stored = (fastify.repositories.refreshTokens.create as unknown as Mock).mock
      .calls[0][0] as { familyCreatedAt: number; expiresAt: number };
    expect(stored.familyCreatedAt).toBeGreaterThan(Date.now() - 60_000);
    expect(stored.familyCreatedAt).toBeLessThanOrEqual(Date.now());
    expect(stored.expiresAt).toBe(stored.familyCreatedAt + 604_800_000);

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

  it("caps the new family's first token at the realm's sso_max_lifespan (#552)", async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    await tokenRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    await ctx.handler(
      { ...baseRequest(), realm: testRealm({ id: 'realm-1', ssoMaxLifespan: 3600 }) },
      createReply()
    );

    // One hour is shorter than the week of REFRESH_TOKEN_LIFESPAN, so the
    // family's end is the token's expiry.
    const stored = (fastify.repositories.refreshTokens.create as unknown as Mock).mock
      .calls[0][0] as { familyCreatedAt: number; expiresAt: number };
    expect(stored.expiresAt).toBe(stored.familyCreatedAt + 3_600_000);
  });

  it('caps the new family at the end of the browser session behind the code (#552)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    // A silent re-authorization one minute before the session's end.
    const sessionExpiresAt = Date.now() + 60_000;
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
      ...authCode,
      sessionExpiresAt,
    });
    await tokenRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    await ctx.handler(
      { ...baseRequest(), realm: testRealm({ id: 'realm-1', ssoMaxLifespan: 3600 }) },
      createReply()
    );

    const stored = (fastify.repositories.refreshTokens.create as unknown as Mock).mock
      .calls[0][0] as { familySessionExpiresAt: number | null; expiresAt: number };
    expect(stored.familySessionExpiresAt).toBe(sessionExpiresAt);
    expect(stored.expiresAt).toBe(sessionExpiresAt);
  });

  it('leaves a family uncapped by its session when the realm sets no limit (#552)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    const sessionExpiresAt = Date.now() + 60_000;
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
      ...authCode,
      sessionExpiresAt,
    });
    await tokenRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    await ctx.handler({ ...baseRequest(), realm: testRealm({ id: 'realm-1' }) }, createReply());

    // The session's end is still recorded, for a limit the realm sets later.
    const stored = (fastify.repositories.refreshTokens.create as unknown as Mock).mock
      .calls[0][0] as { familySessionExpiresAt: number | null; expiresAt: number };
    expect(stored.familySessionExpiresAt).toBe(sessionExpiresAt);
    expect(stored.expiresAt).toBeGreaterThan(sessionExpiresAt + 60_000);
  });

  it('creates no browser session on a successful exchange (#488)', async () => {
    // The session this grant once wrote was never returned or read: the
    // browser's session is the one its sign-in created before /oauth/authorize.
    const { fastify, ctx, sessionService } = setupAuthCodeStub();
    // The Redis store a session was once written to, to show none is now.
    const sessionUtils = { setSession: vi.fn() };
    Object.assign(fastify, { sessionUtils });
    await tokenRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    const result = await ctx.handler(baseRequest(), createReply());

    expect(result).toMatchObject({
      access_token: 'signed.jwt.token',
      refresh_token: 'refresh-token-plain',
    });
    expect(sessionService.create).not.toHaveBeenCalled();
    expect(sessionUtils.setSession).not.toHaveBeenCalled();
    // Nothing failed quietly on the way either: the removed write logged its
    // failures as a warning and answered anyway.
    expect(fastify.log.warn).not.toHaveBeenCalled();
  });

  // The consent row is what `/consents` lists and what revocation reaches the
  // refresh tokens through, so a refresh token without one could be neither
  // seen nor withdrawn by the user.
  it.each([
    ['no consent is stored ("Remember this decision" unticked, or revoked since)', undefined],
    ['the stored consent does not cover the code scopes', ['write:foo']],
  ])('issues the access token but NO refresh token when %s', async (_label, consentScopes) => {
    const { fastify, ctx, client, user, authCode } = setupAuthCodeStub();
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(
      consentScopes && { id: 'consent-uuid-1', scopes: consentScopes, revokedAt: null }
    );
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const result = await handler(baseRequest(), createReply());

    expect(fastify.repositories.oauthConsents.findActive).toHaveBeenCalledWith(user.id, client.id);
    expect(result).toMatchObject({ access_token: 'signed.jwt.token', scope: 'read:foo' });
    expect(result).not.toHaveProperty('refresh_token');
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    expect(fastify.metrics.tokensIssued.inc).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: 'refresh' })
    );
    // The code is spent all the same: it cannot be redeemed a second time.
    expect(fastify.repositories.authorizationCodes.markUsed).toHaveBeenCalledWith(
      authCode.id,
      expect.anything()
    );
  });

  it('issues an id_token when the granted scope includes openid (OIDC Core §3.1.3.3)', async () => {
    const { fastify, ctx, client, user, authCode } = setupAuthCodeStub();
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
      ...authCode,
      scopes: ['openid', 'email', 'profile'],
      nonce: 'n-0S6_WzA2Mj',
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const result = await handler(baseRequest(), reply);

    // ID token `aud` is the client_id (NOT the resource audience). Nonce from
    // the authorization request is echoed; name derives from first/last name
    // under the `profile` scope.
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
      scope: 'openid email profile',
    });
  });

  it.each([
    ['openid alone', ['openid']],
    ['openid email', ['openid', 'email']],
  ])(
    'omits name from the id_token under %s although the user has one — BREAKING #755',
    async (_label, scopes) => {
      const { fastify, ctx, authCode } = setupAuthCodeStub();
      // The stub user is "Ada Lovelace", so only the scope gate can explain
      // the omission (OIDC Core §5.4: `name` is a `profile` claim).
      (
        fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
      ).mockResolvedValue({
        ...authCode,
        scopes,
      });
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      const result = await handler(baseRequest(), createReply());

      expect(result).toHaveProperty('id_token', 'signed.id.token');
      const idClaims = (fastify.jwtUtils.signIdToken as unknown as Mock).mock.calls[0][0] as Record<
        string,
        unknown
      >;
      // Absent, not undefined-valued: the key itself is missing.
      expect('name' in idClaims).toBe(false);
      // The access token never carries `name`, under any scope.
      const accessClaims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
        .calls[0][0] as Record<string, unknown>;
      expect('name' in accessClaims).toBe(false);
    }
  );

  it('threads the code auth_time (epoch ms) into the id_token (OIDC Core §2)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    // A fixed session establishment time captured on the code at authorize time.
    const authTimeMs = 1_700_000_000_000;
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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

  it('puts the code’s browser session in the id_token as sid, and nowhere else (#549)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    const sid = '0199f9a1-0000-7000-8000-000000000549';
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
      ...authCode,
      scopes: ['openid', 'read:foo'],
      sessionId: sid,
    });
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
      id: 'consent-uuid-1',
      scopes: ['openid', 'read:foo'],
      revokedAt: null,
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    expect(fastify.jwtUtils.signIdToken).toHaveBeenCalledWith(expect.objectContaining({ sid }));
    // Not on the access token, nor on the refresh row the exchange stores.
    const [accessClaims] = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock.calls[0];
    expect(JSON.stringify(accessClaims)).not.toContain(sid);
    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledOnce();
    const [refreshRow] = (fastify.repositories.refreshTokens.create as unknown as Mock).mock
      .calls[0];
    expect(JSON.stringify(refreshRow)).not.toContain(sid);
  });

  it.each([
    ['no browser session backs it (the legacy Bearer path)', null],
    ['it predates the session column', undefined],
  ])('gives the id_token no sid when %s (#549)', async (_label, sessionId) => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
      ...authCode,
      scopes: ['openid'],
      sessionId,
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    const idClaims = (fastify.jwtUtils.signIdToken as unknown as Mock).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect(idClaims['sid']).toBeUndefined();
  });

  it('gates ID-token AND access-token email claims on the email scope: openid-only omits them even for a verified user — BREAKING #259, ANT-2026-2O0T72HY', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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
    // The access token follows the same rule (ANT-2026-2O0T72HY). Before, it
    // carried the address anyway, in the same response as the ID token that
    // withheld it.
    const accessClaims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect('email' in accessClaims).toBe(false);
    expect('email_verified' in accessClaims).toBe(false);
  });

  it('releases the email claims in BOTH tokens under the email scope (ANT-2026-2O0T72HY)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
      ...authCode,
      scopes: ['openid', 'email'],
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'user@example.com', email_verified: true })
    );
    expect(fastify.jwtUtils.signIdToken).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'user@example.com', email_verified: true })
    );
  });

  it('omits BOTH email claims from access AND id token when no verified attribute exists — BREAKING #229', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    // The `email` scope is granted, so only the expiry can explain the omission.
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
      ...authCode,
      scopes: ['email'],
    });
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
      (
        fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
      ).mockResolvedValue({
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
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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
    // `profile` IS granted, so only the missing name can explain the omission.
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
      ...authCode,
      scopes: ['openid', 'profile'],
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await handler(baseRequest(), reply);

    const call = (fastify.jwtUtils.signIdToken as unknown as Mock).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect('name' in call).toBe(false);
  });

  it('rejects when authorization code was issued to a different client', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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

  describe('loopback redirect_uri port (RFC 8252 §7.3 / RFC 6749 §4.1.3, #414)', () => {
    // The authorization request may use any port on a registered loopback
    // redirect, but the code stores the URI AS REQUESTED — so the token
    // request must repeat it exactly, port included.
    const ISSUED_TO = 'http://127.0.0.1:53817/callback';

    function setupLoopbackCode() {
      const stub = setupAuthCodeStub();
      (
        stub.fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
      ).mockResolvedValue({ ...stub.authCode, redirectUri: ISSUED_TO });
      return stub;
    }

    it('exchanges the code when redirect_uri repeats the requested port', async () => {
      const { fastify, ctx } = setupLoopbackCode();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await handler(baseRequest({ redirect_uri: ISSUED_TO }), createReply());
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledOnce();
    });

    it.each([
      ['the portless registered form', 'http://127.0.0.1/callback'],
      ['another port', 'http://127.0.0.1:53818/callback'],
    ])('rejects %s — only the port differs, still invalid_grant', async (_label, redirectUri) => {
      const { fastify, ctx } = setupLoopbackCode();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(
        handler(baseRequest({ redirect_uri: redirectUri }), createReply())
      ).rejects.toThrow(InvalidGrantError);
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    });
  });

  it('rejects an unknown code (invalid_grant, code_invalid)', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue(undefined);
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(handler(baseRequest(), reply)).rejects.toThrow(InvalidGrantError);
    // No token issued, and the code was never (re-)marked used.
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.authorizationCodes.markUsed).not.toHaveBeenCalled();
    expect(
      fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
    ).not.toHaveBeenCalled();
    expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
      { grantType: 'authorization_code', error: 'invalid_grant', reason: 'code_invalid' },
    ]);
  });

  it('rejects an unspent code past its expiry like an unknown one, and revokes nothing', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({ ...authCode, expiresAt: Date.now() - 1 });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidGrantError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.authorizationCodes.markUsed).not.toHaveBeenCalled();
    expect(
      fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
    ).not.toHaveBeenCalled();
    expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
      { grantType: 'authorization_code', error: 'invalid_grant', reason: 'code_invalid' },
    ]);
  });

  describe('a second redemption of a code (OAuth 2.1 draft-16 §4.1.3, RFC 6749 §4.1.2, RFC 9700 §4.2.4)', () => {
    /** The refresh family the first redemption started. */
    const CODE_FAMILY_ID = '0199f2b4-7c3e-7a51-9d2b-3a6c8e1f0a42';

    /** The authorization-code stub, with the code read as spent a second ago and `fields` over it. */
    function setupSpentCode(fields: Record<string, unknown> = {}) {
      const stub = setupAuthCodeStub();
      (
        stub.fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
      ).mockResolvedValue({ ...stub.authCode, used: true, usedAt: Date.now() - 1_000, ...fields });
      return stub;
    }

    it('denies a replayed code with invalid_grant and revokes the refresh family it started', async () => {
      const { fastify, ctx, authCode } = setupSpentCode();
      const tx = { tx: 'replay' };
      const steps: string[] = [];
      (fastify.db.transaction as unknown as Mock).mockImplementation(
        async (cb: (tx: unknown) => Promise<unknown>) => {
          steps.push('begin');
          const result = await cb(tx);
          steps.push('commit');
          return result;
        }
      );
      (
        fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode as unknown as Mock
      ).mockImplementation(async () => {
        steps.push('revoke family');
        return { familyId: CODE_FAMILY_ID, revokedCount: 2 };
      });
      revokeGrantAccessTokensMock.mockImplementationOnce(async () => {
        steps.push('revoke access tokens');
        return 1;
      });
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidGrantError);
      // Nothing is issued and the code is not spent again.
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
      expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
      expect(fastify.repositories.authorizationCodes.markUsed).not.toHaveBeenCalled();
      // The family's revocation and its event commit together (ADR-019
      // Decision 8); the access tokens of the code and of the family go on
      // the denylist after that commit.
      expect(
        fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
      ).toHaveBeenCalledWith(authCode.id, 'code_replay', tx);
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        TOKEN_REQUEST_FAILED,
        {
          grantType: 'authorization_code',
          error: 'invalid_grant',
          reason: 'code_replay',
          refreshFamilyId: CODE_FAMILY_ID,
          revokedRefreshCount: 2,
        },
        expect.objectContaining({ tx, userId: 'user-uuid-1', clientId: 'test-client-1' })
      );
      expect(revokeGrantAccessTokensMock).toHaveBeenCalledWith(fastify, {
        authorizationCodeId: authCode.id,
        refreshFamilyId: CODE_FAMILY_ID,
      });
      expect(steps).toEqual(['begin', 'revoke family', 'commit', 'revoke access tokens']);
      expect(emittedData(TOKEN_ISSUED)).toEqual([]);
    });

    it('revokes the access token of a code that started no refresh family', async () => {
      const { fastify, ctx, authCode } = setupSpentCode();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidGrantError);
      expect(revokeGrantAccessTokensMock).toHaveBeenCalledWith(fastify, {
        authorizationCodeId: authCode.id,
        refreshFamilyId: null,
      });
      expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
        {
          grantType: 'authorization_code',
          error: 'invalid_grant',
          reason: 'code_replay',
          revokedRefreshCount: 0,
        },
      ]);
    });

    it('still answers invalid_grant when the access tokens cannot be revoked', async () => {
      const { fastify, ctx } = setupSpentCode();
      revokeGrantAccessTokensMock.mockResolvedValueOnce(undefined);
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidGrantError);
    });

    it('treats a replay past the code’s expiry as a replay too', async () => {
      const { fastify, ctx, authCode } = setupSpentCode({ expiresAt: Date.now() - 1 });
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidGrantError);
      expect(
        fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
      ).toHaveBeenCalledWith(authCode.id, 'code_replay', expect.anything());
    });

    // OAuth 2.1 draft-16 §7.5.3: whoever holds the code but not the client's
    // credentials or the verifier must not be able to end the client's tokens.
    it.each([
      [
        'a wrong code_verifier (OAuth 2.1 draft-16 §7.5.3)',
        'pkce_mismatch',
        {},
        (stub: ReturnType<typeof setupSpentCode>) =>
          (stub.fastify.pkceUtils.verifyCodeChallenge as unknown as Mock).mockReturnValue(false),
      ],
      [
        'another client (OAuth 2.1 draft-16 §7.5.3)',
        'client_mismatch',
        {},
        (stub: ReturnType<typeof setupSpentCode>) =>
          (
            stub.fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
          ).mockResolvedValue({ ...stub.authCode, used: true, oauthClientId: 'another-client' }),
      ],
      ['a different redirect_uri', 'redirect_uri_mismatch', { redirect_uri: 'https://x.test/cb' }],
      ['no redirect_uri', 'redirect_uri_missing', { redirect_uri: undefined }],
    ] as const)(
      'refuses a replay with %s and revokes nothing',
      async (_label, reason, body, arrange?: (stub: ReturnType<typeof setupSpentCode>) => void) => {
        const stub = setupSpentCode();
        arrange?.(stub);
        const { fastify, ctx } = stub;
        await tokenRoute(fastify);
        const handler = ctx.handler;
        if (!handler) throw new Error('Handler missing');

        await expect(handler(baseRequest(body), createReply())).rejects.toThrow(InvalidGrantError);
        expect(
          fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
        ).not.toHaveBeenCalled();
        expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
          { grantType: 'authorization_code', error: 'invalid_grant', reason },
        ]);
      }
    );

    it('refuses a replay of a DPoP-bound code without its key and revokes nothing (OAuth 2.1 draft-16 §7.5.3)', async () => {
      // DPoP is off in this stub, so a code bound to a key is refused outright
      // (`dpop_disabled`), the way a proof under another key is.
      const { fastify, ctx } = setupSpentCode({ dpopJkt: 'k'.repeat(43) });
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidGrantError);
      expect(
        fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
      ).not.toHaveBeenCalled();
      expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
        { grantType: 'authorization_code', error: 'invalid_grant', reason: 'dpop_disabled' },
      ]);
    });

    it('refuses a replay without the proof a DPoP-bound code needs with invalid_grant, and revokes nothing (OAuth 2.1 draft-16 §7.5.3)', async () => {
      // DPoP on: an unspent code would answer invalid_dpop_proof here; a spent
      // one answers invalid_grant, as it did before spent codes were read.
      const { fastify, ctx } = setupSpentCode({ dpopJkt: 'k'.repeat(43) });
      Object.assign(fastify, { dpop: { verifyRequest: vi.fn() } });
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidGrantError);
      expect(
        fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
      ).not.toHaveBeenCalled();
      expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
        { grantType: 'authorization_code', error: 'invalid_grant', reason: 'dpop_missing_proof' },
      ]);
    });

    it('refuses a replay naming a resource outside the code’s binding with invalid_grant, and revokes nothing (OAuth 2.1 draft-16 §7.5.3)', async () => {
      // An unspent code answers invalid_target here; a spent one invalid_grant.
      const { fastify, ctx } = setupSpentCode({ resource: ['https://api.example.com'] });
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(
        handler(baseRequest({ resource: ['https://other.example.com'] }), createReply())
      ).rejects.toThrow(InvalidGrantError);
      expect(
        fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
      ).not.toHaveBeenCalled();
      expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
        {
          grantType: 'authorization_code',
          error: 'invalid_grant',
          reason: 'resource_outside_binding',
        },
      ]);
    });

    it('a replay for a user disabled since is still a replay, and spends nothing', async () => {
      const { fastify, ctx, authCode } = setupSpentCode();
      (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
        id: 'user-uuid-1',
        enabled: false,
      });
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidGrantError);
      expect(
        fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
      ).toHaveBeenCalledWith(authCode.id, 'code_replay', expect.anything());
      expect(fastify.repositories.authorizationCodes.markUsed).not.toHaveBeenCalled();
    });

    it('a redemption that loses the race to a concurrent one is a replay: invalid_grant, family revoked', async () => {
      // Models the concurrent-redemption window: a code passes the lookup (it
      // was still unspent when read), but a parallel exchange spent it first,
      // so the atomic markUsed CAS (`WHERE used = false`) matches no row and
      // throws NotFoundError. No second token for the same code; the family
      // the winner started is revoked once the losing transaction is over.
      const { fastify, ctx, authCode } = setupAuthCodeStub();
      let transactions = 0;
      let open: number | undefined;
      (fastify.db.transaction as unknown as Mock).mockImplementation(
        async (cb: (tx: unknown) => Promise<unknown>) => {
          transactions += 1;
          open = transactions;
          try {
            return await cb({ tx: transactions });
          } finally {
            open = undefined;
          }
        }
      );
      (fastify.repositories.authorizationCodes.markUsed as unknown as Mock).mockRejectedValue(
        new NotFoundError('AuthorizationCode', 'authcode-uuid-1')
      );
      const revokedInTransaction: (number | undefined)[] = [];
      (
        fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode as unknown as Mock
      ).mockImplementation(async () => {
        revokedInTransaction.push(open);
        return { familyId: CODE_FAMILY_ID, revokedCount: 2 };
      });
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      // RFC 6749 §5.2 `invalid_grant` with the usual wording: not a 404
      // naming the row (#513).
      const refused = await handler(baseRequest(), createReply()).catch((error: unknown) => error);
      expect(refused).toBeInstanceOf(InvalidGrantError);
      expect(refused).toMatchObject({ errorDescription: 'Invalid or expired authorization code' });
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
      expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
      expect(
        fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
      ).toHaveBeenCalledWith(authCode.id, 'code_replay', { tx: 2 });
      // In a transaction of its own after the losing one, so the winner's
      // family is committed.
      expect(revokedInTransaction).toEqual([2]);
      expect(revokeGrantAccessTokensMock).toHaveBeenCalledWith(fastify, {
        authorizationCodeId: authCode.id,
        refreshFamilyId: CODE_FAMILY_ID,
      });
      expect(emittedData(TOKEN_ISSUED)).toEqual([]);
      expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
        {
          grantType: 'authorization_code',
          error: 'invalid_grant',
          reason: 'code_replay',
          refreshFamilyId: CODE_FAMILY_ID,
          revokedRefreshCount: 2,
        },
      ]);
    });

    it('a failure other than a lost compare-and-set is not a replay', async () => {
      const { fastify, ctx } = setupAuthCodeStub();
      (fastify.repositories.authorizationCodes.markUsed as unknown as Mock).mockRejectedValue(
        new Error('connection lost')
      );
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      await expect(handler(baseRequest(), createReply())).rejects.toThrow('connection lost');
      expect(
        fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
      ).not.toHaveBeenCalled();
    });
  });

  it('links the refresh token the exchange starts to the code', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({ authorizationCodeId: authCode.id }),
      expect.anything()
    );
  });

  // ADR-017 Decision 10: a second redemption revokes the access token too, so
  // it is recorded against the code and the family it starts, before the
  // redemption commits.
  it('records the access token against the code and the family it starts, inside the redemption', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    let open = false;
    (fastify.db.transaction as unknown as Mock).mockImplementation(
      async (cb: (tx: unknown) => Promise<unknown>) => {
        open = true;
        try {
          return await cb({ tx: 'redemption' });
        } finally {
          open = false;
        }
      }
    );
    const recordedInTransaction: boolean[] = [];
    recordGrantAccessTokenMock.mockImplementationOnce(async () => {
      recordedInTransaction.push(open);
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    const [family] = (fastify.repositories.refreshTokens.create as unknown as Mock).mock.calls[0];
    expect(recordGrantAccessTokenMock).toHaveBeenCalledWith(fastify, 'signed.jwt.token', {
      authorizationCodeId: authCode.id,
      refreshFamilyId: (family as { familyId: string }).familyId,
    });
    expect(recordedInTransaction).toEqual([true]);
  });

  it('records the access token against the code alone when no refresh family starts', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue(undefined);
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    expect(recordGrantAccessTokenMock).toHaveBeenCalledWith(fastify, 'signed.jwt.token', {
      authorizationCodeId: authCode.id,
      refreshFamilyId: null,
    });
  });

  // ADR-017 Decision 10: whether the parameter is needed depends on the code,
  // so a missing value is a mismatch (RFC 6749 §5.2 invalid_grant), not a
  // malformed request.
  it.each([
    ['without redirect_uri', { redirect_uri: undefined }],
    ['with an empty redirect_uri (RFC 6749 §3.2: treated as omitted)', { redirect_uri: '' }],
  ])(
    'answers a browser code presented %s with invalid_grant and leaves the code unspent',
    async (_label, body) => {
      const { fastify, ctx } = setupAuthCodeStub();
      await tokenRoute(fastify);
      const handler = ctx.handler;
      if (!handler) throw new Error('Handler missing');

      const refused = await handler(baseRequest(body), createReply()).catch(
        (error: unknown) => error
      );
      expect(refused).toBeInstanceOf(InvalidGrantError);
      // Says what to send: a client written for OAuth 2.1 alone leaves the
      // parameter out (the caller has already authenticated).
      expect(refused).toMatchObject({ errorDescription: 'redirect_uri is required for this code' });
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
      expect(fastify.repositories.authorizationCodes.markUsed).not.toHaveBeenCalled();
      expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
        { grantType: 'authorization_code', error: 'invalid_grant', reason: 'redirect_uri_missing' },
      ]);
    }
  );

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

    expect(fastify.repositories.authorizationCodes.markUsed).toHaveBeenCalledWith(
      authCode.id,
      expect.anything()
    );
    const markUsedOrder = (fastify.repositories.authorizationCodes.markUsed as unknown as Mock).mock
      .invocationCallOrder[0];
    const signOrder = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .invocationCallOrder[0];
    expect(markUsedOrder).toBeLessThan(signOrder);
  });

  it('spends the code and stores the refresh token in one transaction', async () => {
    // A logout or consent revocation landing between the two would find the
    // code already used and no refresh token to revoke yet (see the repository
    // integration test for the race). Both writes must carry the tx handle of
    // the same fastify.db.transaction call.
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    const tx = { tx: true };
    (fastify.db.transaction as unknown as Mock).mockImplementation(
      async (cb: (tx: unknown) => Promise<unknown>) => cb(tx)
    );
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(baseRequest(), createReply());

    expect(fastify.db.transaction).toHaveBeenCalledTimes(1);
    expect(fastify.repositories.authorizationCodes.markUsed).toHaveBeenCalledWith(authCode.id, tx);
    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(expect.anything(), tx);
    // The token.issued event commits with the redemption, or neither does.
    expect(emitUserEventMock).toHaveBeenCalledTimes(1);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_ISSUED,
      {
        grantType: 'authorization_code',
        scopes: ['read:foo'],
        audience: ['https://api.example.com'],
        expiresIn: 900,
        refreshFamilyId: expect.any(String),
      },
      expect.objectContaining({
        tx,
        realmId: 'realm-1',
        userId: 'user-uuid-1',
        clientId: 'test-client-1',
        actor: 'client',
      })
    );
  });

  it('signs inside the redemption transaction, before token.issued, so a signing failure records none', async () => {
    // token.issued records tokens that exist. Signed after the compare-and-set
    // and before the event, a token that cannot be signed rolls the redemption
    // back: the code stays unspent, and no token.issued commits.
    const { fastify, ctx } = setupAuthCodeStub();
    let open = false;
    (fastify.db.transaction as unknown as Mock).mockImplementation(
      async (cb: (tx: unknown) => Promise<unknown>) => {
        open = true;
        try {
          return await cb({ tx: true });
        } finally {
          open = false;
        }
      }
    );
    const signedInTransaction: boolean[] = [];
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockImplementation(async () => {
      signedInTransaction.push(open);
      throw new Error('signing failed');
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(baseRequest(), createReply())).rejects.toThrow();
    expect(signedInTransaction).toEqual([true]);
    expect(emittedData(TOKEN_ISSUED)).toEqual([]);
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

  // A refusal that burns the code and loses the compare-and-set to a
  // concurrent request finds the code burned already: the refusal stands as
  // it is, and nothing is revoked as a replay.
  it('answers invalid_grant for a disabled user when the code it burns was spent meanwhile', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-uuid-1',
      email: 'u@example.com',
      emailVerified: true,
      enabled: false,
    });
    (fastify.repositories.authorizationCodes.markUsed as unknown as Mock).mockRejectedValue(
      new NotFoundError('AuthorizationCode', 'authcode-uuid-1')
    );
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const refused = await handler(baseRequest(), createReply()).catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(InvalidGrantError);
    expect(refused).toMatchObject({ errorDescription: 'Invalid or expired authorization code' });
    expect(fastify.repositories.authorizationCodes.markUsed).toHaveBeenCalledWith(authCode.id);
    expect(
      fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
    ).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
      { grantType: 'authorization_code', error: 'invalid_grant', reason: 'user_disabled' },
    ]);
  });

  it("answers invalid_scope for the agent's cap when the code it burns was spent meanwhile", async () => {
    const { fastify, ctx, client, authCode } = setupAuthCodeStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...client,
      isAgent: true,
      maxAgentMode: 'readonly',
    });
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({ ...authCode, scopes: ['read:foo', 'agent:exec'] });
    (fastify.repositories.authorizationCodes.markUsed as unknown as Mock).mockRejectedValue(
      new NotFoundError('AuthorizationCode', 'authcode-uuid-1')
    );
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidScopeError);
    expect(fastify.repositories.authorizationCodes.markUsed).toHaveBeenCalledWith(authCode.id);
    expect(
      fastify.repositories.refreshTokens.revokeFamilyByAuthorizationCode
    ).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
      {
        grantType: 'authorization_code',
        error: 'invalid_scope',
        reason: 'scope_exceeds_agent_mode',
      },
    ]);
  });

  it('lets a failure other than a lost compare-and-set through when burning a code', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-uuid-1',
      enabled: false,
    });
    const lost = new Error('connection lost');
    (fastify.repositories.authorizationCodes.markUsed as unknown as Mock).mockRejectedValue(lost);
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(baseRequest(), createReply())).rejects.toBe(lost);
    // Only the catch-all's server_error is recorded, not the refusal's reason.
    expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
      { grantType: 'authorization_code', error: 'server_error' },
    ]);
  });

  // RFC 9700 §4.14: a user disabled between code issuance and redemption gets
  // no tokens — the same gate the refresh, exchange and jwt-bearer grants apply.
  it('rejects a code whose user has been disabled (invalid_grant, no tokens)', async () => {
    const { fastify, ctx, authCode } = setupAuthCodeStub();
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-uuid-1',
      email: 'u@example.com',
      emailVerified: true,
      enabled: false,
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidGrantError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    // The code is still burned, so the exchange cannot be retried.
    expect(fastify.repositories.authorizationCodes.markUsed).toHaveBeenCalledWith(authCode.id);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      { grantType: 'authorization_code', error: 'invalid_grant', reason: 'user_disabled' },
      expect.objectContaining({ userId: 'user-uuid-1', clientId: 'test-client-1' })
    );
  });

  // ADR-007 §2 (#184): the authorization_code grant enforces the agent's
  // CURRENT cap, like every other grant. A code approved under agent:exec must
  // not redeem into agent:exec after the operator lowers the cap.
  it("rejects a code whose agent scope exceeds the client's current max_agent_mode", async () => {
    const { fastify, ctx, client, authCode } = setupAuthCodeStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...client,
      isAgent: true,
      maxAgentMode: 'readonly',
    });
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
      ...authCode,
      scopes: ['read:foo', 'agent:exec'],
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(baseRequest(), createReply())).rejects.toThrow(InvalidScopeError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      {
        grantType: 'authorization_code',
        error: 'invalid_scope',
        reason: 'scope_exceeds_agent_mode',
      },
      expect.objectContaining({ userId: 'user-uuid-1' })
    );
    // The code is burned all the same: a client cannot narrow a code, so it
    // goes back through /oauth/authorize.
    expect(fastify.repositories.authorizationCodes.markUsed).toHaveBeenCalledWith(authCode.id);
  });

  it('rejects with invalid_grant, as for a disabled user, when the user bound to the code cannot be found', async () => {
    const { fastify, ctx } = setupAuthCodeStub();
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue(null);
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    // The answer does not tell a deleted account from a disabled one (#513);
    // the event's reason does.
    await expect(handler(baseRequest(), reply)).rejects.toBeInstanceOf(InvalidGrantError);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:token.request_failed:v1-rc.0',
      expect.objectContaining({ error: 'invalid_grant', reason: 'user_not_found' }),
      expect.anything()
    );
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
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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
    (
      fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
    ).mockResolvedValue({
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

  describe('a QAuth API audience (#509)', () => {
    const ACCOUNT_AUDIENCE = 'urn:qauth:aud:account:v1-rc.0';

    it('is refused with invalid_target when the code binds one the client does not list', async () => {
      const { fastify, ctx, authCode } = setupAuthCodeStub();
      (
        fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
      ).mockResolvedValue({
        ...authCode,
        resource: [ACCOUNT_AUDIENCE],
      });
      await tokenRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');

      await expect(ctx.handler(baseRequest(), createReply())).rejects.toThrow(InvalidTargetError);
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
      expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
      // Not spent, like a `resource` outside the binding: the client may redeem
      // the code again with a `resource` that names no such audience.
      expect(fastify.repositories.authorizationCodes.markUsed).not.toHaveBeenCalled();
    });

    it('is the token audience when the client lists it', async () => {
      const { fastify, ctx, client, authCode } = setupAuthCodeStub();
      client.audience = ['https://api.example.com', ACCOUNT_AUDIENCE];
      (
        fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
      ).mockResolvedValue({
        ...authCode,
        resource: [ACCOUNT_AUDIENCE],
      });
      await tokenRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');

      await ctx.handler(baseRequest(), createReply());
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ aud: ACCOUNT_AUDIENCE })
      );
    });

    // #509: a family audience reaches a user's token only when a `resource`
    // named it, so the consent the user gave covers it.
    it("is left out of the client's default audience when the code binds no resource", async () => {
      const { fastify, ctx, client } = setupAuthCodeStub();
      client.audience = ['https://api.example.com', ACCOUNT_AUDIENCE];
      await tokenRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');

      await ctx.handler(baseRequest(), createReply());
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ aud: 'https://api.example.com' })
      );
    });

    it('falls back to the client id when the family audience is all the client lists', async () => {
      const { fastify, ctx, client } = setupAuthCodeStub();
      client.audience = [ACCOUNT_AUDIENCE];
      await tokenRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');

      await ctx.handler(baseRequest(), createReply());
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ aud: client.clientId })
      );
    });

    it('is matched exactly: another spelling of a listed audience is still refused', async () => {
      const { fastify, ctx, client, authCode } = setupAuthCodeStub();
      client.audience = [ACCOUNT_AUDIENCE];
      (
        fastify.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
      ).mockResolvedValue({
        ...authCode,
        resource: ['URN:qauth:aud:account:v1-rc.0'],
      });
      await tokenRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');

      await expect(ctx.handler(baseRequest(), createReply())).rejects.toThrow(InvalidTargetError);
    });
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
  /** A refresh family id: a UUID, as the store makes it and the event carries it. */
  const REFRESH_FAMILY_ID = '0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b';

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
      familyId: REFRESH_FAMILY_ID,
      familyCreatedAt: Date.now() - 30 * 60_000,
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

  it('answers invalid_grant, not a 404, when the refresh token of a disabled user was revoked meanwhile', async () => {
    // The revocation is a compare-and-set: a concurrent request that revoked
    // the token first leaves no active row, and the repository says
    // NotFoundError. The token is unusable either way (RFC 6749 §5.2).
    const { fastify, ctx, confidentialClient, storedToken, user } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(storedToken);
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      ...user,
      enabled: false,
    });
    (fastify.repositories.refreshTokens.revoke as unknown as Mock).mockRejectedValue(
      new NotFoundError('RefreshToken', storedToken.id)
    );
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const refused = await handler(refreshRequest(), createReply()).catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(InvalidGrantError);
    expect(refused).toMatchObject({ errorDescription: 'Invalid or expired refresh token' });
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    // The token is burned already; the refusal and its reason stand.
    expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
      { grantType: 'refresh_token', error: 'invalid_grant', reason: 'user_disabled' },
    ]);
  });

  it('records the rotated access token against the family, inside the rotation', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(storedToken);
    let open = false;
    (fastify.db.transaction as unknown as Mock).mockImplementation(
      async (cb: (tx: unknown) => Promise<unknown>) => {
        open = true;
        try {
          return await cb({ tx: 'rotation' });
        } finally {
          open = false;
        }
      }
    );
    const recordedInTransaction: boolean[] = [];
    recordGrantAccessTokenMock.mockImplementationOnce(async () => {
      recordedInTransaction.push(open);
    });
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockResolvedValue('rotated.jwt.token');
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(refreshRequest(), createReply());

    expect(recordGrantAccessTokenMock).toHaveBeenCalledWith(fastify, 'rotated.jwt.token', {
      refreshFamilyId: storedToken.familyId,
    });
    expect(recordedInTransaction).toEqual([true]);
  });

  it('signs inside the rotation transaction, before token.issued, so a signing failure records none', async () => {
    // As for a code: a token that cannot be signed rolls the rotation back,
    // so the presented refresh token stays live and no token.issued commits.
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(storedToken);
    let open = false;
    (fastify.db.transaction as unknown as Mock).mockImplementation(
      async (cb: (tx: unknown) => Promise<unknown>) => {
        open = true;
        try {
          return await cb({ tx: 'rotation' });
        } finally {
          open = false;
        }
      }
    );
    const signedInTransaction: boolean[] = [];
    (fastify.jwtUtils.signAccessToken as unknown as Mock).mockImplementation(async () => {
      signedInTransaction.push(open);
      throw new Error('signing failed');
    });
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(refreshRequest(), createReply())).rejects.toThrow();
    expect(signedInTransaction).toEqual([true]);
    expect(emittedData(TOKEN_ISSUED)).toEqual([]);
  });

  it('rotates the token and returns new access+refresh for a confidential client', async () => {
    const { fastify, ctx, confidentialClient, storedToken, user } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(storedToken);
    const tx = { tx: 'rotation' };
    (fastify.db.transaction as unknown as Mock).mockImplementation(
      async (cb: (tx: unknown) => Promise<unknown>) => cb(tx)
    );

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    const result = await handler(refreshRequest(), reply);

    // Old token revoked as 'rotated' BEFORE new token persisted, through the
    // compare-and-set. Third arg is the tx handle propagated from
    // fastify.db.transaction.
    expect(fastify.repositories.refreshTokens.revokeIfActive).toHaveBeenCalledWith(
      storedToken.id,
      'rotated',
      expect.anything()
    );
    // New token inherits the same family_id and the family's start (#552).
    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: user.id,
        oauthClientId: confidentialClient.id,
        tokenHash: 'new-refresh-token-hash',
        familyId: storedToken.familyId,
        familyCreatedAt: storedToken.familyCreatedAt,
        previousTokenHash: `hash:${REFRESH_TOKEN_HEX}`,
        scopes: ['read:foo', 'write:foo'],
      }),
      expect.anything()
    );
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        scope: 'read:foo write:foo',
        aud: 'https://api.example.com',
      })
    );
    // ANT-2026-2O0T72HY: no `email` scope in the refreshed grant, so no email
    // claim, although the user has a verified address.
    const accessClaims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect('email' in accessClaims).toBe(false);
    expect('email_verified' in accessClaims).toBe(false);
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      access_token: 'new.access.jwt',
      refresh_token: 'new-refresh-token',
      token_type: 'Bearer',
      scope: 'read:foo write:foo',
    });
    // The token.issued event commits with the rotation, in its transaction,
    // and names the family, never a token.
    expect(emitUserEventMock).toHaveBeenCalledTimes(1);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_ISSUED,
      {
        grantType: 'refresh_token',
        scopes: ['read:foo', 'write:foo'],
        audience: ['https://api.example.com'],
        expiresIn: 900,
        refreshFamilyId: REFRESH_FAMILY_ID,
      },
      expect.objectContaining({
        tx,
        realmId: 'realm-1',
        userId: user.id,
        clientId: confidentialClient.clientId,
        actor: 'client',
      })
    );
  });

  it('carries the email claims on rotation only under the email scope (ANT-2026-2O0T72HY)', async () => {
    const { fastify, ctx, confidentialClient, storedToken, user } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...confidentialClient,
      scopes: [...confidentialClient.scopes, 'email'],
    });
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, scopes: ['read:foo', 'email'] });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(refreshRequest(), createReply());

    // #229: the emitted email is the ATTRIBUTE value, not the users row's.
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: user.id,
        email: 'rt-attr@example.com',
        email_verified: true,
        scope: 'read:foo email',
      })
    );
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).toHaveBeenCalledWith(
      user.id,
      'email'
    );
  });

  it('drops the email claims when the refresh narrows `email` out of the scope (ANT-2026-2O0T72HY)', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...confidentialClient,
      scopes: [...confidentialClient.scopes, 'email'],
    });
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, scopes: ['read:foo', 'email'] });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(refreshRequest({ scope: 'read:foo' }), createReply());

    const accessClaims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect(accessClaims['scope']).toBe('read:foo');
    expect('email' in accessClaims).toBe(false);
    expect('email_verified' in accessClaims).toBe(false);
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

    // Family-wide revocation triggered with the correct family_id + reason,
    // in the transaction of the event that records it (ADR-019 Decision 8).
    const [[, , tx]] = (fastify.repositories.refreshTokens.revokeFamily as unknown as Mock).mock
      .calls;
    expect(tx).toBeDefined();
    expect(fastify.repositories.refreshTokens.revokeFamily).toHaveBeenCalledWith(
      storedToken.familyId,
      'replay_detected',
      tx
    );
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      {
        grantType: 'refresh_token',
        error: 'invalid_grant',
        reason: 'refresh_replay',
        refreshFamilyId: storedToken.familyId,
        revokedRefreshCount: 3,
      },
      expect.objectContaining({ tx })
    );
    // Every access token issued in the family goes on the denylist too.
    expect(revokeGrantAccessTokensMock).toHaveBeenCalledWith(fastify, {
      refreshFamilyId: storedToken.familyId,
    });
    // Replay path must NOT mint a new token.
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
  });

  // Two concurrent presentations of one live token both pass the snapshot
  // liveness check; only one can win the compare-and-set. The loser must not
  // mint a second child in the family — it is a replay, so the family goes.
  it('treats losing the rotation compare-and-set as replay: no token, family revoked', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(storedToken); // live on read …
    (fastify.repositories.refreshTokens.revokeIfActive as unknown as Mock).mockResolvedValue(
      undefined // … but a concurrent request rotated it first
    );
    (fastify.repositories.refreshTokens.revokeFamily as unknown as Mock).mockResolvedValue(2);

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    const reply = createReply();
    await expect(handler(refreshRequest(), reply)).rejects.toThrow(InvalidGrantError);

    expect(fastify.repositories.refreshTokens.revokeIfActive).toHaveBeenCalledWith(
      storedToken.id,
      'rotated',
      expect.anything()
    );
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.revokeFamily).toHaveBeenCalledWith(
      storedToken.familyId,
      'replay_detected',
      expect.anything()
    );
    // The lost race is the replay it is: no token.issued, one refusal.
    expect(emittedData(TOKEN_ISSUED)).toEqual([]);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      {
        grantType: 'refresh_token',
        error: 'invalid_grant',
        reason: 'refresh_replay',
        refreshFamilyId: storedToken.familyId,
        revokedRefreshCount: 2,
      },
      expect.objectContaining({ userId: storedToken.userId, clientId: 'confidential-client' })
    );
    expect(revokeGrantAccessTokensMock).toHaveBeenCalledWith(fastify, {
      refreshFamilyId: storedToken.familyId,
    });
  });

  describe("the realm's sso_max_lifespan caps the family (ADR-019 Decision 3, #552)", () => {
    const MINUTE = 60_000;
    /** A realm whose families live at most one hour. */
    const CAPPED_REALM = testRealm({ id: 'realm-1', ssoMaxLifespan: 3600 });

    /** The refresh stub, with the presented token's family started `ageMs` ago. */
    function setupFamily(ageMs: number, overrides: Record<string, unknown> = {}) {
      const setup = setupRefreshStub();
      const storedToken = {
        ...setup.storedToken,
        familyCreatedAt: Date.now() - ageMs,
        ...overrides,
      };
      (setup.fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        setup.confidentialClient
      );
      (
        setup.fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
      ).mockResolvedValue(storedToken);
      return { ...setup, storedToken };
    }

    async function refreshIn(
      setup: ReturnType<typeof setupFamily>,
      realm: ReturnType<typeof testRealm>
    ): Promise<unknown> {
      await tokenRoute(setup.fastify);
      if (!setup.ctx.handler) throw new Error('Handler missing');
      return setup.ctx.handler({ ...refreshRequest(), realm }, createReply());
    }

    it('copies the session end on rotation, and ends the family with the session', async () => {
      // The family started five minutes ago, one minute before its session
      // was due to end: the session's end, not start plus one hour, caps it.
      const sessionEnd = Date.now() + 1 * MINUTE;
      const setup = setupFamily(5 * MINUTE, { familySessionExpiresAt: sessionEnd });

      await expect(refreshIn(setup, CAPPED_REALM)).resolves.toMatchObject({
        refresh_token: 'new-refresh-token',
      });
      const created = (setup.fastify.repositories.refreshTokens.create as unknown as Mock).mock
        .calls[0][0] as { familySessionExpiresAt: number | null; expiresAt: number };
      expect(created.familySessionExpiresAt).toBe(sessionEnd);
      expect(created.expiresAt).toBe(sessionEnd);
    });

    it('refuses once the session that started the family has ended', async () => {
      const setup = setupFamily(5 * MINUTE, { familySessionExpiresAt: Date.now() - 1 });

      await expect(refreshIn(setup, CAPPED_REALM)).rejects.toThrow(InvalidGrantError);
      expect(setup.fastify.repositories.refreshTokens.revokeFamily).toHaveBeenCalledWith(
        setup.storedToken.familyId,
        'family_expired'
      );
      expect(setup.fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    });

    it('rotates before the end, and the new token expires no later than the end', async () => {
      const setup = setupFamily(59 * MINUTE);
      const before = Date.now();

      await expect(refreshIn(setup, CAPPED_REALM)).resolves.toMatchObject({
        refresh_token: 'new-refresh-token',
      });

      const created = (setup.fastify.repositories.refreshTokens.create as unknown as Mock).mock
        .calls[0][0] as { familyCreatedAt: number; expiresAt: number };
      const familyEnd = setup.storedToken.familyCreatedAt + 60 * MINUTE;
      expect(created.familyCreatedAt).toBe(setup.storedToken.familyCreatedAt);
      expect(created.expiresAt).toBe(familyEnd);
      expect(created.expiresAt).toBeLessThan(before + 2 * MINUTE);
      expect(setup.fastify.repositories.refreshTokens.revokeFamily).not.toHaveBeenCalled();
    });

    it('refuses past the end with invalid_grant and revokes the whole family', async () => {
      // The token was capped at the family's end, a minute ago, so it has
      // expired too: the family's end is what answers, and it takes the family.
      const setup = setupFamily(61 * MINUTE, { expiresAt: Date.now() - MINUTE });

      await expect(refreshIn(setup, CAPPED_REALM)).rejects.toThrow(InvalidGrantError);

      expect(setup.fastify.repositories.refreshTokens.revokeFamily).toHaveBeenCalledWith(
        REFRESH_FAMILY_ID,
        'family_expired'
      );
      // Nothing is rotated or minted.
      expect(setup.fastify.repositories.refreshTokens.revokeIfActive).not.toHaveBeenCalled();
      expect(setup.fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
      expect(setup.fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
      expect(emittedData(TOKEN_ISSUED)).toEqual([]);
      expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
        { grantType: 'refresh_token', error: 'invalid_grant', reason: 'refresh_family_expired' },
      ]);
    });

    it('ends a family whose token outlives a lowered limit, at its next use', async () => {
      // Issued while the realm set no limit: the token itself is good for
      // another week, but the family started two hours ago.
      const setup = setupFamily(120 * MINUTE, { expiresAt: Date.now() + 7 * 24 * 60 * MINUTE });

      await expect(refreshIn(setup, CAPPED_REALM)).rejects.toThrow(InvalidGrantError);

      expect(setup.fastify.repositories.refreshTokens.revokeFamily).toHaveBeenCalledWith(
        REFRESH_FAMILY_ID,
        'family_expired'
      );
      expect(setup.fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    });

    it('slides as before when the realm sets no sso_max_lifespan', async () => {
      const setup = setupFamily(365 * 24 * 60 * MINUTE);
      const before = Date.now();

      await expect(refreshIn(setup, REALM)).resolves.toMatchObject({
        refresh_token: 'new-refresh-token',
      });

      const created = (setup.fastify.repositories.refreshTokens.create as unknown as Mock).mock
        .calls[0][0] as { familyCreatedAt: number; expiresAt: number };
      expect(created.familyCreatedAt).toBe(setup.storedToken.familyCreatedAt);
      expect(created.expiresAt).toBeGreaterThanOrEqual(before + 604_800_000);
      expect(created.expiresAt).toBeLessThanOrEqual(Date.now() + 604_800_000);
      expect(setup.fastify.repositories.refreshTokens.revokeFamily).not.toHaveBeenCalled();
    });

    // RFC 9700 §4.14.2: the cap must not stand in the way of replay detection.
    it.each([
      ['before the end', 30 * MINUTE],
      ['after the end', 61 * MINUTE],
    ])('still revokes the whole family on replay of an old token %s', async (_label, ageMs) => {
      const setup = setupFamily(ageMs, { revoked: true });

      await expect(refreshIn(setup, CAPPED_REALM)).rejects.toThrow(InvalidGrantError);

      expect(setup.fastify.repositories.refreshTokens.revokeFamily).toHaveBeenCalledTimes(1);
      expect(setup.fastify.repositories.refreshTokens.revokeFamily).toHaveBeenCalledWith(
        REFRESH_FAMILY_ID,
        'replay_detected',
        expect.anything()
      );
      expect(setup.fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
      expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
        {
          grantType: 'refresh_token',
          error: 'invalid_grant',
          reason: 'refresh_replay',
          refreshFamilyId: REFRESH_FAMILY_ID,
          revokedRefreshCount: 0,
        },
      ]);
    });

    it('never lets a party without the DPoP key revoke a bound family past its end', async () => {
      // RFC 9449 §5: a public client's refresh token bound to its key. Whoever
      // holds a copy but not the key is refused before the family's end is
      // looked at, so cannot end the family for the client.
      const setup = setupFamily(61 * MINUTE, { cnfJkt: 'k'.repeat(43) });
      Object.assign(setup.fastify, { dpop: { verifyRequest: vi.fn() } });

      await expect(refreshIn(setup, CAPPED_REALM)).rejects.toThrow();

      expect(setup.fastify.repositories.refreshTokens.revokeFamily).not.toHaveBeenCalled();
      expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
        { grantType: 'refresh_token', error: 'invalid_dpop_proof', reason: 'dpop_missing_proof' },
      ]);
    });

    it("never lets another client's presentation revoke the family", async () => {
      const setup = setupFamily(61 * MINUTE, { oauthClientId: 'someone-else' });

      await expect(refreshIn(setup, CAPPED_REALM)).rejects.toThrow(InvalidGrantError);

      expect(setup.fastify.repositories.refreshTokens.revokeFamily).not.toHaveBeenCalled();
    });
  });

  // ADR-007 §2 (#184): the refresh grant enforces the agent's CURRENT cap,
  // like every other grant. A token issued under agent:exec must not keep
  // refreshing into agent:exec after the operator lowers the cap.
  it("rejects refreshing into an agent scope above the client's current max_agent_mode", async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...confidentialClient,
      isAgent: true,
      maxAgentMode: 'readonly',
    });
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, scopes: ['read:foo', 'agent:exec'] });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(refreshRequest(), createReply())).rejects.toThrow(InvalidScopeError);
    // Rejected before rotation: the presented token is neither revoked nor replaced.
    expect(fastify.repositories.refreshTokens.revokeIfActive).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.revoke).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      {
        grantType: 'refresh_token',
        error: 'invalid_scope',
        reason: 'scope_not_allowed_for_client',
      },
      expect.objectContaining({ userId: 'user-uuid-rt' })
    );
  });

  // The allowlist is a ceiling on every grant, not only on the ones that start
  // one. A scope taken off `oauth_clients.scopes` after the user approved it
  // must not keep being refreshed.
  it("rejects refreshing into a scope that has left the client's allowlist", async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...confidentialClient,
      scopes: ['read:foo'],
    });
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, scopes: ['read:foo', 'write:foo'] });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(handler(refreshRequest(), createReply())).rejects.toThrow(InvalidScopeError);
    // Rejected before rotation: the presented token is neither revoked nor replaced.
    expect(fastify.repositories.refreshTokens.revokeIfActive).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.revoke).not.toHaveBeenCalled();
    expect(fastify.repositories.refreshTokens.create).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      {
        grantType: 'refresh_token',
        error: 'invalid_scope',
        reason: 'scope_not_allowed_for_client',
      },
      expect.objectContaining({ userId: 'user-uuid-rt' })
    );
  });

  it('lets a client keep refreshing within its current allowlist by narrowing scope', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...confidentialClient,
      scopes: ['read:foo'],
    });
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, scopes: ['read:foo', 'write:foo'] });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(
      handler(refreshRequest({ scope: 'read:foo' }), createReply())
    ).resolves.toBeDefined();
    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({ scopes: ['read:foo'] }),
      expect.anything()
    );
  });

  it('lets a capped agent keep refreshing within its current mode by narrowing scope', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...confidentialClient,
      isAgent: true,
      maxAgentMode: 'readonly',
    });
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, scopes: ['read:foo', 'agent:exec'] });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await expect(
      handler(refreshRequest({ scope: 'read:foo' }), createReply())
    ).resolves.toBeDefined();
    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({ scopes: ['read:foo'] }),
      expect.anything()
    );
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
    expect(fastify.repositories.refreshTokens.revokeIfActive).not.toHaveBeenCalled();
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

  it('refuses a QAuth API audience the client no longer lists, before rotating (#509)', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, resource: ['urn:qauth:aud:developer:v1-rc.0'] });

    await tokenRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    await expect(ctx.handler(refreshRequest(), createReply())).rejects.toThrow(InvalidTargetError);
    expect(fastify.repositories.refreshTokens.revokeIfActive).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('leaves a listed QAuth API audience out of the default when the family binds no resource (#509)', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...confidentialClient,
      audience: ['urn:qauth:aud:account:v1-rc.0', 'https://api.example.com'],
    });
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue(storedToken);

    await tokenRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    await ctx.handler(refreshRequest(), createReply());
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ aud: 'https://api.example.com' })
    );
  });

  it('issues a listed QAuth API audience the family binds (#509)', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...confidentialClient,
      audience: ['urn:qauth:aud:account:v1-rc.0'],
    });
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, resource: ['urn:qauth:aud:account:v1-rc.0'] });

    await tokenRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    await ctx.handler(refreshRequest(), createReply());
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ aud: 'urn:qauth:aud:account:v1-rc.0' })
    );
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

  it('stores a repeated scope ONCE on the rotated token', async () => {
    // A refresh with `scope` = 174,000 × `email` used to be stored as sent on
    // the rotated token, and the next refresh's up-scoping check scanned that
    // list once per requested scope: one 1 MiB request then held the event
    // loop for ~78 s. Token exchange already de-duplicates at the same point.
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
    const result = await handler(
      refreshRequest({ scope: 'read:foo read:foo  read:foo\tread:foo' }),
      reply
    );

    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({ scopes: ['read:foo'] }),
      expect.anything()
    );
    expect(result).toMatchObject({ scope: 'read:foo' });
  });

  it('de-duplicates a stored scope list that already holds repeats when carrying it forward', async () => {
    const { fastify, ctx, confidentialClient, storedToken } = setupRefreshStub();
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      confidentialClient
    );
    (
      fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked as unknown as Mock
    ).mockResolvedValue({ ...storedToken, scopes: ['read:foo', 'read:foo', 'read:foo'] });

    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    await handler(refreshRequest(), createReply());

    expect(fastify.repositories.refreshTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({ scopes: ['read:foo'] }),
      expect.anything()
    );
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
    expect(fastify.repositories.refreshTokens.revokeIfActive).not.toHaveBeenCalled();
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
    expect(fastify.repositories.refreshTokens.revokeIfActive).not.toHaveBeenCalled();
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

  // GATE 3a — a subject or actor token that was revoked through /oauth/revoke
  // (RFC 7009 jti denylist) must not be exchangeable for a fresh delegated
  // token with a new, non-revoked jti.
  it('rejects a subject_token whose jti is on the revocation denylist', async () => {
    const { fastify, ctx, subjectPayload } = setupExchangeStub();
    (subjectPayload as { jti?: string }).jti = 'revoked-subject-jti';
    await fastify.redis.set('revoked-access-token:revoked-subject-jti', '1');

    await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toThrow(InvalidRequestError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      { grantType: GRANT, error: 'invalid_request', reason: 'subject_token_revoked' },
      expect.objectContaining({ clientId: AGENT_CLIENT_ID, actor: 'client' })
    );
  });

  it('rejects an actor_token whose jti is on the revocation denylist', async () => {
    const { fastify, ctx, subjectPayload } = setupExchangeStub();
    const actorPayload = { ...subjectPayload, jti: 'revoked-actor-jti' };
    (fastify.jwtUtils.verifyAccessToken as unknown as Mock).mockImplementation((token: string) =>
      Promise.resolve(token === 'actor.jwt.token' ? actorPayload : subjectPayload)
    );
    await fastify.redis.set('revoked-access-token:revoked-actor-jti', '1');

    await expect(
      invoke(
        fastify,
        ctx,
        exchangeRequest({ actor_token: 'actor.jwt.token', actor_token_type: ACCESS_TOKEN_TYPE })
      )
    ).rejects.toThrow(InvalidRequestError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('fails the exchange closed when the revocation denylist cannot be read', async () => {
    const { fastify, ctx, subjectPayload } = setupExchangeStub();
    (subjectPayload as { jti?: string }).jti = 'some-jti';
    const redisDown = new Error('redis down');
    (fastify.redis.exists as unknown as Mock).mockRejectedValueOnce(redisDown);

    // The store's own failure propagates, to be answered as a server error.
    await expect(invoke(fastify, ctx, exchangeRequest())).rejects.toBe(redisDown);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    // The catch-all records the OAuth code the error stands for, never its message.
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      { grantType: GRANT, error: 'server_error' },
      expect.objectContaining({ realmId: 'realm-1', clientId: AGENT_CLIENT_ID, actor: 'client' })
    );
  });

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
    // ANT-2026-2O0T72HY: the delegated scope has no `email`, so the agent gets
    // no email claim although the user has a verified address.
    const claims = (fastify.jwtUtils.signAccessToken as unknown as Mock).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect('email' in claims).toBe(false);
    expect('email_verified' in claims).toBe(false);
    expect(result).toMatchObject({
      access_token: 'delegated.jwt',
      issued_token_type: ACCESS_TOKEN_TYPE,
      token_type: 'Bearer',
      scope: 'read:docs write:docs',
    });
    // RFC 8693: no refresh token issued on delegation.
    expect(result).not.toHaveProperty('refresh_token');
  });

  it('carries the email claims on the delegated token only under the email scope (ANT-2026-2O0T72HY)', async () => {
    const { fastify, ctx } = setupExchangeStub({
      subjectAud: ['https://api.example.com', AGENT_CLIENT_ID],
      subjectScope: 'read:docs email',
    });

    await invoke(fastify, ctx, exchangeRequest());

    // #229 sourcing-decisive: the default attribute fixture resolves
    // user@example.com while the subject users row carries
    // subject@example.com — a users-row revert emits the wrong value.
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'user@example.com',
        email_verified: true,
        scope: 'read:docs email',
      })
    );

    // Narrowing `email` out of the delegated scope drops the claims again.
    const narrowed = setupExchangeStub({
      subjectAud: ['https://api.example.com', AGENT_CLIENT_ID],
      subjectScope: 'read:docs email',
    });
    await invoke(narrowed.fastify, narrowed.ctx, exchangeRequest({ scope: 'read:docs' }));
    const claims = (narrowed.fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect('email' in claims).toBe(false);
    expect('email_verified' in claims).toBe(false);
  });

  it('omits BOTH email claims from the delegated token when no verified attribute exists — BREAKING #229', async () => {
    const { fastify, ctx } = setupExchangeStub({
      subjectAud: ['https://api.example.com', AGENT_CLIENT_ID],
      // The `email` scope is granted, so only the missing attribute explains it.
      subjectScope: 'read:docs email',
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

  it('per-agent audit (#186): the event carries actor + subject + act chain + scope mode', async () => {
    // Agent capped at exec, subject token grants agent:exec; on-behalf-of of the
    // end-user with a prior actor already in the chain.
    const { fastify, ctx, client, user } = setupExchangeStub({
      maxAgentMode: 'exec',
      subjectScope: 'read:docs agent:exec',
      subjectAct: { sub: 'prior-agent' },
    });

    await invoke(fastify, ctx, exchangeRequest());

    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_ISSUED,
      expect.objectContaining({
        grantType: GRANT,
        scopes: ['read:docs', 'agent:exec'],
        issuedTokenType: ACCESS_TOKEN_TYPE,
        delegationDepth: 2,
        // Highest agent scope mode present in the granted set.
        scopeMode: 'exec',
      }),
      expect.objectContaining({
        // Subject = the end-user the agent acted on behalf of.
        userId: user.id,
        clientId: client.clientId,
        // The minted token's RFC 8693 `act` claim.
        act: { sub: client.clientId, act: { sub: 'prior-agent' } },
      })
    );
    // Actor = the authenticated agent, with the flattened `act` chain:
    // outermost (this agent) first.
    const call = emitUserEventMock.mock.calls.find(([, type]) => type === TOKEN_ISSUED);
    if (!call) throw new Error('no token.issued event');
    expect(userEventFor(call[0], call[1], call[2], call[3] ?? {}, 'realm-1').actor).toEqual({
      type: 'client',
      id: client.clientId,
      delegationChain: [client.clientId, 'prior-agent'],
    });
  });

  it('per-agent audit (#186): never records token/secret material in its event', async () => {
    const { fastify, ctx } = setupExchangeStub({ subjectScope: 'read:docs' });

    await invoke(fastify, ctx, exchangeRequest({ client_secret: 'super-secret' }));

    const successCall = emitUserEventMock.mock.calls.find(([, type]) => type === TOKEN_ISSUED);
    expect(successCall).toBeDefined();
    const serialized = JSON.stringify(successCall?.slice(2));
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

  describe('a QAuth API audience (#509)', () => {
    const ACCOUNT_AUDIENCE = 'urn:qauth:aud:account:v1-rc.0';

    it('is not passed on to an agent that does not list it', async () => {
      const { fastify, ctx } = setupExchangeStub({ subjectAud: ACCOUNT_AUDIENCE });
      for (const request of [
        exchangeRequest({ audience: [ACCOUNT_AUDIENCE] }),
        // Kept verbatim from the subject token when the request names none.
        exchangeRequest(),
      ]) {
        await expect(invoke(fastify, ctx, request)).rejects.toThrow(InvalidTargetError);
      }
      expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    });

    it('is passed on to an agent that lists it', async () => {
      const { fastify, ctx, client } = setupExchangeStub({ subjectAud: ACCOUNT_AUDIENCE });
      client.audience = [ACCOUNT_AUDIENCE] as never;
      await invoke(fastify, ctx, exchangeRequest({ audience: [ACCOUNT_AUDIENCE] }));
      expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ aud: ACCOUNT_AUDIENCE })
      );
    });
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

  it("rejects the agent's own client_credentials token as subject_token without a user lookup (#754)", async () => {
    const { fastify, ctx, subjectPayload } = setupExchangeStub();
    // What `handleClientCredentials` mints with no `resource` and no client
    // audience: `sub` and `aud` are the agent's own client_id, so GATE 3c binds.
    Object.assign(subjectPayload, {
      sub: AGENT_CLIENT_ID,
      clientId: AGENT_CLIENT_ID,
      aud: AGENT_CLIENT_ID,
    });

    const refusal = invoke(fastify, ctx, exchangeRequest());
    await expect(refusal).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(refusal).rejects.toMatchObject({ message: 'invalid_request' });

    expect(fastify.repositories.users.findById).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      { grantType: GRANT, error: 'invalid_request', reason: 'subject_not_a_user' },
      expect.objectContaining({ userId: null })
    );
  });

  it('accepts and verifies an actor_token; the event names the agent as the actor', async () => {
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
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_ISSUED,
      expect.objectContaining({ grantType: GRANT, delegationDepth: 1 }),
      expect.objectContaining({ act: { sub: 'agent-client' } })
    );
    // The actor token's self-declared subject is not recorded: the actor is
    // the authenticated agent.
    expect(JSON.stringify(emitUserEventMock.mock.calls.map((call) => call.slice(2)))).not.toContain(
      'actor-service'
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

  egressGet.mockImplementation(async (_fastify: unknown, url: string) => {
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
   * server among its operator-set ID-JAG targets (#434) and a linked enterprise
   * subject. Every ID-JAG deny-path test starts from this and removes one thing.
   * Its `audience` is empty by default, so the happy path proves the targets
   * alone suffice.
   */
  function setupConsumeStub(
    opts: {
      grantTypes?: string[];
      audience?: string[] | null;
      idJagTargets?: string[];
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
      audience: opts.audience === undefined ? null : opts.audience,
      idJagTargets: opts.idJagTargets === undefined ? [MCP_SERVER] : opts.idJagTargets,
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

  it('carries the email claims only under the email scope (ANT-2026-2O0T72HY)', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const verifiedEmail = [
      {
        id: 'attr-ema',
        userId: 'user-uuid-enterprise',
        source: 'self_reported',
        attrKey: 'email',
        attrValue: 'enterprise@example.com',
        verified: true,
        expiresAt: null,
        createdAt: 1,
        updatedAt: 1,
      },
    ];

    // The assertion grants no `email`: the user has a verified address, and
    // the access token carries none of it.
    const without = setupConsumeStub();
    (
      without.fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue(verifiedEmail);
    await invoke(
      without.fastify,
      without.ctx,
      bearerRequest(await signIdJag(idpKey, { scope: 'chat.read' }))
    );
    const claims = (without.fastify.jwtUtils.signAccessToken as unknown as Mock).mock
      .calls[0][0] as Record<string, unknown>;
    expect('email' in claims).toBe(false);
    expect('email_verified' in claims).toBe(false);

    // Granted by the assertion and allowed by the client: released.
    const withEmail = setupConsumeStub({ scopes: ['chat.read', 'email'] });
    (
      withEmail.fastify.repositories.userAttributes.findVerifiedByUserIdAndKey as unknown as Mock
    ).mockResolvedValue(verifiedEmail);
    await invoke(
      withEmail.fastify,
      withEmail.ctx,
      bearerRequest(await signIdJag(idpKey, { scope: 'chat.read email' }))
    );
    expect(withEmail.fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'enterprise@example.com',
        email_verified: true,
        scope: 'chat.read email',
      })
    );
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
    ).rejects.toBeInstanceOf(UnsupportedGrantTypeError);
    // Refused BEFORE client authentication, so nothing was looked up.
    expect(fastify.repositories.oauthClients.findByClientId).not.toHaveBeenCalled();
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    // No client is authenticated yet, so the event names none.
    expect(emitUserEventMock).toHaveBeenCalledTimes(1);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      { grantType: JWT_BEARER_GRANT, error: 'unsupported_grant_type', reason: 'id_jag_disabled' },
      { actor: 'client' }
    );
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
    expect(egressGet).not.toHaveBeenCalled();
  });

  it('rejects an issuer that is not on the allowlist, without fetching anything', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub();

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey, { iss: 'https://evil.example' })))
    ).rejects.toBeInstanceOf(InvalidGrantError);
    expect(egressGet).not.toHaveBeenCalled();
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
    expect(egressGet).not.toHaveBeenCalled();
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
    expect(egressGet).not.toHaveBeenCalled();
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
    expect(emittedData(TOKEN_ISSUED)).toHaveLength(1);
    // The validator's own reason code, behind the one opaque `invalid_grant`.
    expect(emittedData(TOKEN_REQUEST_FAILED)).toEqual([
      { grantType: JWT_BEARER_GRANT, error: 'invalid_grant', reason: 'replayed' },
    ]);
    // The validator's message stays in the operator's log, never in the event.
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ reason: 'replayed', detail: expect.any(String) }),
      'token endpoint: identity assertion refused'
    );
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
    const { fastify, ctx } = setupConsumeStub({ idJagTargets: ['https://other-mcp.example/'] });

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(InvalidTargetError);
  });

  it('rejects every resource when the client has NO ID-JAG target (deny by default)', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub({ idJagTargets: [] });

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(InvalidTargetError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('rejects a `resource` listed only in the client `audience` (#434)', async () => {
    // `audience` bounds the QAuth tokens `client_credentials` issues; it is not
    // an ID-JAG target list, so it lets no assertion be redeemed.
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub({ audience: [MCP_SERVER], idJagTargets: [] });

    await expect(
      invoke(fastify, ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(InvalidTargetError);
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      {
        grantType: JWT_BEARER_GRANT,
        error: 'invalid_target',
        reason: 'id_jag_target_not_allowed',
      },
      expect.objectContaining({ clientId: EMA_CLIENT_ID, actor: 'client' })
    );
  });

  it('redeems an assertion for a QAuth API audience only for a client that lists it (#509)', async () => {
    // The ID-JAG targets name what an assertion may be redeemed for; a QAuth
    // API audience is issued only to a client whose `audience` lists it too.
    const DEVELOPER_AUDIENCE = 'urn:qauth:aud:developer:v1-rc.0';
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const unlisted = setupConsumeStub({ idJagTargets: [DEVELOPER_AUDIENCE] });
    await expect(
      invoke(
        unlisted.fastify,
        unlisted.ctx,
        bearerRequest(await signIdJag(idpKey, { resource: DEVELOPER_AUDIENCE }))
      )
    ).rejects.toBeInstanceOf(InvalidTargetError);
    expect(unlisted.fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      {
        grantType: JWT_BEARER_GRANT,
        error: 'invalid_target',
        reason: 'reserved_audience_not_listed',
      },
      expect.objectContaining({ clientId: EMA_CLIENT_ID })
    );

    const listed = setupConsumeStub({
      idJagTargets: [DEVELOPER_AUDIENCE],
      audience: [DEVELOPER_AUDIENCE],
    });
    await invoke(
      listed.fastify,
      listed.ctx,
      bearerRequest(await signIdJag(idpKey, { resource: DEVELOPER_AUDIENCE }))
    );
    expect(listed.fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ aud: DEVELOPER_AUDIENCE })
    );
  });

  it('denies when the stored targets are not a list, rather than matching a substring', async () => {
    // Beside the DB CHECK: a string would make `includes` a substring test.
    enableIdJag();
    const idpKey = await wireTrustedIdp();
    const { fastify, ctx } = setupConsumeStub({
      idJagTargets: `${MCP_SERVER} https://other-mcp.example/` as unknown as string[],
    });

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

  it('records both the accept and the reject as events', async () => {
    enableIdJag();
    const idpKey = await wireTrustedIdp();

    const accepted = setupConsumeStub();
    await invoke(accepted.fastify, accepted.ctx, bearerRequest(await signIdJag(idpKey)));
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_ISSUED,
      expect.objectContaining({
        grantType: JWT_BEARER_GRANT,
        resources: [MCP_SERVER],
        idJagIssuer: IDP_ISSUER,
        idJagId: expect.any(String),
      }),
      expect.objectContaining({ userId: 'user-uuid-enterprise', clientId: EMA_CLIENT_ID })
    );

    emitUserEventMock.mockClear();
    const rejected = setupConsumeStub({ linked: false });
    await expect(
      invoke(rejected.fastify, rejected.ctx, bearerRequest(await signIdJag(idpKey)))
    ).rejects.toBeInstanceOf(InvalidGrantError);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      { grantType: JWT_BEARER_GRANT, error: 'invalid_grant', reason: 'subject_not_linked' },
      expect.objectContaining({ userId: null, clientId: EMA_CLIENT_ID })
    );
    expect(emittedData(TOKEN_ISSUED)).toEqual([]);
  });
});

describe('POST /oauth/token — ID-JAG MINT (token exchange, ADR-011)', () => {
  const AGENT_CLIENT_ID = 'agent-client';

  /**
   * An agent client provisioned to mint for {@link TARGET_AS} and
   * {@link MCP_SERVER} through its ID-JAG targets (#434). Its `audience` is
   * empty by default, so the happy path proves the targets alone suffice.
   */
  function setupMintStub(
    opts: {
      audience?: string[] | null;
      idJagTargets?: string[];
      isAgent?: boolean;
      grantTypes?: string[];
      subjectScope?: string;
      subjectAct?: unknown;
      subjectExp?: number;
      /**
       * The agent's registered `scopes`. Defaults to the default subject
       * token's scope, so the cases that test something else mint; GATE 4d
       * (ADR-011 §3, amended 2026-10-19) has its own cases below.
       */
      scopes?: string[];
    } = {}
  ) {
    const { fastify, ctx } = createFastifyStub();

    const client = {
      id: 'client-uuid-agent-1',
      clientId: AGENT_CLIENT_ID,
      clientSecretHash: 'hash',
      enabled: true,
      grantTypes: opts.grantTypes ?? [TOKEN_EXCHANGE_GRANT],
      scopes: opts.scopes ?? ['chat.read', 'chat.history'],
      audience: opts.audience === undefined ? null : opts.audience,
      idJagTargets: opts.idJagTargets === undefined ? [TARGET_AS, MCP_SERVER] : opts.idJagTargets,
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
      exp: opts.subjectExp ?? Math.floor(Date.now() / 1000) + 600,
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
    // The subject token's scope is inside the agent's registered scopes, so
    // the assertion carries all of it (GATE 4a and GATE 4d both hold).
    const { fastify, ctx } = setupMintStub({
      subjectScope: 'chat.read chat.history',
      scopes: ['chat.read', 'chat.history'],
    });

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

  it("caps the assertion at the subject token's remaining lifetime (never outlives its authority)", async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    // The subject token has 60 s left; ID_JAG_ISSUED_LIFETIME is 300 s.
    const subjectExp = Math.floor(Date.now() / 1000) + 60;
    const { fastify, ctx } = setupMintStub({ subjectExp });

    const result = (await invoke(fastify, ctx, mintRequest())) as Record<string, unknown>;

    expect(result['expires_in']).toBeLessThanOrEqual(60);
    const claims = decodeJwt(result['access_token'] as string);
    expect(claims.exp as number).toBeLessThanOrEqual(subjectExp);
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

  it.each([AS_ISSUER, `${AS_ISSUER}/`])(
    'refuses to mint for THIS server (%s), even when the client allowlist lists it (gate 5)',
    async (selfAudience) => {
      mockEnv['ID_JAG_ENABLED'] = true;
      // The misconfiguration the gate exists for: the operator put QAuth's own
      // issuer among the client's targets. The mint must still refuse it.
      const { fastify, ctx } = setupMintStub({
        idJagTargets: [AS_ISSUER, `${AS_ISSUER}/`, MCP_SERVER],
      });

      await expect(
        invoke(fastify, ctx, mintRequest({ audience: [selfAudience] }))
      ).rejects.toBeInstanceOf(InvalidTargetError);
    }
  );

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

    const multiple = setupMintStub({
      idJagTargets: [TARGET_AS, MCP_SERVER, 'https://mcp2.example/'],
    });
    await expect(
      invoke(
        multiple.fastify,
        multiple.ctx,
        mintRequest({ resource: [MCP_SERVER, 'https://mcp2.example/'] })
      )
    ).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it('rejects an audience outside the client ID-JAG targets', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub({ idJagTargets: [MCP_SERVER] });

    await expect(invoke(fastify, ctx, mintRequest())).rejects.toBeInstanceOf(InvalidTargetError);
  });

  it('rejects everything when the client has NO ID-JAG target (deny by default)', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub({ idJagTargets: [] });

    await expect(invoke(fastify, ctx, mintRequest())).rejects.toBeInstanceOf(InvalidTargetError);
    expect(emittedData(TOKEN_ISSUED)).toEqual([]);
  });

  it('refuses targets listed only in the client `audience` (#434)', async () => {
    // `audience` bounds the QAuth tokens `client_credentials` issues; it is not
    // an ID-JAG target list, so it lets the agent mint for nothing.
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub({
      audience: [TARGET_AS, MCP_SERVER],
      idJagTargets: [],
    });

    await expect(invoke(fastify, ctx, mintRequest())).rejects.toBeInstanceOf(InvalidTargetError);
    expect(emittedData(TOKEN_ISSUED)).toEqual([]);
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      {
        grantType: TOKEN_EXCHANGE_GRANT,
        error: 'invalid_target',
        reason: 'id_jag_target_not_allowed',
      },
      expect.objectContaining({ userId: 'user-uuid-subject', clientId: AGENT_CLIENT_ID })
    );
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

  // GATE 4d (ADR-011 §3, amended 2026-10-19). The assertion's target comes from
  // the agent's registration (`audience`), so its scope is bounded by the
  // agent's registration (`scopes`) as well — the same pair of columns
  // `client_credentials` applies. Before the amendment the mint copied the
  // subject token's scope unchecked, so an agent registered for `chat.read`
  // got a QAuth-signed `chat.read chat.history` at a foreign server.
  describe('GATE 4d — the agent registered scopes bound the assertion', () => {
    function expectRefusedWithEvent() {
      expect(emitUserEventMock).toHaveBeenCalledWith(
        expect.anything(),
        TOKEN_REQUEST_FAILED,
        {
          grantType: TOKEN_EXCHANGE_GRANT,
          error: 'invalid_scope',
          reason: 'scope_not_allowed_for_client',
        },
        expect.objectContaining({ userId: 'user-uuid-subject', clientId: AGENT_CLIENT_ID })
      );
      expect(emittedData(TOKEN_ISSUED)).toEqual([]);
    }

    it('refuses a scope inherited from the subject token that the agent is not registered for', async () => {
      mockEnv['ID_JAG_ENABLED'] = true;
      const { fastify, ctx } = setupMintStub({
        scopes: ['chat.read'],
        subjectScope: 'chat.read chat.history',
      });

      const refusal = invoke(fastify, ctx, mintRequest());
      await expect(refusal).rejects.toBeInstanceOf(InvalidScopeError);
      await expect(refusal).rejects.toMatchObject({ message: 'invalid_scope' });
      expectRefusedWithEvent();
    });

    it('refuses an explicitly requested scope outside the registered scopes', async () => {
      mockEnv['ID_JAG_ENABLED'] = true;
      const { fastify, ctx } = setupMintStub({
        scopes: ['chat.read'],
        subjectScope: 'chat.read chat.history',
      });

      await expect(
        invoke(fastify, ctx, mintRequest({ scope: 'chat.history' }))
      ).rejects.toBeInstanceOf(InvalidScopeError);
      expectRefusedWithEvent();
    });

    it('denies a scoped assertion to an agent registered with no scopes', async () => {
      mockEnv['ID_JAG_ENABLED'] = true;
      // This is the case the pre-amendment suite minted: an agent stub with
      // `scopes: []` received the subject token's `chat.read chat.history`.
      const { fastify, ctx } = setupMintStub({ scopes: [] });

      await expect(invoke(fastify, ctx, mintRequest())).rejects.toBeInstanceOf(InvalidScopeError);
    });

    it('mints when the request narrows the scope into the registered scopes', async () => {
      mockEnv['ID_JAG_ENABLED'] = true;
      const { fastify, ctx } = setupMintStub({
        scopes: ['chat.read'],
        subjectScope: 'chat.read chat.history',
      });

      const result = (await invoke(fastify, ctx, mintRequest({ scope: 'chat.read' }))) as Record<
        string,
        unknown
      >;

      expect(result['issued_token_type']).toBe(ID_JAG_TOKEN_TYPE);
      expect(result['scope']).toBe('chat.read');
      expect(decodeJwt(result['access_token'] as string)['scope']).toBe('chat.read');
    });

    it('leaves the delegation branch as it was (GATE 4d there waits for ADR-014)', async () => {
      mockEnv['ID_JAG_ENABLED'] = true;
      // The same agent with no registered scopes still receives a delegated
      // access token inside QAuth's trust domain: there the target stays
      // inside the subject token's audience (GATE 4b), and adding GATE 4d on
      // this branch is ADR-014's decision, behind AUTHORITY_TREE_ENABLED.
      const { fastify, ctx } = setupMintStub({ scopes: [] });
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

      expect(result['issued_token_type']).toBe(ACCESS_TOKEN_URN);
      expect(result['scope']).toBe('chat.read chat.history');
    });
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

  it('records the mint with the assertion id, never the assertion itself', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const { fastify, ctx } = setupMintStub();

    const result = (await invoke(fastify, ctx, mintRequest())) as Record<string, unknown>;
    const claims = decodeJwt(result['access_token'] as string);

    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_ISSUED,
      expect.objectContaining({
        grantType: TOKEN_EXCHANGE_GRANT,
        issuedTokenType: ID_JAG_TOKEN_TYPE,
        delegationDepth: 1,
        idJagId: claims.jti,
        audience: [TARGET_AS],
        resources: [MCP_SERVER],
      }),
      // The agent is the actor, through the chain the assertion derives from.
      expect.objectContaining({
        userId: 'user-uuid-subject',
        clientId: AGENT_CLIENT_ID,
        act: { sub: AGENT_CLIENT_ID },
      })
    );
    const logged = emitUserEventMock.mock.calls
      .map((call) => JSON.stringify(call.slice(2)))
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
    supplyRequestRealm(app, REALM);
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
        // Covers the subject token's scope, or GATE 4d refuses the mint.
        scopes: ['chat.read'],
        audience: null,
        idJagTargets: [TARGET_AS, MCP_SERVER],
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
      (
        instance.repositories.authorizationCodes.findByCodeIncludingUsed as unknown as Mock
      ).mockResolvedValue({
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
      (instance.repositories.oauthConsents.findActive as unknown as Mock).mockResolvedValue({
        id: 'consent-1',
        scopes: ['email', 'openid'],
        revokedAt: null,
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
      .setAudience(overrides.aud ?? AS_ISSUER_URL)
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

  // Regression (ANT-2026-MW7I4DS4): the verifier's refusal reason, meant for
  // the server side only, was rethrown with the error and rendered as
  // `error_description` — telling an unauthenticated caller which client_ids
  // are registered and how they authenticate, what a `jwks_uri` fetch found,
  // and the address an internal name resolves to when the SSRF guard blocks it.
  // The event records the refusal as a code, without that prose.
  it('keeps the reason an assertion was refused off the wire and out of the event', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    // A registered client must answer exactly as an unregistered one does.
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient({ tokenEndpointAuthMethod: 'client_secret_post' })
    );

    const error = await runToken(handler, {
      grant_type: 'client_credentials',
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await signAssertion(),
    }).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(InvalidClientError);
    expect((error as InvalidClientError).errorDescription).toBeUndefined();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      {
        grantType: 'client_credentials',
        error: 'invalid_client',
        reason: 'client_authentication_failed',
      },
      expect.objectContaining({ realmId: 'realm-1', actor: 'client' })
    );
    expect(JSON.stringify(emitUserEventMock.mock.calls.map((call) => call.slice(2)))).not.toContain(
      'private_key_jwt'
    );
  });

  it('keeps a blocked jwks_uri target, and the address it resolved to, off the wire', async () => {
    const { fastify, ctx } = createFastifyStub();
    await tokenRoute(fastify);
    const handler = ctx.handler;
    if (!handler) throw new Error('Handler missing');

    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      pkjwtClient({ jwks: null, jwksUri: 'https://internal.example/jwks.json' })
    );
    egressGet.mockRejectedValue(
      blockedEgress('CIMD host resolves to a non-public address (10.9.8.7)')
    );

    const error = await runToken(handler, {
      grant_type: 'client_credentials',
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await signAssertion(),
    }).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(InvalidClientError);
    expect((error as InvalidClientError).errorDescription).toBeUndefined();
    expect(JSON.stringify(error)).not.toContain('10.9.8.7');
    // Nor in the event, which is exported beyond the operator's logs.
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      TOKEN_REQUEST_FAILED,
      expect.objectContaining({ error: 'invalid_client', reason: 'client_authentication_failed' }),
      expect.anything()
    );
    expect(JSON.stringify(emitUserEventMock.mock.calls.map((call) => call.slice(2)))).not.toContain(
      '10.9.8.7'
    );
    // The operator's log keeps why, as the audit row did.
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        grantType: 'client_credentials',
        reason: expect.stringContaining('10.9.8.7'),
      }),
      'token endpoint: client authentication refused'
    );
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
      .setAudience(AS_ISSUER_URL)
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
