/**
 * Environment-aware authorization posture at the token endpoint
 * (ADR-008 §5/§7, issue #197).
 *
 * Proves the production profile delivers the hardened bundle (short access-token
 * lifespan, PKCE downgrade rejected), development relaxes ONLY the sanctioned
 * knob (long lifespan), staging keeps the short lifespan, and the HARD FLOORS
 * (client secret hashed + verified, RFC 8707 audience binding, PKCE downgrade)
 * hold even for a development client.
 *
 * The two lifespans are the realm's (#527): its policies hold them, and the
 * JWT plugin's environment lifespans, which differ here, go unused.
 */
import { InvalidGrantError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    TOKEN_RATE_LIMIT: 60,
    TOKEN_RATE_WINDOW: 60,
  },
}));

import { testPolicyStore } from '../../../testing/realm-policies';
import { testRealm } from '../../../testing/request-realm';
import type { RealmRow } from '../../helpers/request-realm';
import tokenRoute from './token';

// ADR-008 §5 (#197): short baseline (staging/production) vs the long
// development convenience, both the realm's (#527). The handler selects
// between them by tier.
const SHORT_LIFESPAN = 900;
const LONG_LIFESPAN = 28_800; // 8h
const REFRESH_LIFESPAN = 86_400;
/** The JWT plugin's lifespans: what the environment gave it, for a realm with no policies. */
const PLUGIN_ACCESS_LIFESPAN = 60;
const PLUGIN_REFRESH_LIFESPAN = 604_800;

/** The realm argument of every token the route signs: the request's (#491). */
const IN_REQUEST_REALM = expect.objectContaining({ id: 'realm-1' });

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
}

function createReply(onSend?: (body: unknown) => void) {
  const reply: any = {
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

/**
 * Build a token-route stub primed for the authorization_code grant. `realmEnv`
 * is the realm ceiling and `clientEnv` the client's declared environment; the
 * effective policy is the stricter of the two (fail-safe to production).
 */
function makeAuthCodeStub(opts: {
  realmEnv: string;
  clientEnv: string;
  /** Override the bound code challenge (empty string ⇒ no PKCE on the code). */
  codeChallenge?: string;
}) {
  const ctx: TestContext = {};
  const realm = testRealm({
    id: 'realm-1',
    name: 'default',
    // Unchecked on purpose: the fail-safe test hands in a value outside the enum.
    maxEnvironmentLaxity: opts.realmEnv as RealmRow['maxEnvironmentLaxity'],
    policiesVersion: 1,
  });
  const fastify: any = {
    withTypeProvider: () => ({
      post: (_url: string, _o: unknown, handler: any) => {
        ctx.handler = (request, reply) => {
          // The realm resolver's decoration (#486): a request reaches its
          // handler with the realm of its host, ceiling included.
          request.realm ??= realm;
          return handler(request, reply);
        };
        return fastify;
      },
    }),
    repositories: {
      oauthClients: {
        findByClientId: vi.fn().mockResolvedValue({
          id: 'client-uuid',
          clientId: 'app-123',
          clientSecretHash: 'argon2-hash',
          enabled: true,
          grantTypes: ['authorization_code'],
          scopes: ['openid'],
          audience: ['https://api.example.com'],
          tokenEndpointAuthMethod: 'client_secret_post',
          environment: opts.clientEnv,
        }),
      },
      authorizationCodes: {
        findByCodeIncludingUsed: vi.fn().mockResolvedValue({
          id: 'code-1',
          used: false,
          expiresAt: Date.now() + 60_000,
          oauthClientId: 'client-uuid',
          userId: 'user-1',
          redirectUri: 'https://example.com/cb',
          codeChallenge: opts.codeChallenge ?? 'bound-challenge',
          codeChallengeMethod: 'S256',
          nonce: null,
          scopes: ['openid'],
          resource: ['https://api.example.com'],
          state: null,
        }),
        markUsed: vi.fn().mockResolvedValue(undefined),
      },
      users: {
        findById: vi.fn().mockResolvedValue({
          id: 'user-1',
          email: 'u@example.com',
          emailVerified: true,
          enabled: true,
        }),
      },
      refreshTokens: {
        create: vi.fn().mockResolvedValue(undefined),
      },
      oauthConsents: {
        findActive: vi.fn().mockResolvedValue({
          scopes: ['openid'],
          resourceScopes: { 'https://api.example.com': ['openid'] },
          revokedAt: null,
        }),
      },
      // #229: token issuance resolves email claims from verified attributes.
      userAttributes: {
        findVerifiedByUserIdAndKey: vi.fn().mockResolvedValue([
          {
            id: 'attr-1',
            userId: 'user-1',
            source: 'self_reported',
            attrKey: 'email',
            attrValue: 'u@example.com',
            verified: true,
            expiresAt: null,
            createdAt: 1,
            updatedAt: 1,
          },
        ]),
      },
    },
    passwordHasher: {
      verifyPassword: vi.fn().mockResolvedValue(true),
    },
    jwtUtils: {
      signAccessToken: vi.fn().mockResolvedValue('access.jwt'),
      // #275: classical posture — issueAccessToken takes the non-hybrid branch.
      isHybridSigningEnabled: () => false,
      signIdToken: vi.fn().mockResolvedValue('id.jwt'),
      generateRefreshToken: vi
        .fn()
        .mockReturnValue({ token: 'refresh-token', tokenHash: 'refresh-hash' }),
      getAccessTokenLifespan: vi.fn().mockReturnValue(PLUGIN_ACCESS_LIFESPAN),
      getRefreshTokenLifespan: vi.fn().mockReturnValue(PLUGIN_REFRESH_LIFESPAN),
    },
    policyStore: testPolicyStore({
      accessTokenLifespanSeconds: SHORT_LIFESPAN,
      developmentAccessTokenLifespanSeconds: LONG_LIFESPAN,
      refreshTokenLifespanSeconds: REFRESH_LIFESPAN,
    }),
    pkceUtils: {
      verifyCodeChallenge: vi.fn().mockReturnValue(true),
    },
    db: { transaction: vi.fn(async (cb: (tx: unknown) => Promise<unknown>) => cb({})) },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    metrics: { tokensIssued: { inc: vi.fn() } },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

function authCodeRequest() {
  return {
    body: {
      grant_type: 'authorization_code',
      code: 'the-code',
      redirect_uri: 'https://example.com/cb',
      client_id: 'app-123',
      client_secret: 'the-secret',
      code_verifier: 'V'.repeat(43),
    },
    ip: '127.0.0.1',
    headers: { 'user-agent': 'vitest' },
  };
}

describe('token endpoint — environment-aware access-token lifespan (#197)', () => {
  it('production client gets the SHORT lifespan baseline', async () => {
    const { fastify, ctx } = makeAuthCodeStub({ realmEnv: 'production', clientEnv: 'production' });
    await tokenRoute(fastify);
    let body: any;
    await ctx.handler!(
      authCodeRequest(),
      createReply((b) => (body = b))
    );

    expect(body.expires_in).toBe(SHORT_LIFESPAN);
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      IN_REQUEST_REALM,
      expect.objectContaining({ expiresInOverride: SHORT_LIFESPAN })
    );
  });

  it('development client (under a development realm) gets the LONG lifespan', async () => {
    const { fastify, ctx } = makeAuthCodeStub({
      realmEnv: 'development',
      clientEnv: 'development',
    });
    await tokenRoute(fastify);
    let body: any;
    await ctx.handler!(
      authCodeRequest(),
      createReply((b) => (body = b))
    );

    expect(body.expires_in).toBe(LONG_LIFESPAN);
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      IN_REQUEST_REALM,
      expect.objectContaining({ expiresInOverride: LONG_LIFESPAN })
    );
  });

  it("gives a development client's ID token the realm's SHORT lifespan: the tier is for access tokens (#527)", async () => {
    const { fastify, ctx } = makeAuthCodeStub({
      realmEnv: 'development',
      clientEnv: 'development',
    });
    await tokenRoute(fastify);
    await ctx.handler!(authCodeRequest(), createReply());

    expect(fastify.jwtUtils.signIdToken).toHaveBeenCalledWith(
      IN_REQUEST_REALM,
      expect.objectContaining({ expiresInOverride: SHORT_LIFESPAN })
    );
  });

  it.each(['production', 'development'])(
    "gives a %s client's refresh token the realm's refresh lifespan (#527)",
    async (environment) => {
      const { fastify, ctx } = makeAuthCodeStub({
        realmEnv: environment,
        clientEnv: environment,
      });
      await tokenRoute(fastify);
      const before = Date.now();
      await ctx.handler!(authCodeRequest(), createReply());

      const stored = (fastify.repositories.refreshTokens.create as Mock).mock.calls[0][0] as {
        familyCreatedAt: number;
        expiresAt: number;
      };
      expect(stored.familyCreatedAt).toBeGreaterThanOrEqual(before);
      expect(stored.expiresAt).toBe(stored.familyCreatedAt + REFRESH_LIFESPAN * 1000);
      expect(fastify.jwtUtils.getRefreshTokenLifespan).not.toHaveBeenCalled();
    }
  );

  it('staging client keeps the SHORT lifespan (security/operational baseline)', async () => {
    const { fastify, ctx } = makeAuthCodeStub({ realmEnv: 'staging', clientEnv: 'staging' });
    await tokenRoute(fastify);
    let body: any;
    await ctx.handler!(
      authCodeRequest(),
      createReply((b) => (body = b))
    );
    expect(body.expires_in).toBe(SHORT_LIFESPAN);
  });

  it('a PRODUCTION realm caps a development client back to the SHORT lifespan (ceiling wins)', async () => {
    const { fastify, ctx } = makeAuthCodeStub({ realmEnv: 'production', clientEnv: 'development' });
    await tokenRoute(fastify);
    let body: any;
    await ctx.handler!(
      authCodeRequest(),
      createReply((b) => (body = b))
    );
    expect(body.expires_in).toBe(SHORT_LIFESPAN);
  });

  it('an UNSET client/realm environment fails safe to the short (production) lifespan', async () => {
    const { fastify, ctx } = makeAuthCodeStub({ realmEnv: 'bogus', clientEnv: 'also-bogus' });
    await tokenRoute(fastify);
    let body: any;
    await ctx.handler!(
      authCodeRequest(),
      createReply((b) => (body = b))
    );
    expect(body.expires_in).toBe(SHORT_LIFESPAN);
  });
});

describe('token endpoint — HARD FLOORS hold even for a development client (#197)', () => {
  it('PKCE downgrade is rejected for a development client (floor, not a dev relaxation)', async () => {
    // No challenge bound to the code, but a verifier is presented → downgrade.
    const { fastify, ctx } = makeAuthCodeStub({
      realmEnv: 'development',
      clientEnv: 'development',
      codeChallenge: '',
    });
    await tokenRoute(fastify);
    await expect(ctx.handler!(authCodeRequest(), createReply())).rejects.toThrow(InvalidGrantError);
    // No token is minted on a downgrade attempt.
    expect(fastify.jwtUtils.signAccessToken).not.toHaveBeenCalled();
  });

  it('client secret is still hashed + verified for a development client', async () => {
    const { fastify, ctx } = makeAuthCodeStub({
      realmEnv: 'development',
      clientEnv: 'development',
    });
    await tokenRoute(fastify);
    await ctx.handler!(authCodeRequest(), createReply());
    // The argon2 hash is compared — never a plaintext equality, in any environment.
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledWith(
      'argon2-hash',
      'the-secret',
      {
        shedWhenQueueFull: true,
      }
    );
  });

  it('RFC 8707 audience binding still holds for a development client', async () => {
    const { fastify, ctx } = makeAuthCodeStub({
      realmEnv: 'development',
      clientEnv: 'development',
    });
    await tokenRoute(fastify);
    await ctx.handler!(authCodeRequest(), createReply());
    // aud is bound to the code's resource, not widened by the dev profile.
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      IN_REQUEST_REALM,
      expect.objectContaining({ aud: 'https://api.example.com' })
    );
  });
});
