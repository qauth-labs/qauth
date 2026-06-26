/**
 * Environment-aware authorization posture at the token endpoint
 * (ADR-008 §5/§7, issue #197).
 *
 * Proves the production profile delivers the hardened bundle (short access-token
 * lifespan, PKCE downgrade rejected), development relaxes ONLY the sanctioned
 * knob (long lifespan), staging keeps the short lifespan, and the HARD FLOORS
 * (client secret hashed + verified, RFC 8707 audience binding, PKCE downgrade)
 * hold even for a development client.
 */
import { InvalidGrantError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    TOKEN_RATE_LIMIT: 60,
    TOKEN_RATE_WINDOW: 60,
    // ADR-008 §5 (#197): short baseline (staging/production) vs the long
    // development convenience. The handler selects between them by tier.
    DEV_ACCESS_TOKEN_LIFESPAN: 28800, // 8h
  },
}));

import tokenRoute from './token';

const SHORT_LIFESPAN = 900;

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
  const fastify: any = {
    withTypeProvider: () => ({
      post: (_url: string, _o: unknown, handler: any) => {
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
          maxEnvironmentLaxity: opts.realmEnv,
        }),
        create: vi.fn(),
      },
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
        findByCode: vi.fn().mockResolvedValue({
          id: 'code-1',
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
      auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
    },
    passwordHasher: {
      verifyPassword: vi.fn().mockResolvedValue(true),
    },
    jwtUtils: {
      signAccessToken: vi.fn().mockResolvedValue('access.jwt'),
      signIdToken: vi.fn().mockResolvedValue('id.jwt'),
      generateRefreshToken: vi
        .fn()
        .mockReturnValue({ token: 'refresh-token', tokenHash: 'refresh-hash' }),
      getAccessTokenLifespan: vi.fn().mockReturnValue(SHORT_LIFESPAN),
      getRefreshTokenLifespan: vi.fn().mockReturnValue(604800),
    },
    pkceUtils: {
      verifyCodeChallenge: vi.fn().mockReturnValue(true),
    },
    sessionUtils: { setSession: vi.fn().mockResolvedValue(undefined) },
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

    expect(body.expires_in).toBe(28800);
    expect(fastify.jwtUtils.signAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ expiresInOverride: 28800 })
    );
  });

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
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledWith('argon2-hash', 'the-secret');
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
      expect.objectContaining({ aud: 'https://api.example.com' })
    );
  });
});
