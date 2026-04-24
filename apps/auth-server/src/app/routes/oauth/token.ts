import { randomUUID } from 'node:crypto';

import {
  BadRequestError,
  InvalidClientError,
  InvalidGrantError,
  InvalidScopeError,
  NotFoundError,
  UnauthorizedClientError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import {
  authenticateClient,
  authenticateClientPublicOrConfidential,
  extractClientCredentials,
  type OAuthClientLike,
  resolveAudience,
  validateScopes,
} from '../../helpers/client-auth';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import {
  type TokenExchangeAuthCodeBody,
  tokenExchangeBodySchema,
  type TokenExchangeClientCredsBody,
  type TokenExchangeRefreshBody,
  type TokenExchangeResponse,
  tokenExchangeResponseSchema,
} from '../../schemas/oauth';

/**
 * POST /oauth/token
 *
 * OAuth 2.1 token endpoint. Supports:
 *  - `authorization_code` grant with PKCE (RFC 6749 4.1.3 + RFC 7636).
 *  - `client_credentials` grant for service-to-service auth (RFC 6749 4.4).
 *  - `refresh_token` grant with rotation + replay detection (RFC 6749 §6,
 *    OAuth 2.1 §4.3.1, RFC 9700 §2.2.2). Confidential and public clients
 *    both dispatch here; public clients authenticate by refresh-token
 *    ownership instead of a client secret.
 *
 * Client auth supports both `client_secret_post` (form body) and
 * `client_secret_basic` (Authorization header, RFC 6749 2.3.1).
 *
 * Issued JWTs include `iss`, `aud` (per-client, RFC 8707 light), `exp`, `iat`,
 * and `scope` (when granted). `client_credentials` tokens set `sub = client_id`
 * and do NOT include a refresh token (RFC 6749 4.4.3).
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/token',
    {
      schema: {
        description:
          'OAuth 2.1 token endpoint. Supports authorization_code (with PKCE) and client_credentials grants. Client auth via client_secret_post or client_secret_basic.',
        tags: ['OAuth', 'Token'],
        body: tokenExchangeBodySchema,
        response: {
          200: tokenExchangeResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.TOKEN_RATE_LIMIT,
          timeWindow: env.TOKEN_RATE_WINDOW * 1000,
          keyGenerator: (req) => req.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const body = request.body as
        | TokenExchangeAuthCodeBody
        | TokenExchangeClientCredsBody
        | TokenExchangeRefreshBody;

      try {
        const realm = await getOrCreateDefaultRealm(fastify);

        // Authenticate the client. authorization_code (PKCE) and
        // refresh_token both support public clients
        // (OAuth 2.1 §4.1.3 / §4.3.1 / RFC 6749 §6). The PKCE verifier /
        // refresh-token ownership binds the grant to the client; no
        // `client_secret` is required when `token_endpoint_auth_method:
        // 'none'`. client_credentials is confidential-only by definition.
        let client: OAuthClientLike;
        try {
          if (body.grant_type === 'authorization_code' || body.grant_type === 'refresh_token') {
            client = await authenticateClientPublicOrConfidential(
              fastify,
              realm.id,
              request as FastifyRequest,
              body.client_id,
              body.client_secret
            );
          } else {
            const creds = extractClientCredentials(
              request as FastifyRequest,
              body.client_id,
              body.client_secret
            );
            client = await authenticateClient(fastify, realm.id, creds);
          }
        } catch (err) {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: null,
            event: 'oauth.token.exchange.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { error: 'Client authentication failed', grantType: body.grant_type },
          });
          throw err;
        }

        // RFC 6749 §5.1: token responses MUST NOT be cached by intermediaries.
        reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');

        // Route by grant type.
        if (body.grant_type === 'authorization_code') {
          const responseBody = await handleAuthorizationCode({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
          });
          return reply.send(responseBody);
        }

        if (body.grant_type === 'client_credentials') {
          const responseBody = await handleClientCredentials({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
          });
          return reply.send(responseBody);
        }

        if (body.grant_type === 'refresh_token') {
          const responseBody = await handleRefreshToken({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
          });
          return reply.send(responseBody);
        }

        // Schema validation should have rejected this already, but guard anyway.
        throw new BadRequestError('unsupported_grant_type');
      } catch (error) {
        if (
          error instanceof InvalidGrantError ||
          error instanceof InvalidClientError ||
          error instanceof InvalidScopeError ||
          error instanceof NotFoundError ||
          error instanceof BadRequestError ||
          error instanceof UnauthorizedClientError
        ) {
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.TOKEN);
          throw error;
        }

        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'oauth.token.exchange.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });

        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.TOKEN);
        throw error;
      }
    }
  );
}

type HandlerContext<TBody> = {
  fastify: FastifyInstance;
  request: FastifyRequest;
  client: OAuthClientLike;
  body: TBody;
};

/**
 * Handle the authorization_code grant (legacy flow from Phase 1).
 * Now also issues `aud` + `scope` claims on the access token.
 */
async function handleAuthorizationCode(
  ctx: HandlerContext<TokenExchangeAuthCodeBody>
): Promise<TokenExchangeResponse> {
  const { fastify, request, client, body } = ctx;

  if (!client.grantTypes.includes('authorization_code')) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'unauthorized_client', grantType: 'authorization_code' },
    });
    // RFC 6749 5.2: client authenticated, but not authorized for this grant.
    throw new UnauthorizedClientError();
  }

  // Authorization code lookup
  const authCode = await fastify.repositories.authorizationCodes.findByCode(body.code);
  if (!authCode) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'Invalid or expired authorization code' },
    });
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  if (authCode.oauthClientId !== client.id) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'Invalid or expired authorization code' },
    });
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  if (body.redirect_uri !== authCode.redirectUri) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'Invalid or expired authorization code' },
    });
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  const pkceValid = fastify.pkceUtils.verifyCodeChallenge(
    body.code_verifier,
    authCode.codeChallenge
  );
  if (!pkceValid) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'Invalid or expired authorization code' },
    });
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  await fastify.repositories.authorizationCodes.markUsed(authCode.id);

  const user = await fastify.repositories.users.findById(authCode.userId);
  if (!user) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'User not found' },
    });
    throw new NotFoundError('User', authCode.userId);
  }

  const scopeString = authCode.scopes.length > 0 ? authCode.scopes.join(' ') : undefined;

  const accessToken = await fastify.jwtUtils.signAccessToken({
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    clientId: client.clientId,
    scope: scopeString,
    aud: resolveAudience(client),
  });

  const { token: refreshToken, tokenHash } = fastify.jwtUtils.generateRefreshToken();

  const accessTokenExpiresIn = fastify.jwtUtils.getAccessTokenLifespan();
  const refreshTokenExpiresAt = Date.now() + fastify.jwtUtils.getRefreshTokenLifespan() * 1000;

  // Start a fresh refresh-token family. Every rotation (see
  // `handleRefreshToken`) inherits this `familyId` so replay of a revoked
  // token can be traced to — and revoke — the entire family.
  const familyId = randomUUID();

  await fastify.repositories.refreshTokens.create({
    userId: user.id,
    oauthClientId: client.id,
    tokenHash,
    familyId,
    expiresAt: refreshTokenExpiresAt,
    scopes: authCode.scopes,
  });

  let sessionId: string | undefined;
  try {
    sessionId = randomUUID();
    await fastify.sessionUtils.setSession(
      sessionId,
      {
        userId: user.id,
        email: user.email,
        sessionId,
        createdAt: Date.now(),
      },
      accessTokenExpiresIn
    );
  } catch (sessionError) {
    fastify.log.warn({ err: sessionError }, 'Failed to manage session during token exchange');
  }

  await fastify.repositories.auditLogs.create({
    userId: user.id,
    oauthClientId: client.id,
    event: 'oauth.token.exchange.success',
    eventType: 'token',
    success: true,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: { authCodeId: authCode.id, grantType: 'authorization_code' },
  });

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: accessTokenExpiresIn,
    token_type: 'Bearer' as const,
    ...(scopeString ? { scope: scopeString } : {}),
  };
}

/**
 * Handle the client_credentials grant (RFC 6749 4.4).
 *
 * - `sub` = clientId (no end-user).
 * - No refresh token issued (RFC 6749 4.4.3).
 * - Scopes must be a subset of client's configured `scopes` column.
 * - `aud` resolves from client.audience (default: clientId).
 */
async function handleClientCredentials(
  ctx: HandlerContext<TokenExchangeClientCredsBody>
): Promise<TokenExchangeResponse> {
  const { fastify, request, client, body } = ctx;

  if (!client.grantTypes.includes('client_credentials')) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'unauthorized_client', grantType: 'client_credentials' },
    });
    // RFC 6749 5.2: client authenticated, but not authorized for this grant.
    throw new UnauthorizedClientError();
  }

  // Validate requested scopes against client.scopes allowlist.
  let grantedScopes: string[];
  try {
    grantedScopes = validateScopes(body.scope, client.scopes);
  } catch (err) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: {
        error: err instanceof Error ? err.message : 'invalid_scope',
        grantType: 'client_credentials',
      },
    });
    throw err;
  }

  // A scopeless machine token has no authorisation surface — almost always a
  // misconfiguration. Require at least one granted scope per RFC 9700 best
  // practice for client_credentials tokens.
  if (grantedScopes.length === 0) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: {
        error: 'invalid_scope: client_credentials requires at least one scope',
        grantType: 'client_credentials',
      },
    });
    throw new InvalidScopeError('client_credentials grant requires at least one scope');
  }

  const scopeString = grantedScopes.join(' ');

  const accessToken = await fastify.jwtUtils.signAccessToken({
    sub: client.clientId,
    clientId: client.clientId,
    scope: scopeString,
    aud: resolveAudience(client),
  });

  const accessTokenExpiresIn = fastify.jwtUtils.getAccessTokenLifespan();

  await fastify.repositories.auditLogs.create({
    userId: null,
    oauthClientId: client.id,
    event: 'oauth.token.exchange.success',
    eventType: 'token',
    success: true,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: {
      grantType: 'client_credentials',
      scope: scopeString,
    },
  });

  return {
    access_token: accessToken,
    expires_in: accessTokenExpiresIn,
    token_type: 'Bearer' as const,
    ...(scopeString ? { scope: scopeString } : {}),
  };
}

/**
 * Handle the refresh_token grant (RFC 6749 §6, OAuth 2.1 §4.3.1).
 *
 * Security invariants enforced here:
 * - The client (confidential or public) must be enabled and allowed the
 *   `refresh_token` grant type (RFC 6749 §5.2 `unauthorized_client`).
 * - Presented refresh token must hash to a row that is either active OR
 *   revoked-but-known. Unknown/expired → `invalid_grant`.
 * - Ownership: `refreshToken.oauthClientId === client.id` (OAuth 2.1
 *   §4.3.1). Cross-client presentation → `invalid_grant`.
 * - Replay detection (RFC 9700 §2.2.2): if a revoked token is presented,
 *   revoke the entire family (every rotation sharing `family_id`) so any
 *   still-active descendant cannot be exchanged.
 * - Rotation: the presented token is marked `revoked='rotated'` BEFORE
 *   the new refresh token is persisted — never issue two concurrently
 *   live tokens for the same link in the family chain.
 * - Down-scoping: a `scope` param may request a subset of the original
 *   scopes; any scope not present in the original set → `invalid_scope`.
 *   Omitting the parameter reuses the original scopes verbatim.
 */
async function handleRefreshToken(
  ctx: HandlerContext<TokenExchangeRefreshBody>
): Promise<TokenExchangeResponse> {
  const { fastify, request, client, body } = ctx;

  if (!client.grantTypes.includes('refresh_token')) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'unauthorized_client', grantType: 'refresh_token' },
    });
    throw new UnauthorizedClientError();
  }

  const presentedHash = fastify.jwtUtils.hashRefreshToken(body.refresh_token);

  // Fetch the row without any active-state filter so replay of a
  // revoked token is detectable; downstream checks enforce liveness.
  const storedToken =
    await fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked(presentedHash);

  if (!storedToken) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'invalid_grant: refresh token not recognised' },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // Ownership check — before any replay logic, before any revocation.
  // Cross-client replay must never be able to fan out family revocation
  // on another client's tokens.
  if (storedToken.oauthClientId !== client.id) {
    await fastify.repositories.auditLogs.create({
      userId: storedToken.userId,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: {
        error: 'invalid_grant: refresh token bound to different client',
        presentingClientId: client.id,
        ownerClientId: storedToken.oauthClientId,
      },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // Replay detection — a revoked token in the correct family MUST trigger
  // family-wide revocation per RFC 9700 §2.2.2 / OAuth 2.1 §4.3.1.
  if (storedToken.revoked) {
    const familyRevokedCount = await fastify.repositories.refreshTokens.revokeFamily(
      storedToken.familyId,
      'replay_detected'
    );
    await fastify.repositories.auditLogs.create({
      userId: storedToken.userId,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'security',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: {
        error: 'invalid_grant: refresh token replay detected',
        familyId: storedToken.familyId,
        familyTokensRevoked: familyRevokedCount,
      },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  if (storedToken.expiresAt <= Date.now()) {
    await fastify.repositories.auditLogs.create({
      userId: storedToken.userId,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'invalid_grant: refresh token expired' },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // Load the subject user; reject if missing or disabled (RFC 9700 §4.14).
  const user = await fastify.repositories.users.findById(storedToken.userId);
  if (!user) {
    await fastify.repositories.auditLogs.create({
      userId: storedToken.userId,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'invalid_grant: user not found' },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }
  if (!user.enabled) {
    await fastify.repositories.refreshTokens.revoke(storedToken.id, 'user_disabled');
    await fastify.repositories.auditLogs.create({
      userId: user.id,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'invalid_grant: user_disabled' },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // Down-scoping: request narrower scope or keep original set.
  // Upscoping (any scope not in the original set) → invalid_scope.
  let grantedScopes: string[];
  if (body.scope !== undefined) {
    const requested = body.scope.split(/\s+/).filter((s) => s.length > 0);
    const extraneous = requested.filter((s) => !storedToken.scopes.includes(s));
    if (extraneous.length > 0) {
      await fastify.repositories.auditLogs.create({
        userId: user.id,
        oauthClientId: client.id,
        event: 'oauth.token.exchange.failure',
        eventType: 'token',
        success: false,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: {
          error: 'invalid_scope: upscoping rejected',
          extraneous,
          originalScopes: storedToken.scopes,
        },
      });
      throw new InvalidScopeError(`${extraneous.join(' ')} not in original refresh token scope`);
    }
    grantedScopes = requested;
  } else {
    grantedScopes = storedToken.scopes;
  }

  // Rotate atomically: revoke the presented token and insert the new one
  // inside a single transaction so a crash/failure between the two steps
  // can never leave the user with a revoked token and no replacement.
  // The revoke runs first inside the transaction so a concurrent replay
  // attempt waits on the row lock and then sees the token as already
  // revoked (→ family-revoke path). The unique index on `token_hash`
  // protects against the degenerate collision case.
  const { token: newRefreshToken, tokenHash: newRefreshTokenHash } =
    fastify.jwtUtils.generateRefreshToken();
  const refreshTokenExpiresAt = Date.now() + fastify.jwtUtils.getRefreshTokenLifespan() * 1000;

  await fastify.db.transaction(async (tx) => {
    await fastify.repositories.refreshTokens.revoke(storedToken.id, 'rotated', tx);
    await fastify.repositories.refreshTokens.create(
      {
        userId: user.id,
        oauthClientId: client.id,
        tokenHash: newRefreshTokenHash,
        familyId: storedToken.familyId,
        previousTokenHash: presentedHash,
        expiresAt: refreshTokenExpiresAt,
        scopes: grantedScopes,
      },
      tx
    );
  });

  const scopeString = grantedScopes.length > 0 ? grantedScopes.join(' ') : undefined;

  const accessToken = await fastify.jwtUtils.signAccessToken({
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    clientId: client.clientId,
    scope: scopeString,
    aud: resolveAudience(client),
  });

  const accessTokenExpiresIn = fastify.jwtUtils.getAccessTokenLifespan();

  await fastify.repositories.auditLogs.create({
    userId: user.id,
    oauthClientId: client.id,
    event: 'oauth.token.exchange.success',
    eventType: 'token',
    success: true,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: {
      grantType: 'refresh_token',
      familyId: storedToken.familyId,
      rotatedFromTokenId: storedToken.id,
      scope: scopeString,
    },
  });

  return {
    access_token: accessToken,
    refresh_token: newRefreshToken,
    expires_in: accessTokenExpiresIn,
    token_type: 'Bearer' as const,
    ...(scopeString ? { scope: scopeString } : {}),
  };
}
