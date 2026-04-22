import { randomUUID } from 'node:crypto';

import {
  BadRequestError,
  InvalidCredentialsError,
  InvalidTokenError,
  NotFoundError,
  UnauthorizedClientError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import {
  authenticateClient,
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
  type TokenExchangeResponse,
  tokenExchangeResponseSchema,
} from '../../schemas/oauth';

/**
 * POST /oauth/token
 *
 * OAuth 2.1 token endpoint. Supports:
 *  - `authorization_code` grant with PKCE (RFC 6749 4.1.3 + RFC 7636).
 *  - `client_credentials` grant for service-to-service auth (RFC 6749 4.4).
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
      const body = request.body as TokenExchangeAuthCodeBody | TokenExchangeClientCredsBody;

      try {
        const realm = await getOrCreateDefaultRealm(fastify);

        // Authenticate the client up-front. This handles both
        // client_secret_post (body) and client_secret_basic (header).
        let creds;
        try {
          creds = extractClientCredentials(request, body.client_id, body.client_secret);
        } catch (err) {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: null,
            event: 'oauth.token.exchange.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: {
              error: 'Client authentication failed (credentials extraction)',
              grantType: body.grant_type,
            },
          });
          throw err;
        }

        let client;
        try {
          client = await authenticateClient(fastify, realm.id, creds);
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

        // Schema validation should have rejected this already, but guard anyway.
        throw new BadRequestError('unsupported_grant_type');
      } catch (error) {
        if (
          error instanceof InvalidTokenError ||
          error instanceof InvalidCredentialsError ||
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
    throw new InvalidTokenError('Invalid or expired authorization code');
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
    throw new InvalidTokenError('Invalid or expired authorization code');
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
    throw new InvalidTokenError('Invalid or expired authorization code');
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
    throw new InvalidTokenError('Invalid or expired authorization code');
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

  await fastify.repositories.refreshTokens.create({
    userId: user.id,
    oauthClientId: client.id,
    tokenHash,
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
    throw new BadRequestError(
      'invalid_scope: client_credentials grant requires at least one scope'
    );
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
