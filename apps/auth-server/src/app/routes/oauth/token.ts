import { randomUUID } from 'node:crypto';

import {
  InvalidCredentialsError,
  InvalidTokenError,
  NotFoundError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import {
  type TokenExchangeBody,
  tokenExchangeBodySchema,
  tokenExchangeResponseSchema,
} from '../../schemas/oauth';

/**
 * POST /oauth/token
 * OAuth 2.1 Authorization Code Grant with PKCE.
 * Exchanges authorization code for access and refresh tokens.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/token',
    {
      schema: {
        description:
          'OAuth 2.1 token endpoint. Exchanges authorization code for access and refresh tokens. Requires client credentials and PKCE code_verifier.',
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
      const body = request.body as TokenExchangeBody;

      try {
        // Realm
        const realm = await getOrCreateDefaultRealm(fastify);

        // Client lookup
        const client = await fastify.repositories.oauthClients.findByClientId(
          realm.id,
          body.client_id
        );

        if (!client) {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: null,
            event: 'oauth.token.exchange.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { error: 'Client authentication failed' },
          });
          throw new InvalidCredentialsError('Client authentication failed');
        }

        // Client checks
        if (!client.enabled || !client.grantTypes.includes('authorization_code')) {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: client.id,
            event: 'oauth.token.exchange.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { error: 'Client authentication failed' },
          });
          throw new InvalidCredentialsError('Client authentication failed');
        }

        // Client authentication (client_secret_post)
        const clientSecretValid = await fastify.passwordHasher.verifyPassword(
          client.clientSecretHash,
          body.client_secret
        );

        if (!clientSecretValid) {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: client.id,
            event: 'oauth.token.exchange.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { error: 'Client authentication failed' },
          });
          throw new InvalidCredentialsError('Client authentication failed');
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

        // Code–client match
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

        // Redirect URI match
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

        // PKCE verification
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

        // Mark code as used
        await fastify.repositories.authorizationCodes.markUsed(authCode.id);

        // Get user
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

        // Issue tokens
        const accessToken = await fastify.jwtUtils.signAccessToken({
          sub: user.id,
          email: user.email,
          email_verified: user.emailVerified,
          clientId: client.clientId,
        });

        const { token: refreshToken, tokenHash } = fastify.jwtUtils.generateRefreshToken();

        const accessTokenExpiresIn = fastify.jwtUtils.getAccessTokenLifespan();
        const refreshTokenExpiresAt =
          Date.now() + fastify.jwtUtils.getRefreshTokenLifespan() * 1000;

        await fastify.repositories.refreshTokens.create({
          userId: user.id,
          oauthClientId: client.id,
          tokenHash,
          expiresAt: refreshTokenExpiresAt,
          scopes: authCode.scopes,
        });

        // Session management (optional)
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
          // Session management is optional for token exchange
          // Log but don't fail the request
          fastify.log.warn({ err: sessionError }, 'Failed to manage session during token exchange');
        }

        // Audit success
        await fastify.repositories.auditLogs.create({
          userId: user.id,
          oauthClientId: client.id,
          event: 'oauth.token.exchange.success',
          eventType: 'token',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { authCodeId: authCode.id },
        });

        // Return tokens
        return reply.send({
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: accessTokenExpiresIn,
          token_type: 'Bearer' as const,
        });
      } catch (error) {
        // If error is already handled (InvalidTokenError, InvalidCredentialsError, NotFoundError),
        // ensure minimum response time then rethrow
        if (
          error instanceof InvalidTokenError ||
          error instanceof InvalidCredentialsError ||
          error instanceof NotFoundError
        ) {
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.TOKEN);
          throw error;
        }

        // Log other errors as failed token exchange attempts
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

        // Ensure minimum response time even on errors
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.TOKEN);

        throw error;
      }
    }
  );
}
