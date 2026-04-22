import { randomUUID } from 'node:crypto';

import { InvalidTokenError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { resolveAudience } from '../../helpers/client-auth';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { type RefreshRequest, refreshResponseSchema, refreshSchema } from '../../schemas/auth';

/**
 * Refresh token route
 * Handles refresh token validation, token rotation, new access token generation,
 * session management, and audit logging
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/refresh',
    {
      schema: {
        description:
          'Exchange a refresh token for new access and refresh tokens. Implements token rotation for security.',
        tags: ['Auth'],
        body: refreshSchema,
        response: {
          200: refreshResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.REFRESH_RATE_LIMIT,
          timeWindow: env.REFRESH_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const { refresh_token } = request.body as RefreshRequest;

      try {
        // Hash refresh token
        const refreshTokenHash = fastify.jwtUtils.hashRefreshToken(refresh_token);

        // Lookup token in database (repository filters for non-revoked and non-expired)
        const token = await fastify.repositories.refreshTokens.findByTokenHash(refreshTokenHash);

        // If token not found, expired, or revoked, throw generic error to prevent enumeration
        if (!token) {
          // Ensure minimum response time to prevent timing attacks
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.REFRESH);

          // Log failed refresh attempt
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: null,
            event: 'user.token.refresh.failure',
            eventType: 'auth',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: {
              error: 'Invalid or expired refresh token',
            },
          });

          throw new InvalidTokenError('Invalid or expired refresh token');
        }

        // Get user
        const user = await fastify.repositories.users.findById(token.userId);
        if (!user) {
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.REFRESH);
          throw new NotFoundError('User', token.userId);
        }

        // Get OAuth client
        const oauthClient = await fastify.repositories.oauthClients.findById(token.oauthClientId);
        if (!oauthClient) {
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.REFRESH);
          throw new NotFoundError('OAuthClient', token.oauthClientId);
        }

        // Reject refresh when the client or user has been disabled. Revoke
        // the stored token so repeated attempts fail fast, and audit the
        // disabled-state reason (RFC 9700 §4.14 — token revocation on
        // subject/client deactivation).
        if (!oauthClient.enabled || !user.enabled) {
          const reason = !oauthClient.enabled ? 'client_disabled' : 'user_disabled';
          await fastify.repositories.refreshTokens.revoke(token.id, reason);
          await fastify.repositories.auditLogs.create({
            userId: user.id,
            oauthClientId: oauthClient.id,
            event: 'user.token.refresh.failure',
            eventType: 'auth',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { error: reason },
          });
          throw new InvalidTokenError('Invalid or expired refresh token');
        }

        // Token rotation: Revoke old refresh token
        await fastify.repositories.refreshTokens.revoke(token.id, 'rotated');

        // Generate new refresh token
        const { token: newRefreshToken, tokenHash: newRefreshTokenHash } =
          fastify.jwtUtils.generateRefreshToken();

        // Calculate expiration times
        const accessTokenExpiresIn = fastify.jwtUtils.getAccessTokenLifespan();
        const refreshTokenExpiresAt = new Date(
          Date.now() + fastify.jwtUtils.getRefreshTokenLifespan() * 1000
        );

        // Store new refresh token in database
        await fastify.repositories.refreshTokens.create({
          userId: user.id,
          oauthClientId: oauthClient.id,
          tokenHash: newRefreshTokenHash,
          expiresAt: refreshTokenExpiresAt.getTime(),
          scopes: token.scopes,
          previousTokenHash: refreshTokenHash, // Track token rotation
        });

        // Generate new access token with current user data
        const refreshScopeString = token.scopes.length > 0 ? token.scopes.join(' ') : undefined;
        const accessToken = await fastify.jwtUtils.signAccessToken({
          sub: user.id,
          email: user.email,
          email_verified: user.emailVerified,
          clientId: oauthClient.clientId,
          scope: refreshScopeString,
          aud: resolveAudience(oauthClient),
        });

        // Session management
        // Try to get existing session from Redis (if sessionId was stored)
        // For MVP, we'll create/extend session if possible
        // Note: Session ID is not currently stored in refresh token metadata
        // For now, we'll create a new session or extend existing if we can find it
        // This is optional - refresh can work without session
        let sessionId: string | undefined;
        try {
          // Try to find session by userId (if we implement userId->sessionId mapping)
          // For MVP, we'll create a new session
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
          // Session management is optional for refresh
          // Log but don't fail the request
          fastify.log.warn({ err: sessionError }, 'Failed to manage session during refresh');
        }

        // Log audit event (success)
        await fastify.repositories.auditLogs.create({
          userId: user.id,
          oauthClientId: oauthClient.id,
          event: 'user.token.refresh.success',
          eventType: 'auth',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            sessionId,
            previousTokenId: token.id,
          },
        });

        // Update token lastUsedAt (if supported by repository)
        // Note: This might require repository enhancement

        // RFC 6749 §5.1: token responses MUST NOT be cached by intermediaries.
        reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');

        // Return new tokens
        return reply.send({
          access_token: accessToken,
          refresh_token: newRefreshToken,
          expires_in: accessTokenExpiresIn,
          token_type: 'Bearer' as const,
          ...(refreshScopeString ? { scope: refreshScopeString } : {}),
        });
      } catch (error) {
        // If error is already handled (InvalidTokenError, NotFoundError), ensure minimum response time
        if (error instanceof InvalidTokenError || error instanceof NotFoundError) {
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.REFRESH);
          throw error;
        }

        // Log other errors as failed refresh attempts
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'user.token.refresh.failure',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });

        // Ensure minimum response time even on errors
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.REFRESH);

        throw error;
      }
    }
  );
}
