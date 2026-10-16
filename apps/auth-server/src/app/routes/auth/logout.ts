import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import { JWTExpiredError, JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { logAuthEvent } from '../../helpers/auth-events';
import { clientAddressKey } from '../../helpers/client-address';
import { assertManagementToken } from '../../helpers/management-token';
import { revokeJti } from '../../helpers/token-revocation';
import { logoutHeadersSchema, logoutResponseSchema } from '../../schemas/auth';

/**
 * Logout route
 * Handles JWT verification, refresh token revocation, and audit logging
 * Allows logout even with expired tokens (user is ending their session anyway)
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/logout',
    {
      schema: {
        description:
          'Log out the current user. Revokes all refresh tokens and unredeemed authorization codes for the user, and the access token presented. Accepts expired access tokens.',
        tags: ['Auth'],
        headers: logoutHeadersSchema,
        response: {
          200: logoutResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.LOGOUT_RATE_LIMIT,
          timeWindow: env.LOGOUT_RATE_WINDOW * 1000,
          keyGenerator: clientAddressKey,
        },
      },
    },
    async (request, reply) => {
      let userId: string | undefined;
      let isExpired = false;

      try {
        // Extract JWT from Authorization header
        const authHeader = request.headers.authorization;
        const token = fastify.jwtUtils.extractFromHeader(authHeader);

        if (!token) {
          throw new JWTInvalidError(
            'Missing or invalid Authorization header. Expected format: "Bearer <token>"'
          );
        }

        // Try to verify JWT token
        // For logout, we allow expired tokens - user is ending their session anyway
        let claims: JWTPayload;
        try {
          claims = await fastify.jwtUtils.verifyAccessToken(token, {
            // RFC 9700 mix-up defence: only accept a token this AS issued.
            issuer: fastify.jwtUtils.getIssuer(),
          });
        } catch (error) {
          if (error instanceof JWTExpiredError) {
            // Token expired - its signature verified, so decode it to read the claims
            isExpired = true;
            claims = fastify.jwtUtils.decodeTokenUnsafe(token);
          } else {
            // Token is invalid (bad signature, malformed, etc.)
            throw error;
          }
        }

        // Logout revokes the user's refresh tokens at EVERY client, and every
        // user access token carries the user's id as `sub`. Accept only the
        // first-party token `/auth/login` mints, expired or not, so a token
        // issued to another client or audience cannot end the user's sessions.
        await assertManagementToken(fastify, claims);
        userId = claims.sub;

        if (!userId) {
          throw new JWTInvalidError('Invalid JWT token');
        }

        // Get user from database to verify existence
        const user = await fastify.repositories.users.findById(userId);
        if (!user) {
          throw new NotFoundError('User', userId);
        }

        // Invalidate unredeemed authorization codes first: one redeemed after
        // the sweep below would mint a refresh token that survives the logout.
        // This also waits for a redemption in flight, which keeps its code row
        // locked until its refresh token is committed for the sweep to see.
        await fastify.repositories.authorizationCodes.invalidateForUser(userId);

        // Revoke all active refresh tokens for user
        // This ensures user is logged out from all devices
        await fastify.repositories.refreshTokens.revokeAllForUser(userId, 'logout');

        // End the token this request was made with as well, as `/oauth/revoke`
        // ends one presented to it: otherwise it keeps working at the
        // management API until it expires. An expired token is already inert.
        if (!isExpired && claims.jti && claims.exp !== undefined) {
          await revokeJti(fastify, claims.jti, claims.exp - Math.floor(Date.now() / 1000));
        }

        // Log audit event (success)
        await fastify.repositories.auditLogs.create({
          userId: user.id,
          oauthClientId: null,
          event: 'user.logout.success',
          eventType: 'auth',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            tokenExpired: isExpired,
          },
        });

        // Structured success log (#124).
        logAuthEvent(request, 'user.logout.success', true, { userId: user.id });

        return reply.send({
          success: true as const,
          message: 'Successfully logged out' as const,
        });
      } catch (error) {
        // Structured failure log (#124).
        logAuthEvent(request, 'user.logout.failure', false, {
          userId: userId ?? null,
          reason: error instanceof Error ? error.name : 'unknown_error',
        });

        // Log failed logout attempt
        await fastify.repositories.auditLogs.create({
          userId: userId ?? null,
          oauthClientId: null,
          event: 'user.logout.failure',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });

        throw error;
      }
    }
  );
}
