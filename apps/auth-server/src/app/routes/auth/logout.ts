import { JWTExpiredError, JWTInvalidError, NotFoundError } from '@qauth/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
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
          'Log out the current user. Revokes all refresh tokens for the user. Accepts expired access tokens.',
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
          keyGenerator: (request) => request.ip || 'unknown',
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
        try {
          const { sub } = await fastify.jwtUtils.verifyAccessToken(token);
          userId = sub;
        } catch (error) {
          if (error instanceof JWTExpiredError) {
            // Token expired - decode without verification to get user ID
            isExpired = true;
            const { sub } = fastify.jwtUtils.decodeTokenUnsafe(token);
            userId = sub;
          } else {
            // Token is invalid (bad signature, malformed, etc.)
            throw error;
          }
        }

        if (!userId) {
          throw new JWTInvalidError('Invalid JWT token');
        }

        // Get user from database to verify existence
        const user = await fastify.repositories.users.findById(userId);
        if (!user) {
          throw new NotFoundError('User', userId);
        }

        // Revoke all active refresh tokens for user
        // This ensures user is logged out from all devices
        await fastify.repositories.refreshTokens.revokeAllForUser(userId, 'logout');

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

        return reply.send({
          success: true as const,
          message: 'Successfully logged out' as const,
        });
      } catch (error) {
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
