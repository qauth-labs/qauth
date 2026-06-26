import { JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { userinfoResponseSchema } from '../../schemas/oauth';

/**
 * GET /userinfo
 * OIDC userinfo endpoint (MVP).
 *
 * - Requires Authorization: Bearer <access_token>.
 * - Uses JWT middleware to verify token and attach payload.
 * - Returns sub, email, email_verified for the authenticated user.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/userinfo',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          'OIDC userinfo endpoint. Returns claims for the authenticated user. Requires Bearer access token.',
        tags: ['OAuth', 'Userinfo'],
        security: [{ bearerAuth: [] }],
        response: {
          200: userinfoResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.USERINFO_RATE_LIMIT,
          timeWindow: env.USERINFO_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      let userId: string | null = null;

      try {
        const payload = request.jwtPayload;

        if (!payload || !payload.sub) {
          throw new JWTInvalidError('Missing JWT payload');
        }

        userId = payload.sub;

        const user = await fastify.repositories.users.findById(userId);

        if (!user) {
          throw new NotFoundError('User', userId);
        }

        // OIDC Core §5.4: userinfo claims are gated by the scopes the access
        // token was granted. `sub` is ALWAYS returned; `email`/`email_verified`
        // require the `email` scope; `name` (a profile claim) requires
        // `profile`. Parsing the space-delimited `scope` claim into a set is the
        // same convention used across the token/authorize paths.
        const grantedScopes = new Set(
          (payload.scope ?? '').split(/\s+/).filter((s) => s.length > 0)
        );

        const responseBody: {
          sub: string;
          email?: string;
          email_verified?: boolean;
          name?: string;
        } = {
          sub: user.id,
        };

        if (grantedScopes.has('email')) {
          if (typeof user.email === 'string' && user.email.length > 0) {
            responseBody.email = user.email;
          }
          if (typeof user.emailVerified === 'boolean') {
            responseBody.email_verified = user.emailVerified;
          }
        }

        // OIDC Core §5.1 `name` — the end-user display name, derived from the
        // stored first/last name parts. Released only under the `profile` scope;
        // omitted when neither part is set, keeping the claim set consistent
        // with the ID token.
        if (grantedScopes.has('profile')) {
          const nameParts = [user.firstName, user.lastName].filter(
            (p): p is string => typeof p === 'string' && p.trim().length > 0
          );
          if (nameParts.length > 0) {
            responseBody.name = nameParts.join(' ');
          }
        }

        await fastify.repositories.auditLogs.create({
          userId: user.id,
          oauthClientId: null,
          event: 'oauth.userinfo.success',
          eventType: 'token',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {},
        });

        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.USERINFO);

        return reply.send(responseBody);
      } catch (error) {
        await fastify.repositories.auditLogs.create({
          userId: userId,
          oauthClientId: null,
          event: 'oauth.userinfo.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });

        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.USERINFO);

        throw error;
      }
    }
  );
}
