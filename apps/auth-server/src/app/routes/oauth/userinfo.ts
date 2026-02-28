import { JWTInvalidError, NotFoundError } from '@qauth/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

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
        response: {
          200: userinfoResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const payload = request.jwtPayload;

      if (!payload || !payload.sub) {
        throw new JWTInvalidError('Missing JWT payload');
      }

      const user = await fastify.repositories.users.findById(payload.sub);

      if (!user) {
        throw new NotFoundError('User', payload.sub);
      }

      return reply.send({
        sub: user.id,
        email: user.email,
        email_verified: user.emailVerified,
      });
    }
  );
}
