import {
  EmailAlreadyVerifiedError,
  InvalidTokenError,
  NotFoundError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { type VerifyQuery, verifyQuerySchema, verifyResponseSchema } from '../../schemas/auth';

/**
 * Email verification route
 * Verifies user email addresses using tokens sent via email
 *
 * Security considerations:
 * - Token is hashed (SHA-256) before database lookup
 * - Generic error messages prevent token enumeration
 * - Rate limiting prevents brute-force attacks (10 req/15 min per IP)
 * - 256-bit random tokens make guessing infeasible (2^256 combinations)
 * - Single-use tokens prevent replay attacks
 *
 * Note on timing attacks: Database index lookups have consistent timing.
 * Combined with rate limiting and high-entropy tokens, timing-based
 * enumeration is not a practical attack vector for this endpoint.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/verify',
    {
      schema: {
        description:
          'Verify email address using token sent via email. Single-use; marks token as used. Returns success message.',
        tags: ['Auth'],
        querystring: verifyQuerySchema,
        response: {
          200: verifyResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.VERIFICATION_RATE_LIMIT,
          timeWindow: env.VERIFICATION_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request) => {
      const { token } = request.query as VerifyQuery;

      // Token format already validated by Zod schema (64-char hex string)
      // This prevents CVE-2025-12374 style attacks at schema level

      // 1. Hash token before database lookup
      const tokenHash = fastify.emailVerificationTokenUtils.hashToken(token);

      // 2. Find token in database (returns undefined if not found, expired, or used)
      const verificationToken =
        await fastify.repositories.emailVerificationTokens.findByTokenHash(tokenHash);

      if (!verificationToken) {
        // Generic error to prevent token enumeration (security: don't reveal why it failed)
        throw new InvalidTokenError('Invalid or expired token');
      }

      // 3. Get user by verificationToken.userId
      const user = await fastify.repositories.users.findById(verificationToken.userId);
      if (!user) {
        throw new NotFoundError('User', verificationToken.userId);
      }

      // 4. Check if email already verified
      if (user.emailVerified) {
        throw new EmailAlreadyVerifiedError();
      }

      // 5. Mark token as used (prevents reuse)
      await fastify.repositories.emailVerificationTokens.markUsed(verificationToken.id);

      // 6. Verify user email
      await fastify.repositories.users.verifyEmail(user.id);

      // 7. Return success response
      return {
        message: 'Email verified successfully',
        email: user.email,
      };
    }
  );
}
