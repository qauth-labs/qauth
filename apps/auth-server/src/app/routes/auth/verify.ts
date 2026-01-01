import { hashToken, isValidTokenFormat } from '@qauth/server-email';
import {
  EmailAlreadyVerifiedError,
  InvalidTokenError,
  NotFoundError,
  TokenAlreadyUsedError,
  TokenExpiredError,
} from '@qauth/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { verifyQuerySchema, verifyResponseSchema } from '../../schemas/auth';

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
    '/auth/verify',
    {
      schema: {
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
      const { token } = request.query;

      // 1. Validate token format (prevents CVE-2025-12374)
      if (!isValidTokenFormat(token)) {
        throw new InvalidTokenError('Invalid token format');
      }

      // 2. Hash token before database lookup
      const tokenHash = hashToken(token);

      // 3. Find token in database (repository handles expiry and used checks)
      const verificationToken =
        await fastify.repositories.emailVerificationTokens.findByTokenHash(tokenHash);

      if (!verificationToken) {
        // Generic error message to prevent token enumeration (don't expose hash)
        throw new InvalidTokenError('Invalid or expired token');
      }

      // 4. Double-check token expiry (defensive check)
      if (verificationToken.expiresAt < Date.now()) {
        throw new TokenExpiredError();
      }

      // 5. Double-check if token is already used (defensive check for CVE-2025-12421)
      if (verificationToken.used) {
        throw new TokenAlreadyUsedError();
      }

      // 6. Get user by verificationToken.userId
      const user = await fastify.repositories.users.findById(verificationToken.userId);
      if (!user) {
        throw new NotFoundError('User', verificationToken.userId);
      }

      // 7. Check if email already verified
      if (user.emailVerified) {
        throw new EmailAlreadyVerifiedError(user.email);
      }

      // 8. Mark token as used (prevents reuse)
      await fastify.repositories.emailVerificationTokens.markUsed(verificationToken.id);

      // 9. Verify user email
      await fastify.repositories.users.verifyEmail(user.id);

      // 10. Return success response
      return {
        message: 'Email verified successfully',
        email: user.email,
      };
    }
  );
}
