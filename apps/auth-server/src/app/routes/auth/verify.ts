import {
  EMAIL_ATTR_KEY,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  SELF_REPORTED_SOURCE,
} from '@qauth-labs/fastify-plugin-federation';
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

      // 3. Resolve the password credential this token targets (#228,
      // ADR-002). Tokens minted before #228 (or during a rollback window)
      // carry only user_id — fall back to the user's password credential so
      // in-flight verification links keep working. Both paths gone missing is
      // fail-closed: generic InvalidTokenError, no enumeration signal.
      const credential = verificationToken.credentialId
        ? await fastify.repositories.userCredentials.findById(verificationToken.credentialId)
        : await fastify.repositories.userCredentials.findByUserIdAndType(
            verificationToken.userId,
            PASSWORD_PROVIDER_TYPE
          );
      if (!credential) {
        throw new InvalidTokenError('Invalid or expired token');
      }

      const user = await fastify.repositories.users.findById(credential.userId);
      if (!user) {
        throw new NotFoundError('User', credential.userId);
      }

      // 4. Check if email already verified — sourced from credential_data
      // since #228 (kept equal to users.email_verified by the dual-write
      // below). Malformed credential_data is operator-alerting data
      // corruption; the wire stays the generic token error.
      const parsed = passwordCredentialDataSchema.safeParse(credential.credentialData);
      if (!parsed.success) {
        fastify.log.error(
          { credentialId: credential.id },
          'malformed credential_data on password credential'
        );
        throw new InvalidTokenError('Invalid or expired token');
      }
      if (parsed.data.email_verified) {
        throw new EmailAlreadyVerifiedError();
      }

      // 5.-6. Completion write set (one transaction): consume the token, flip
      // credential_data.email_verified + the attribute's verified flag, and
      // dual-write users.email_verified so REQUIRE_EMAIL_VERIFIED, today's
      // JWT claims, and a rolled-back binary all stay truthful (until #230).
      await fastify.db.transaction(async (tx) => {
        await fastify.repositories.emailVerificationTokens.markUsed(verificationToken.id, tx);
        await fastify.repositories.userCredentials.setEmailVerified(credential.id, tx);
        const attribute = await fastify.repositories.userAttributes.setVerified(
          credential.userId,
          SELF_REPORTED_SOURCE,
          EMAIL_ATTR_KEY,
          true,
          tx
        );
        if (!attribute) {
          // Register/backfill guarantee the row; absence is log-worthy data
          // inconsistency but must not fail the user's verification.
          fastify.log.warn(
            { userId: credential.userId },
            'no self_reported email attribute to mark verified'
          );
        }
        await fastify.repositories.users.verifyEmail(credential.userId, tx);
      });

      // 7. Return success response
      return {
        message: 'Email verified successfully',
        email: user.email,
      };
    }
  );
}
