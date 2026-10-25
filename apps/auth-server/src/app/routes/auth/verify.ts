import {
  EMAIL_ATTR_KEY,
  passwordCredentialDataSchema,
  SELF_REPORTED_SOURCE,
} from '@qauth-labs/fastify-plugin-federation';
import {
  EmailAlreadyVerifiedError,
  InvalidCredentialsError,
  InvalidTokenError,
  TooManyRequestsError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { hashEmail } from '../../helpers/auth-events';
import { clientAddressKey } from '../../helpers/client-address';
import { recordSuccessfulLogin, registerLoginAttempt } from '../../helpers/failed-login';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { type VerifyBody, verifyBodySchema, verifyResponseSchema } from '../../schemas/auth';

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
 *
 * POST, never GET. Verifying is a state change with consequences: it marks
 * the credential's email as verified, and relying parties may link accounts
 * by verified email. A GET verified on any fetch of the emailed link — a mail
 * gateway's link scanner, a browser prefetch, or a page that calls the API as
 * it loads — so an account someone else registered with this address, and
 * whose password they hold, could be verified without the mailbox owner ever
 * choosing to. The token travels in the body, and the portal's /verify page
 * calls this only when the reader presses its confirm button.
 *
 * Token AND password. The token proves control of the mailbox; it cannot say
 * who registered. Someone who registers with another person's address holds
 * the password, and the mailbox owner holds the token; a confirm button alone
 * would let the owner verify the other person's account by clicking it. So the
 * request must also carry the account's password, checked against the
 * credential the token targets: only a person who has both the mailbox and the
 * password (the genuine registrant) can verify. A wrong password consumes
 * nothing, so the registrant can retry within the token's lifetime.
 *
 * The token must not become a password oracle, though: the per-IP rate limit
 * above caps guesses per address, not per account. So the password check sits
 * under the failed-login lockout (#115) with the SAME identifiers as
 * POST /auth/login and POST /ui/login: wrong passwords here count against the
 * account, and an account locked on either login route is locked here too.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/verify',
    {
      schema: {
        description:
          'Verify email address using the token sent via email, in the request body. Single-use; marks token as used. POST so no link fetch or prefetch can verify an address on its own.',
        tags: ['Auth'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 409],
        body: verifyBodySchema,
        response: {
          200: verifyResponseSchema,
        },
      },
      config: {
        surface: 'api',
        rateLimit: {
          max: env.VERIFICATION_RATE_LIMIT,
          timeWindow: env.VERIFICATION_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const { token, password } = request.body as VerifyBody;

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
      // ADR-002). credential_id is NOT NULL since #230, so the lookup is
      // unconditional; a genuinely missing credential fails closed with the
      // generic token error (no enumeration signal).
      const credential = await fastify.repositories.userCredentials.findById(
        verificationToken.credentialId
      );
      if (!credential) {
        throw new InvalidTokenError('Invalid or expired token');
      }

      // 3b. A disabled account must not change its verified state or have its
      // password checked: same generic token error, and the token is left
      // unconsumed so it still works if the operator enables the account again.
      const user = await fastify.repositories.users.findById(credential.userId);
      if (!user || !user.enabled) {
        throw new InvalidTokenError('Invalid or expired token');
      }

      // 4. Check if email already verified — credential_data is the sole
      // authoritative source (the legacy users.email_verified dual-write
      // ended with #230). Malformed credential_data is operator-alerting
      // data corruption; the wire stays the generic token error.
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

      // 4b. The registrant, not just the mailbox (see the route comment). Checked
      // BEFORE the completion transaction, so a wrong password leaves the token
      // unconsumed and nothing verified.
      //
      // Under the failed-login lockout (#115), keyed as the login routes key
      // it: external_sub IS the normalized registered address (#230), so the
      // email hash matches theirs, the address is the client address key
      // (an IPv6 client by its /64), and the realm is the account's (#487),
      // the realm the login routes count it in. The attempt is counted before
      // the password is compared; a wrong one stays counted.
      const emailIdentifier = `email:${hashEmail(credential.externalSub)}`;
      const lockout = await registerLoginAttempt(fastify.redis, credential.realmId, [
        emailIdentifier,
        `ip:${clientAddressKey(request)}`,
      ]);
      if (lockout.locked) {
        if (lockout.retryAfterSeconds !== undefined) {
          reply.header('Retry-After', String(lockout.retryAfterSeconds));
        }
        throw new TooManyRequestsError('Too many failed attempts. Please try again later.');
      }

      const passwordValid = await fastify.passwordHasher.verifyPassword(
        parsed.data.password_hash,
        password
      );
      if (!passwordValid) {
        throw new InvalidCredentialsError('Incorrect password for this account');
      }
      // The password is proved: settle the attempt as a successful login does.
      await recordSuccessfulLogin(fastify.redis, credential.realmId, lockout, [emailIdentifier]);

      // 5.-6. Completion write set (one transaction): consume the token and
      // flip credential_data.email_verified + the attribute's verified flag —
      // the authoritative verified state since #228 (the legacy users
      // dual-write ended with #230).
      await fastify.db.transaction(async (tx) => {
        // Single-use CAS (#258): losing the race to a concurrent attempt with
        // the same token rolls the whole completion back and surfaces the
        // same generic error as an invalid/expired token — no state leak.
        const consumed = await fastify.repositories.emailVerificationTokens.markUsed(
          verificationToken.id,
          tx
        );
        if (!consumed) {
          throw new InvalidTokenError('Invalid or expired token');
        }
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
      });

      // 7. Return success response. The credential's external_sub IS the
      // registered normalized address (#230: users.email no longer exists).
      return {
        message: 'Email verified successfully',
        email: credential.externalSub,
      };
    }
  );
}
