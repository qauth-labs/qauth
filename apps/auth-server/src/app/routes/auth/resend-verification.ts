import {
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
} from '@qauth-labs/fastify-plugin-federation';
import { TooManyRequestsError } from '@qauth-labs/shared-errors';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import {
  ERROR_MESSAGES,
  MIN_RESPONSE_TIME_MS,
  REDIS_KEYS,
  SUCCESS_MESSAGES,
} from '../../constants';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { realmMailLink } from '../../helpers/realm-url';
import { requestRealm } from '../../helpers/request-realm';
import {
  type ResendVerificationRequest,
  resendVerificationResponseSchema,
  resendVerificationSchema,
} from '../../schemas/auth';

/**
 * Resend verification email route
 * Allows users to request a new verification email
 *
 * Security considerations:
 * - Per-IP rate limiting (RESEND_VERIFICATION_RATE_LIMIT) prevents DDoS attacks
 * - Per-email rate limiting (RESEND_VERIFICATION_EMAIL_LIMIT) prevents inbox bombing
 * - Minimum interval (RESEND_VERIFICATION_MIN_INTERVAL) prevents rapid requests
 * - Atomic Redis INCR / SET NX prevent race conditions in rate limiting
 * - TTL set only on first request to prevent sliding window bypass
 * - Rate limit counters increment for ALL requests (even non-existent users)
 *   to prevent email enumeration via timing/behavior differences
 * - Fixed minimum response time prevents timing-based email enumeration
 * - Mail delivery runs off the request path: the floor only pads up, so a
 *   delivery awaited in the one branch that sends would show in the response
 *   time. Sends still in flight are awaited when the server closes.
 * - Always returns success message to prevent email enumeration
 * - Tokens are hashed (SHA-256) before storage
 * - Optional token invalidation (EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND)
 */
export default async function (fastify: FastifyInstance) {
  // Verification mails still being delivered. The request does not wait for
  // them; the server does when it closes, so a shutdown does not drop a mail
  // that a request has already answered for.
  const pendingSends = new Set<Promise<void>>();
  fastify.addHook('onClose', async () => {
    await Promise.allSettled(pendingSends);
  });

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/resend-verification',
    {
      schema: {
        description:
          'Request a new verification email. Rate limited per IP and per email. Always returns success to prevent email enumeration.',
        tags: ['Auth'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        body: resendVerificationSchema,
        response: {
          200: resendVerificationResponseSchema,
        },
      },
      config: {
        surface: 'api',
        rateLimit: {
          max: env.RESEND_VERIFICATION_RATE_LIMIT,
          timeWindow: env.RESEND_VERIFICATION_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request) => {
      const startTime = Date.now();
      const { email } = request.body as ResendVerificationRequest;

      // Email is already validated by Zod schema, just normalize it
      const normalizedEmail = normalizeEmail(email);

      // The realm of the host the request named (#487): the account the
      // address names, and the allowance it is counted against, are this
      // realm's (#489).
      const realm = requestRealm(request);

      // Per-email rate limiting using atomic INCR
      // This counter is incremented for ALL requests (even if user doesn't exist)
      // to prevent email enumeration via rate limit behavior differences
      const emailRateLimitKey = REDIS_KEYS.RESEND_RATE_LIMIT(realm.id, normalizedEmail);

      // INCR is atomic - returns unique incrementing value per request
      // TTL is set only on first request (count=1) to ensure window doesn't reset
      // Note: If EXPIRE fails after INCR=1, key will persist without TTL.
      // This is acceptable as it's a conservative failure (blocks more, not less)
      const emailRateLimitCount = await fastify.redis.incr(emailRateLimitKey);

      if (emailRateLimitCount === 1) {
        // Set TTL only on first request to prevent window reset on subsequent requests
        await fastify.redis.expire(emailRateLimitKey, env.RESEND_VERIFICATION_EMAIL_WINDOW);
      }

      if (emailRateLimitCount > env.RESEND_VERIFICATION_EMAIL_LIMIT) {
        throw new TooManyRequestsError(ERROR_MESSAGES.RATE_LIMIT_EXCEEDED);
      }

      // Minimum interval between sends to the same email, claimed with one
      // atomic SET NX: of any number of concurrent requests exactly one gets
      // 'OK'. It is claimed for ALL requests and BEFORE the credential lookup,
      // so the moment the marker appears does not depend on whether the
      // address has an account. (A GET here and a SET after the send let a
      // quick second request read account existence from 200 vs 429.) The
      // key's TTL is the interval.
      const intervalClaimed = await fastify.redis.set(
        REDIS_KEYS.LAST_EMAIL_SENT(realm.id, normalizedEmail),
        Date.now().toString(),
        'EX',
        env.RESEND_VERIFICATION_MIN_INTERVAL,
        'NX'
      );
      if (intervalClaimed !== 'OK') {
        throw new TooManyRequestsError(ERROR_MESSAGES.RATE_LIMIT_EXCEEDED);
      }

      // Find the password credential (don't expose if not found — prevent
      // enumeration). Since #228 this is the credential read path; malformed
      // credential_data is operator-alerting corruption and behaves exactly
      // like an unknown email on the wire (generic 200).
      const credential = await fastify.repositories.userCredentials.findByRealmProviderSub(
        realm.id,
        PASSWORD_PROVIDER_TYPE,
        normalizedEmail
      );
      const parsed = credential
        ? passwordCredentialDataSchema.safeParse(credential.credentialData)
        : undefined;
      if (credential && parsed && !parsed.success) {
        fastify.log.error(
          { credentialId: credential.id },
          'malformed credential_data on password credential'
        );
      }
      // The users row is read for `enabled` only (the address comes from the
      // credential since #230). A disabled account behaves like an unknown
      // address: generic 200, no token, no mail.
      const user = credential
        ? await fastify.repositories.users.findById(realm.id, credential.userId)
        : undefined;
      if (credential && !user) {
        fastify.log.error(
          { credentialId: credential.id },
          'password credential without a users row'
        );
      }
      // If the credential exists, its account is enabled and its email is not
      // verified, send the mail. The credential's external_sub IS the
      // registered normalized address.
      if (credential && parsed?.success && !parsed.data.email_verified && user?.enabled) {
        // Invalidate existing tokens if config is enabled (credential-keyed
        // since #230 — user_id no longer exists on the tokens table).
        if (env.EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND) {
          await fastify.repositories.emailVerificationTokens.invalidateCredentialTokens(
            credential.id
          );
        }

        // Generate new verification token
        const { token, tokenHash } =
          fastify.emailVerificationTokenUtils.generateVerificationToken();

        // Calculate expiration time
        const expiresAt = Date.now() + env.EMAIL_VERIFICATION_TOKEN_EXPIRY * 1000;

        // Store token hash in database
        await fastify.repositories.emailVerificationTokens.create({
          credentialId: credential.id,
          tokenHash,
          expiresAt,
          used: false,
        });

        // Send the verification email WITHOUT waiting for it. Only this branch
        // sends, so a delivery slower than the response floor would tell a
        // registered, unverified address from any other one. A failure is
        // logged and does not fail the request: the user can try again later.
        const recipient = credential.externalSub;
        const send: Promise<void> = Promise.resolve()
          .then(() =>
            fastify.emailService.sendVerificationEmail(recipient, token, realmMailLink(realm))
          )
          .then(
            () => undefined,
            (error: unknown) => {
              fastify.log.error(error, 'Failed to send verification email');
            }
          )
          .finally(() => {
            pendingSends.delete(send);
          });
        pendingSends.add(send);
      }
      // If user doesn't exist or email is already verified, still return success
      // This prevents email enumeration attacks

      // Enforce minimum response time to prevent timing-based email enumeration
      // This ensures consistent response time regardless of whether user exists
      const elapsed = Date.now() - startTime;
      if (elapsed < MIN_RESPONSE_TIME_MS.RESEND_VERIFICATION) {
        await new Promise((resolve) =>
          setTimeout(resolve, MIN_RESPONSE_TIME_MS.RESEND_VERIFICATION - elapsed)
        );
      }

      // Always return success with generic message (prevent email enumeration)
      return {
        message: SUCCESS_MESSAGES.RESEND_VERIFICATION,
      };
    }
  );
}
