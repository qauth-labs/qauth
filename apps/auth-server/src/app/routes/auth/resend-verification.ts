import { generateVerificationToken } from '@qauth/server-email';
import { TooManyRequestsError } from '@qauth/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { ERROR_MESSAGES, REDIS_KEYS, SUCCESS_MESSAGES } from '../../constants';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { resendVerificationResponseSchema, resendVerificationSchema } from '../../schemas/auth';
import { errorResponseSchema } from '../../schemas/common';

/** Minimum response time in milliseconds to prevent timing attacks */
const MIN_RESPONSE_TIME_MS = 200;

/**
 * Resend verification email route
 * Allows users to request a new verification email
 *
 * Security considerations:
 * - Per-IP rate limiting (RESEND_VERIFICATION_RATE_LIMIT) prevents DDoS attacks
 * - Per-email rate limiting (RESEND_VERIFICATION_EMAIL_LIMIT) prevents inbox bombing
 * - Minimum interval (RESEND_VERIFICATION_MIN_INTERVAL) prevents rapid requests
 * - Atomic Redis operations prevent race conditions in rate limiting
 * - Rate limit counters increment for ALL requests (even non-existent users)
 *   to prevent email enumeration via timing/behavior differences
 * - Fixed minimum response time prevents timing-based email enumeration
 * - Always returns success message to prevent email enumeration
 * - Tokens are hashed (SHA-256) before storage
 * - Optional token invalidation (EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND)
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/auth/resend-verification',
    {
      schema: {
        body: resendVerificationSchema,
        response: {
          200: resendVerificationResponseSchema,
          429: errorResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.RESEND_VERIFICATION_RATE_LIMIT,
          timeWindow: env.RESEND_VERIFICATION_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request) => {
      const startTime = Date.now();
      const { email } = request.body;

      // Email is already validated by Zod schema, just normalize it
      const normalizedEmail = email.toLowerCase().trim();

      // Per-email rate limiting using atomic INCR + EXPIRE to prevent race conditions
      // This counter is incremented for ALL requests (even if user doesn't exist)
      // to prevent email enumeration via rate limit behavior differences
      const emailRateLimitKey = REDIS_KEYS.RESEND_RATE_LIMIT(normalizedEmail);

      // Atomic increment and expire using Redis multi to prevent TTL race condition
      const results = await fastify.redis
        .multi()
        .incr(emailRateLimitKey)
        .expire(emailRateLimitKey, env.RESEND_VERIFICATION_EMAIL_WINDOW)
        .exec();

      // Get the count from multi result: [[null, count], [null, 1]]
      const emailRateLimitCount = results?.[0]?.[1] as number;

      if (emailRateLimitCount > env.RESEND_VERIFICATION_EMAIL_LIMIT) {
        throw new TooManyRequestsError(ERROR_MESSAGES.RATE_LIMIT_EXCEEDED);
      }

      // Minimum interval check between sends to same email
      const lastSentKey = REDIS_KEYS.LAST_EMAIL_SENT(normalizedEmail);
      const lastSent = await fastify.redis.get(lastSentKey);

      if (lastSent) {
        const timeSinceLastSent = Date.now() - parseInt(lastSent, 10);
        if (timeSinceLastSent < env.RESEND_VERIFICATION_MIN_INTERVAL * 1000) {
          throw new TooManyRequestsError(ERROR_MESSAGES.RATE_LIMIT_EXCEEDED);
        }
      }

      // Get default realm for user lookup
      const realm = await getOrCreateDefaultRealm(fastify);

      // Find user by email (don't expose if not found - prevent enumeration)
      // Note: findByEmail internally normalizes email, but we already have it normalized
      const user = await fastify.repositories.users.findByEmail(realm.id, normalizedEmail);

      // If user exists and email is not verified, send verification email
      if (user && !user.emailVerified) {
        // Invalidate existing tokens if config is enabled
        if (env.EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND) {
          await fastify.repositories.emailVerificationTokens.invalidateUserTokens(user.id);
        }

        // Generate new verification token
        const { token, tokenHash } = generateVerificationToken();

        // Calculate expiration time
        const expiresAt = Date.now() + env.EMAIL_VERIFICATION_TOKEN_EXPIRY * 1000;

        // Store token hash in database
        await fastify.repositories.emailVerificationTokens.create({
          userId: user.id,
          tokenHash,
          expiresAt,
          used: false,
        });

        // Send verification email (don't fail if email send fails)
        try {
          await fastify.emailService.sendVerificationEmail(user.email, token);
        } catch (error) {
          fastify.log.error(error, 'Failed to send verification email');
          // Don't fail the request - user can try again later
        }
      }
      // If user doesn't exist or email is already verified, still return success
      // This prevents email enumeration attacks

      // Update last sent timestamp for minimum interval check
      await fastify.redis.set(
        lastSentKey,
        Date.now().toString(),
        'EX',
        env.RESEND_VERIFICATION_MIN_INTERVAL
      );

      // Enforce minimum response time to prevent timing-based email enumeration
      // This ensures consistent response time regardless of whether user exists
      const elapsed = Date.now() - startTime;
      if (elapsed < MIN_RESPONSE_TIME_MS) {
        await new Promise((resolve) => setTimeout(resolve, MIN_RESPONSE_TIME_MS - elapsed));
      }

      // Always return success with generic message (prevent email enumeration)
      return {
        message: SUCCESS_MESSAGES.RESEND_VERIFICATION,
      };
    }
  );
}
