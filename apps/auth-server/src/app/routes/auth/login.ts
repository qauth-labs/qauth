import { InvalidCredentialsError, TooManyRequestsError } from '@qauth-labs/shared-errors';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import { randomUUID } from 'crypto';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { hashEmail, logAuthEvent } from '../../helpers/auth-events';
import { resolveAudience } from '../../helpers/client-auth';
import { checkLockout, recordFailedAttempt, resetFailedAttempts } from '../../helpers/failed-login';
import { getOrCreateSystemClient } from '../../helpers/oauth-client';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { type LoginRequest, loginResponseSchema, loginSchema } from '../../schemas/auth';

/**
 * Login route
 * Handles user authentication with password verification, JWT generation,
 * refresh token storage, session management, and audit logging
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/login',
    {
      schema: {
        description:
          'Authenticate with email and password. Returns access token, refresh token, and expiration. Requires valid credentials.',
        tags: ['Auth'],
        body: loginSchema,
        response: {
          200: loginResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.LOGIN_RATE_LIMIT,
          timeWindow: env.LOGIN_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const { email, password } = request.body as LoginRequest;

      // Normalize email up front so it is available to lockout tracking and
      // structured logging on every code path (#115, #124, #125).
      const normalizedEmail = normalizeEmail(email);
      // Identifiers tracked for failed-login throttling (#115): the email is
      // hashed so the cache never stores raw addresses, plus the source IP.
      const emailHash = hashEmail(normalizedEmail);
      const lockoutIdentifiers = [`email:${emailHash}`, `ip:${request.ip}`];

      try {
        // Reject early if this identifier is currently locked out (#115).
        const lockout = await checkLockout(fastify.redis, lockoutIdentifiers);
        if (lockout.locked) {
          fastify.metrics.loginAttempts.inc({ result: 'failure', reason: 'locked_out' });
          logAuthEvent(request, 'user.login.failure', false, {
            emailHash,
            reason: 'locked_out',
          });
          if (lockout.retryAfterSeconds !== undefined) {
            reply.header('Retry-After', String(lockout.retryAfterSeconds));
          }
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);
          throw new TooManyRequestsError('Too many failed login attempts. Please try again later.');
        }

        // Get default realm
        const realm = await getOrCreateDefaultRealm(fastify);

        // Find user by email (realm scoped)
        const user = await fastify.repositories.users.findByEmail(realm.id, normalizedEmail);

        // Verify password (always perform verification to prevent timing attacks)
        let passwordValid = false;
        if (user) {
          passwordValid = await fastify.passwordHasher.verifyPassword(user.passwordHash, password);
        }

        // Check email verified (optional for MVP - can be configurable)
        // For MVP, we allow unverified logins, but this can be enabled later
        // if (user && passwordValid && !user.emailVerified) {
        //   throw new EmailNotVerifiedError('Email address not verified');
        // }

        // If credentials are invalid, throw generic error
        if (!user || !passwordValid) {
          // Record the failed attempt for throttling/lockout (#115).
          await recordFailedAttempt(fastify.redis, lockoutIdentifiers);

          // Structured log of the failed login (#125): IP + email *hash* only,
          // never the password or the raw email.
          fastify.metrics.loginAttempts.inc({ result: 'failure', reason: 'invalid_credentials' });
          logAuthEvent(request, 'user.login.failure', false, {
            emailHash,
            reason: 'invalid_credentials',
          });

          // Ensure minimum response time to prevent timing attacks
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);

          // Log failed login attempt (DB audit trail)
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: null,
            event: 'user.login.failure',
            eventType: 'auth',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: {
              email: normalizedEmail,
              error: 'Invalid credentials',
            },
          });

          throw new InvalidCredentialsError('Invalid email or password');
        }

        // Get or create system OAuth client
        const systemClient = await getOrCreateSystemClient(realm.id, fastify);

        // Generate access token (JWT) using JWT plugin
        const accessToken = await fastify.jwtUtils.signAccessToken({
          sub: user.id,
          email: user.email,
          email_verified: user.emailVerified,
          clientId: systemClient.clientId,
          aud: resolveAudience(systemClient),
        });

        // Generate refresh token using JWT plugin
        const { token: refreshToken, tokenHash: refreshTokenHash } =
          fastify.jwtUtils.generateRefreshToken();

        // Calculate expiration times
        const accessTokenExpiresIn = fastify.jwtUtils.getAccessTokenLifespan();
        const refreshTokenExpiresAt = new Date(
          Date.now() + fastify.jwtUtils.getRefreshTokenLifespan() * 1000
        );

        // Store refresh token in database (hashed). Each login starts a
        // new refresh-token family — every rotation at /oauth/token
        // inherits this `familyId` for replay-detection revocation.
        await fastify.repositories.refreshTokens.create({
          userId: user.id,
          oauthClientId: systemClient.id,
          tokenHash: refreshTokenHash,
          familyId: randomUUID(),
          expiresAt: refreshTokenExpiresAt.getTime(),
          scopes: [],
        });

        // Create session ID
        const sessionId = randomUUID();

        // Store session in Redis
        await fastify.sessionUtils.setSession(
          sessionId,
          {
            userId: user.id,
            email: user.email,
            sessionId,
            createdAt: Date.now(),
          },
          accessTokenExpiresIn
        );

        // Log audit event (success)
        await fastify.repositories.auditLogs.create({
          userId: user.id,
          oauthClientId: systemClient.id,
          event: 'user.login.success',
          eventType: 'auth',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            sessionId,
          },
        });

        // Update user lastLoginAt timestamp
        await fastify.repositories.users.updateLastLogin(user.id);

        // Successful login: clear failed-attempt counters/lockout (#115) and
        // emit structured success log + metrics (#123, #124, #126).
        await resetFailedAttempts(fastify.redis, lockoutIdentifiers);
        fastify.metrics.loginAttempts.inc({ result: 'success' });
        fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'password' });
        fastify.metrics.tokensIssued.inc({ type: 'refresh', grant_type: 'password' });
        logAuthEvent(request, 'user.login.success', true, {
          userId: user.id,
          clientId: systemClient.clientId,
          email: user.email,
        });

        // RFC 6749 §5.1: token responses MUST NOT be cached by intermediaries.
        reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');

        // Return tokens
        return reply.send({
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: accessTokenExpiresIn,
          token_type: 'Bearer' as const,
        });
      } catch (error) {
        // InvalidCredentialsError (delay/logging already handled above) and
        // TooManyRequestsError (lockout, handled above) are re-thrown as-is.
        if (error instanceof InvalidCredentialsError || error instanceof TooManyRequestsError) {
          throw error;
        }

        // Log other errors as failed login attempts (structured + DB audit).
        fastify.metrics.loginAttempts.inc({ result: 'failure', reason: 'error' });
        logAuthEvent(request, 'user.login.failure', false, {
          emailHash,
          reason: 'error',
        });

        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'user.login.failure',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            email: normalizedEmail,
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });

        // Ensure minimum response time even on errors
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);

        throw error;
      }
    }
  );
}
