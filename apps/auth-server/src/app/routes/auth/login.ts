import {
  EmailNotVerifiedError,
  InvalidCredentialsError,
  TooManyRequestsError,
} from '@qauth-labs/shared-errors';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import { randomUUID } from 'crypto';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { hashEmail, logAuthEvent } from '../../helpers/auth-events';
import { resolveAudience } from '../../helpers/client-auth';
import { verifyPasswordCredential } from '../../helpers/credential-auth';
import { resolveEmailClaims } from '../../helpers/email-claims';
import { checkLockout, recordFailedAttempt, resetFailedAttempts } from '../../helpers/failed-login';
import { issueAccessToken } from '../../helpers/hybrid-token';
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

        // Password check via the user_credentials read path (#228): lookup on
        // (realm_id, 'password', external_sub), argon2 against
        // credential_data.password_hash, provider-normalized identity.
        const check = await verifyPasswordCredential(fastify, {
          realmId: realm.id,
          email: normalizedEmail,
          password,
        });

        // Email-verified gate (F-08): config-driven, MVP default is `false`
        // (unverified-email login allowed per PRD "optional for MVP"). An
        // operator who needs a verified-email guarantee flips
        // `REQUIRE_EMAIL_VERIFIED=true`; the login then fails closed with
        // `EmailNotVerifiedError` BEFORE tokens are issued, so the OIDC
        // `email_verified` claim is always trustworthy when that flag is on.
        // Since #228 the gate reads credential_data.email_verified — the
        // authoritative source (the legacy users.email_verified column was
        // dropped in #261).
        if (check.status === 'ok' && !check.emailVerified && env.REQUIRE_EMAIL_VERIFIED) {
          await recordFailedAttempt(fastify.redis, lockoutIdentifiers);
          fastify.metrics.loginAttempts.inc({ result: 'failure', reason: 'email_not_verified' });
          logAuthEvent(request, 'user.login.failure', false, {
            emailHash,
            reason: 'email_not_verified',
          });
          await fastify.repositories.auditLogs.create({
            userId: check.credential.userId,
            oauthClientId: null,
            event: 'user.login.failure',
            eventType: 'auth',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { email: normalizedEmail, error: 'Email address not verified' },
          });
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);
          throw new EmailNotVerifiedError('Email address not verified. Check your inbox.');
        }

        // The users row supplies the stable subject id plus session/audit/log
        // fields; email claims are resolved separately from verified
        // user_attributes (#229). The row must exist for any live credential
        // (FK), so a miss is treated as invalid below.
        const user =
          check.status === 'ok'
            ? await fastify.repositories.users.findById(check.credential.userId)
            : undefined;
        if (check.status === 'ok' && !user) {
          fastify.log.error(
            { credentialId: check.credential.id },
            'password credential without a users row'
          );
        }

        // If credentials are invalid, throw generic error
        if (check.status !== 'ok' || !user) {
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

        // BREAKING (#229, ADR-002): email/email_verified resolve from verified
        // user_attributes via the trust order; both OMITTED when no verified
        // email exists. Post-gate placement keeps failure-path timing intact.
        const emailClaims = await resolveEmailClaims(fastify, user.id);

        // Generate access token (JWT) using JWT plugin
        const accessToken = await issueAccessToken(fastify, {
          sub: user.id,
          ...emailClaims,
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
            // The address the user just authenticated with (#230:
            // users.email no longer exists; external_sub is the normalized
            // registered address of the password credential).
            email: check.credential.externalSub,
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
          email: check.credential.externalSub,
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
