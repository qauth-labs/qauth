import { InvalidCredentialsError } from '@qauth/shared-errors';
import { normalizeEmail } from '@qauth/shared-validation';
import { randomUUID } from 'crypto';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { getOrCreateSystemClient } from '../../helpers/oauth-client';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { loginResponseSchema, loginSchema } from '../../schemas/auth';

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
      const { email, password } = request.body;

      try {
        // Normalize email
        const normalizedEmail = normalizeEmail(email);

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
          // Ensure minimum response time to prevent timing attacks
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);

          // Log failed login attempt
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
        });

        // Generate refresh token using JWT plugin
        const { token: refreshToken, tokenHash: refreshTokenHash } =
          fastify.jwtUtils.generateRefreshToken();

        // Calculate expiration times
        const accessTokenExpiresIn = fastify.jwtUtils.getAccessTokenLifespan();
        const refreshTokenExpiresAt = new Date(
          Date.now() + fastify.jwtUtils.getRefreshTokenLifespan() * 1000
        );

        // Store refresh token in database (hashed)
        await fastify.repositories.refreshTokens.create({
          userId: user.id,
          oauthClientId: systemClient.id,
          tokenHash: refreshTokenHash,
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

        // Return tokens
        return reply.send({
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: accessTokenExpiresIn,
          token_type: 'Bearer' as const,
        });
      } catch (error) {
        // If error is already an InvalidCredentialsError, delay and logging were already handled
        // Simply re-throw the error without additional processing
        if (error instanceof InvalidCredentialsError) {
          throw error;
        }

        // Log other errors as failed login attempts
        const normalizedEmail = normalizeEmail(email);

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
