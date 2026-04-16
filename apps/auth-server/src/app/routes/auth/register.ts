import { BadRequestError, WeakPasswordError } from '@qauth-labs/shared-errors';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { type RegisterRequest, registerResponseSchema, registerSchema } from '../../schemas/auth';

/**
 * Registration route
 * Types are automatically inferred from registerSchema and registerResponseSchema
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/register',
    {
      schema: {
        description:
          'Register a new user account. Creates user, sends verification email, and returns user data. Password must meet strength requirements.',
        tags: ['Auth'],
        body: registerSchema,
        response: {
          201: registerResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.REGISTRATION_RATE_LIMIT,
          timeWindow: env.REGISTRATION_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const { email, password, realmId } = request.body as RegisterRequest;

      // Email is already validated by Zod schema, just normalize it
      const normalizedEmail = normalizeEmail(email);

      // Validate password strength using injected validator
      const passwordStrength = fastify.passwordValidator.validatePasswordStrength(password);
      if (!passwordStrength.valid) {
        throw new WeakPasswordError(
          'Password does not meet strength requirements',
          passwordStrength.feedback
        );
      }

      // Get or create default realm
      let realm;
      if (realmId) {
        realm = await fastify.repositories.realms.findById(realmId);
        if (!realm) {
          throw new BadRequestError(`Invalid realmId: ${realmId}`);
        }
        if (!realm.enabled) {
          throw new BadRequestError(`Realm ${realmId} is disabled`);
        }
      } else {
        realm = await getOrCreateDefaultRealm(fastify);
      }

      // Hash password using injected hasher
      const passwordHash = await fastify.passwordHasher.hashPassword(password);

      // Create user (database unique constraint prevents race conditions)
      // UniqueConstraintError will be handled by error handler with constraint information
      const user = await fastify.repositories.users.create({
        email: normalizedEmail,
        emailNormalized: normalizedEmail,
        passwordHash,
        realmId: realm.id,
        emailVerified: false,
      });

      // Generate verification token pair (token + tokenHash)
      const { token, tokenHash } = fastify.emailVerificationTokenUtils.generateVerificationToken();

      // Calculate expiration time
      const expiresAt = Date.now() + env.EMAIL_VERIFICATION_TOKEN_EXPIRY * 1000;

      // Store tokenHash in database (NOT plain token)
      await fastify.repositories.emailVerificationTokens.create({
        userId: user.id,
        tokenHash,
        expiresAt,
        used: false,
      });

      // Send verification email (don't fail registration if this fails)
      try {
        await fastify.emailService.sendVerificationEmail(user.email, token);
        fastify.log.info({ userId: user.id, email: user.email }, 'Verification email sent');
      } catch (error) {
        fastify.log.error(
          { err: error, userId: user.id, email: user.email },
          'Failed to send verification email during registration'
        );
        // Don't throw - registration succeeded, user can request resend
      }

      // Return user data without password_hash
      // Type is automatically inferred from registerResponseSchema
      return reply.code(201).send({
        id: user.id,
        email: user.email,
        emailVerified: user.emailVerified,
        realmId: user.realmId,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      });
    }
  );
}
