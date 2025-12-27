import { WeakPasswordError } from '@qauth/errors';
import { hashPassword } from '@qauth/password';
import { validateEmail, validatePasswordStrength } from '@qauth/validation';
import type { FastifyInstance } from 'fastify';

import { env } from '../../../config/env';
import { type RegisterRequest, type RegisterResponse, registerSchema } from '../../schemas/auth';

/**
 * Get or create default realm
 */
async function getOrCreateDefaultRealm(fastify: FastifyInstance) {
  const defaultRealmName = env.DEFAULT_REALM_NAME;
  let realm = await fastify.repositories.realms.findByName(defaultRealmName);

  if (!realm) {
    realm = await fastify.repositories.realms.create({
      name: defaultRealmName,
      enabled: true,
    });
  }

  return realm;
}

/**
 * Registration route
 */
export default async function (fastify: FastifyInstance) {
  fastify.post<{ Body: RegisterRequest; Reply: RegisterResponse }>(
    '/auth/register',
    {
      schema: {
        body: registerSchema,
      },
      config: {
        rateLimit: {
          max: env.REGISTRATION_RATE_LIMIT,
          timeWindow: env.REGISTRATION_RATE_WINDOW * 1000,
        },
      },
    },
    async (request, reply) => {
      const { email, password, realmId } = request.body;

      // Validate email format and normalize
      const normalizedEmail = validateEmail(email);

      // Validate password strength
      const passwordStrength = validatePasswordStrength(password);
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
          return reply.badRequest(`Invalid realmId: ${realmId}`);
        }
        if (!realm.enabled) {
          return reply.badRequest(`Realm ${realmId} is disabled`);
        }
      } else {
        realm = await getOrCreateDefaultRealm(fastify);
      }

      // Hash password
      const passwordHash = await hashPassword(password);

      // Create user (database unique constraint prevents race conditions)
      // UniqueConstraintError will be handled by error handler with constraint information
      const user = await fastify.repositories.users.create({
        email: normalizedEmail,
        emailNormalized: normalizedEmail,
        passwordHash,
        realmId: realm.id,
        emailVerified: false,
      });

      // Return user data without password_hash
      const response: RegisterResponse = {
        id: user.id,
        email: user.email,
        emailVerified: user.emailVerified,
        realmId: user.realmId,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      };

      return reply.code(201).send(response);
    }
  );
}
