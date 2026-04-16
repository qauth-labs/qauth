import { createPasswordHasher, type PasswordHasher } from '@qauth-labs/server-password';
import { createPasswordValidator, type PasswordValidator } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type { PasswordPluginOptions } from '../types';

declare module 'fastify' {
  interface FastifyInstance {
    passwordHasher: PasswordHasher;
    passwordValidator: PasswordValidator;
  }
}

/**
 * Fastify plugin for password hashing and validation
 * Decorates fastify instance with passwordHasher and passwordValidator
 *
 * @example
 * ```typescript
 * await fastify.register(passwordPlugin, {
 *   hashConfig: {
 *     memoryCost: 65536,
 *     timeCost: 3,
 *     parallelism: 4,
 *   },
 *   validationConfig: {
 *     minScore: 2,
 *   },
 * });
 *
 * // Use in routes
 * const isValid = fastify.passwordValidator.validatePasswordStrength(password);
 * const hash = await fastify.passwordHasher.hashPassword(password);
 * ```
 */
export const passwordPlugin = fp<PasswordPluginOptions>(
  async (fastify: FastifyInstance, options: PasswordPluginOptions) => {
    const passwordHasher = createPasswordHasher(options.hashConfig);
    const passwordValidator = createPasswordValidator(options.validationConfig);

    fastify.decorate('passwordHasher', passwordHasher);
    fastify.decorate('passwordValidator', passwordValidator);

    fastify.log.debug('Password plugin registered');
  },
  {
    name: packageJson.name,
  }
);
