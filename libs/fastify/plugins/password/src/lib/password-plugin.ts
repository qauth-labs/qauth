import {
  createPasswordHasher,
  type PasswordHashConfig,
  type PasswordHasher,
} from '@qauth/server-password';
import {
  createPasswordValidator,
  type PasswordValidationConfig,
  type PasswordValidator,
} from '@qauth/shared-validation';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    passwordHasher: PasswordHasher;
    passwordValidator: PasswordValidator;
  }
}

/**
 * Password plugin configuration options
 */
export interface PasswordPluginOptions extends FastifyPluginOptions {
  /**
   * Configuration for password hashing (Argon2)
   * Optional - missing values will use defaults
   */
  hashConfig?: Partial<PasswordHashConfig>;
  /**
   * Configuration for password strength validation
   * Optional - missing values will use defaults
   */
  validationConfig?: Partial<PasswordValidationConfig>;
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
    name: '@qauth/fastify-plugin-password',
  }
);
