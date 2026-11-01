import { createPasswordHasher, type PasswordHasher } from '@qauth-labs/server-password';
import { createPasswordValidators, type PasswordValidators } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type { PasswordPluginOptions } from '../types';

declare module 'fastify' {
  interface FastifyInstance {
    passwordHasher: PasswordHasher;
    /**
     * Password strength validators by minimum score (#528):
     * `forMinScore(score)` for the lowest score of the realm the password is
     * chosen in, built once per score and kept. No score is fixed at
     * registration, since each realm sets its own.
     */
    passwordValidators: PasswordValidators;
  }
}

/**
 * Fastify plugin for password hashing and validation
 * Decorates fastify instance with passwordHasher and passwordValidators
 *
 * @example
 * ```typescript
 * await fastify.register(passwordPlugin, {
 *   hashConfig: {
 *     memoryCost: 65536,
 *     timeCost: 3,
 *     parallelism: 4,
 *   },
 * });
 *
 * // Use in routes, with the lowest score of the realm (`password.minScore`)
 * const result = fastify.passwordValidators.forMinScore(minScore).validatePasswordStrength(password);
 * const hash = await fastify.passwordHasher.hashPassword(password);
 * ```
 */
export const passwordPlugin = fp<PasswordPluginOptions>(
  async (fastify: FastifyInstance, options: PasswordPluginOptions) => {
    const passwordHasher = createPasswordHasher(options.hashConfig);
    const passwordValidators = createPasswordValidators();

    fastify.decorate('passwordHasher', passwordHasher);
    fastify.decorate('passwordValidators', passwordValidators);

    fastify.log.debug('Password plugin registered');
  },
  {
    name: packageJson.name,
  }
);
