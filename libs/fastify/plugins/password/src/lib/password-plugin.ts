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
     * The one password policy's validators (#528, #634, ADR-017 Decision 8):
     * `forPolicy({ minLength, minScore })` for the policy of the realm the
     * password is chosen in, built once per policy and kept. No policy is
     * fixed at registration, since each realm sets its own. Every route that
     * stores a new password checks it here and hashes the NFC form it
     * returns.
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
 * // Use in routes, with the realm's policy (`password.minLength`, `password.minScore`)
 * const result = fastify.passwordValidators.forPolicy({ minLength, minScore }).check(password, { email });
 * if (result.valid) {
 *   const hash = await fastify.passwordHasher.hashPassword(result.password);
 * }
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
