import type { PasswordHashConfig } from '@qauth-labs/server-password';
import type { FastifyPluginOptions } from 'fastify';

/**
 * Password plugin configuration options
 *
 * No password policy setting: the minimum length and lowest score are each
 * realm's (`password.minLength`, `password.minScore`, #528, #634), passed to
 * `passwordValidators.forPolicy` where a password is chosen.
 */
export interface PasswordPluginOptions extends FastifyPluginOptions {
  /** Configuration for password hashing (Argon2) - optional, missing values will use defaults */
  hashConfig?: Partial<PasswordHashConfig>;
}
