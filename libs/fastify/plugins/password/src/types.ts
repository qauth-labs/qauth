import type { PasswordHashConfig } from '@qauth-labs/server-password';
import type { FastifyPluginOptions } from 'fastify';

/**
 * Password plugin configuration options
 *
 * No password strength setting: the lowest score is each realm's
 * (`password.minScore`, #528), passed to `passwordValidators.forMinScore`
 * where a password is chosen.
 */
export interface PasswordPluginOptions extends FastifyPluginOptions {
  /** Configuration for password hashing (Argon2) - optional, missing values will use defaults */
  hashConfig?: Partial<PasswordHashConfig>;
}
