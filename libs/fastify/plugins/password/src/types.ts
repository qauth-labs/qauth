import type { PasswordHashConfig } from '@qauth/server-password';
import type { PasswordValidationConfig } from '@qauth/shared-validation';
import type { FastifyPluginOptions } from 'fastify';

/**
 * Password plugin configuration options
 */
export interface PasswordPluginOptions extends FastifyPluginOptions {
  /** Configuration for password hashing (Argon2) - optional, missing values will use defaults */
  hashConfig?: Partial<PasswordHashConfig>;
  /** Configuration for password strength validation - optional, missing values will use defaults */
  validationConfig?: Partial<PasswordValidationConfig>;
}
