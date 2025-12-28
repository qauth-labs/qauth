import * as dotenv from 'dotenv';
import { z } from 'zod';

/**
 * Parse and validate environment variables against a Zod schema
 *
 * This function:
 * 1. Loads environment variables from .env file using dotenv
 * 2. Validates process.env against the provided Zod schema
 * 3. Returns a type-safe configuration object
 *
 * @param schema - Zod schema to validate against
 * @returns Parsed and validated environment configuration
 * @throws ZodError if validation fails
 *
 * @example
 * ```typescript
 * import { baseEnvSchema, databaseEnvSchema, parseEnv } from '@qauth/config';
 *
 * const envSchema = baseEnvSchema.merge(databaseEnvSchema);
 * const env = parseEnv(envSchema);
 * // env is typed as BaseEnv & DatabaseEnv
 * ```
 */
export function parseEnv<T extends z.ZodTypeAny>(schema: T): z.infer<T> {
  // Load environment variables from .env file
  dotenv.config();

  // Parse and validate against the schema
  return schema.parse(process.env);
}
