import { hash, verify } from '@node-rs/argon2';

/**
 * Password hashing configuration options
 */
export interface PasswordHashOptions {
  /**
   * Memory cost in KB (default: 65536 = 64MB)
   */
  memoryCost?: number;
  /**
   * Time cost / iterations (default: 3)
   */
  timeCost?: number;
  /**
   * Parallelism / threads (default: 4)
   */
  parallelism?: number;
}

/**
 * Default password hashing configuration
 * These values provide a good balance between security and performance
 */
const DEFAULT_OPTIONS: Required<PasswordHashOptions> = {
  memoryCost: 65536, // 64MB
  timeCost: 3,
  parallelism: 4,
};

/**
 * Get password hashing options from environment variables or use defaults
 */
function getPasswordHashOptions(): Required<PasswordHashOptions> {
  return {
    memoryCost:
      process.env['PASSWORD_MEMORY_COST'] !== undefined
        ? parseInt(process.env['PASSWORD_MEMORY_COST'], 10)
        : DEFAULT_OPTIONS.memoryCost,
    timeCost:
      process.env['PASSWORD_TIME_COST'] !== undefined
        ? parseInt(process.env['PASSWORD_TIME_COST'], 10)
        : DEFAULT_OPTIONS.timeCost,
    parallelism:
      process.env['PASSWORD_PARALLELISM'] !== undefined
        ? parseInt(process.env['PASSWORD_PARALLELISM'], 10)
        : DEFAULT_OPTIONS.parallelism,
  };
}

/**
 * Hash a password using Argon2id
 *
 * @param password - Plain text password to hash
 * @param options - Optional hashing configuration (overrides defaults and env vars)
 * @returns Hashed password string
 * @throws Error if hashing fails
 *
 * @example
 * ```typescript
 * const hashed = await hashPassword('mySecurePassword123');
 * ```
 */
export async function hashPassword(
  password: string,
  options?: PasswordHashOptions
): Promise<string> {
  const config = options ? { ...getPasswordHashOptions(), ...options } : getPasswordHashOptions();

  try {
    return await hash(password, {
      memoryCost: config.memoryCost,
      timeCost: config.timeCost,
      parallelism: config.parallelism,
    });
  } catch (error) {
    throw new Error(
      `Failed to hash password: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

/**
 * Verify a password against a hash
 *
 * @param hashedPassword - Previously hashed password string
 * @param plainPassword - Plain text password to verify
 * @returns True if password matches, false otherwise
 * @throws Error if verification fails (e.g., invalid hash format)
 *
 * @example
 * ```typescript
 * const isValid = await verifyPassword(hashedPassword, 'mySecurePassword123');
 * if (isValid) {
 *   // Password is correct
 * }
 * ```
 */
export async function verifyPassword(
  hashedPassword: string,
  plainPassword: string
): Promise<boolean> {
  try {
    return await verify(hashedPassword, plainPassword);
  } catch (error) {
    // If verification fails due to invalid hash format, throw error
    // Otherwise, return false for incorrect password
    if (error instanceof Error && error.message.includes('Invalid')) {
      throw new Error(`Invalid password hash format: ${error.message}`);
    }
    return false;
  }
}
