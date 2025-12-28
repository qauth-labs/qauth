import { hash, verify } from '@node-rs/argon2';
import { z } from 'zod';

/**
 * Password hashing configuration schema
 */
export const passwordHashConfigSchema = z.object({
  /**
   * Memory cost in KB (default: 65536 = 64MB)
   * Minimum: 1 KB, recommended: at least 8192 KB (8MB) for security
   */
  memoryCost: z.number().int().min(1, 'Memory cost must be at least 1 KB'),
  /**
   * Time cost / iterations (default: 3)
   * Minimum: 1, maximum: 10 (higher values may cause performance issues)
   */
  timeCost: z
    .number()
    .int()
    .min(1, 'Time cost must be at least 1')
    .max(10, 'Time cost must not exceed 10'),
  /**
   * Parallelism / threads (default: 4)
   * Minimum: 1, maximum: 255 (Argon2 specification limit)
   */
  parallelism: z
    .number()
    .int()
    .min(1, 'Parallelism must be at least 1')
    .max(255, 'Parallelism must not exceed 255'),
});

/**
 * Password hashing configuration
 */
export type PasswordHashConfig = z.infer<typeof passwordHashConfigSchema>;

/**
 * Password hasher interface
 */
export interface PasswordHasher {
  /**
   * Hash a password using Argon2id
   *
   * @param password - Plain text password to hash
   * @returns Hashed password string
   * @throws Error if hashing fails
   */
  hashPassword(password: string): Promise<string>;

  /**
   * Verify a password against a hash
   *
   * @param hashedPassword - Previously hashed password string
   * @param plainPassword - Plain text password to verify
   * @returns True if password matches, false otherwise (including invalid hash format)
   */
  verifyPassword(hashedPassword: string, plainPassword: string): Promise<boolean>;
}

/**
 * Default password hashing configuration
 * These values provide a good balance between security and performance
 */
export const DEFAULT_PASSWORD_CONFIG: PasswordHashConfig = {
  memoryCost: 65536, // 64MB
  timeCost: 3,
  parallelism: 4,
};

/**
 * Create a password hasher with the given configuration
 *
 * @param config - Optional partial password hashing configuration. Missing values will use defaults.
 * @returns Password hasher object with hashPassword and verifyPassword methods
 * @throws {z.ZodError} If the configuration is invalid
 *
 * @example
 * ```typescript
 * // Use all defaults
 * const hasher = createPasswordHasher();
 *
 * // Override only specific values
 * const customHasher = createPasswordHasher({
 *   memoryCost: 32768,
 * });
 *
 * // Or provide full configuration
 * const fullHasher = createPasswordHasher({
 *   memoryCost: 65536,
 *   timeCost: 3,
 *   parallelism: 4,
 * });
 *
 * const hashed = await hasher.hashPassword('mySecurePassword123');
 * const isValid = await hasher.verifyPassword(hashed, 'mySecurePassword123');
 * ```
 */
export function createPasswordHasher(config?: Partial<PasswordHashConfig>): PasswordHasher {
  // Merge with defaults and validate configuration
  const finalConfig = { ...DEFAULT_PASSWORD_CONFIG, ...config };
  const validatedConfig = passwordHashConfigSchema.parse(finalConfig);
  return {
    async hashPassword(password: string): Promise<string> {
      try {
        return await hash(password, {
          memoryCost: validatedConfig.memoryCost,
          timeCost: validatedConfig.timeCost,
          parallelism: validatedConfig.parallelism,
        });
      } catch (error) {
        throw new Error(
          `Failed to hash password: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    },

    async verifyPassword(hashedPassword: string, plainPassword: string): Promise<boolean> {
      try {
        return await verify(hashedPassword, plainPassword);
      } catch {
        // Return false for all errors (incorrect password, invalid hash format, etc.)
        return false;
      }
    },
  };
}
