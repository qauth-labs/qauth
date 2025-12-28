import { z } from 'zod';

/**
 * Password configuration schema
 * Password validation and hashing settings
 */
export const passwordEnvSchema = z.object({
  /**
   * Minimum password strength score (0-4)
   * 0: Very weak, 1: Weak, 2: Fair, 3: Good, 4: Strong
   */
  PASSWORD_MIN_SCORE: z.coerce.number().int().min(0).max(4).default(2),

  /**
   * Argon2 memory cost in KB (default: 64MB)
   */
  PASSWORD_MEMORY_COST: z.coerce.number().int().min(1).default(65536),

  /**
   * Argon2 time cost / iterations
   */
  PASSWORD_TIME_COST: z.coerce.number().int().min(1).default(3),

  /**
   * Argon2 parallelism / threads
   */
  PASSWORD_PARALLELISM: z.coerce.number().int().min(1).default(4),
});

/**
 * Password environment configuration type
 */
export type PasswordEnv = z.infer<typeof passwordEnvSchema>;
