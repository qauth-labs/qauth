import { z } from 'zod';

/** Blank is read as unset, since Docker Compose passes an absent variable as `''`. */
function blankAsUnset(value: unknown): unknown {
  return typeof value === 'string' && value.trim() === '' ? undefined : value;
}

/**
 * Password configuration schema
 * Password validation and hashing settings
 */
export const passwordEnvSchema = z.object({
  /**
   * Minimum password strength score (0-4)
   * 0: Very weak, 1: Weak, 2: Fair, 3: Good, 4: Strong
   *
   * Blank is unset, so the default. `z.coerce.number()` alone reads `''` as
   * `0`, the weakest score, and it seeds a new realm's `password.minScore`
   * (#514), which reads blank as unset.
   */
  PASSWORD_MIN_SCORE: z.preprocess(blankAsUnset, z.coerce.number().int().min(0).max(4).default(2)),

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

  /**
   * How many Argon2 jobs may wait for a free slot before a client-secret
   * check is refused with 503 and `Retry-After` instead of joining the queue
   * (#751). `0` refuses one whenever every slot is busy.
   */
  PASSWORD_HASH_QUEUE_LIMIT: z.coerce.number().int().min(0).default(32),
});

/**
 * Password environment configuration type
 */
export type PasswordEnv = z.infer<typeof passwordEnvSchema>;
