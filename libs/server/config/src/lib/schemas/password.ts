import {
  DEFAULT_PASSWORD_MIN_LENGTH,
  PASSWORD_MIN_LENGTH_CEILING,
  PASSWORD_MIN_LENGTH_FLOOR,
  PASSWORD_SINGLE_FACTOR_MIN_LENGTH,
} from '@qauth-labs/shared-validation';
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
   * The seed of a new realm's `password.minScore` (#528): registration checks
   * a password against the realm's own score, read from the realm row.
   *
   * Blank is unset, so the default. `z.coerce.number()` alone reads `''` as
   * `0`, the weakest score, and it seeds a new realm's `password.minScore`
   * (#514), which reads blank as unset.
   */
  PASSWORD_MIN_SCORE: z.preprocess(blankAsUnset, z.coerce.number().int().min(0).max(4).default(2)),

  /**
   * The fewest characters (Unicode code points, after NFC normalisation) a new
   * password may have (#634, ADR-017 Decision 8): the seed of a new realm's
   * `password.minLength`. Default 15, the NIST SP 800-63B-4 §3.1.1.2 minimum
   * for a password that may be the only factor. An operator may lower it to
   * 8, never below: a lower value fails the boot, and one below 15 boots with
   * a warning ({@link passwordPolicyWarnings}). At most 64.
   *
   * Blank is unset, so the default, as for `PASSWORD_MIN_SCORE`.
   */
  PASSWORD_MIN_LENGTH: z.preprocess(
    blankAsUnset,
    z.coerce
      .number()
      .int()
      .min(PASSWORD_MIN_LENGTH_FLOOR)
      .max(PASSWORD_MIN_LENGTH_CEILING)
      .default(DEFAULT_PASSWORD_MIN_LENGTH)
  ),

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

/** A warning the boot logs about the password settings, naming its variable. */
export interface PasswordPolicyWarning {
  readonly variable: string;
  readonly message: string;
}

/**
 * What the boot warns about in the password settings (#634): a
 * `PASSWORD_MIN_LENGTH` below 15, which NIST SP 800-63B-4 §3.1.1.2 allows only
 * for a password used within multi-factor authentication, while QAuth lets a
 * password be the only factor. The key seeds new realms' `password.minLength`,
 * so the warning says that too. Takes the parsed environment and names no key
 * of it at the caller, like the other seed readers.
 */
export function passwordPolicyWarnings(
  env: Pick<PasswordEnv, 'PASSWORD_MIN_LENGTH'>
): PasswordPolicyWarning[] {
  const minLength = env.PASSWORD_MIN_LENGTH;
  if (minLength >= PASSWORD_SINGLE_FACTOR_MIN_LENGTH) return [];
  return [
    {
      variable: 'PASSWORD_MIN_LENGTH',
      message: `PASSWORD_MIN_LENGTH is ${minLength}, below ${PASSWORD_SINGLE_FACTOR_MIN_LENGTH}: a new realm gets this minimum password length (password.minLength), which NIST SP 800-63B-4 allows only for a password used within multi-factor authentication, and a password can still be the only factor of a sign-in; this is a recorded deviation`,
    },
  ];
}
