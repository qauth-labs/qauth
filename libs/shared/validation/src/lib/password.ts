// eslint-disable-next-line @typescript-eslint/triple-slash-reference -- `@types/zxcvbn` does not declare zxcvbn's matcher module, and the declaration must reach every program that compiles this file, the auth-server's included, which consumes this library from source.
/// <reference path="./zxcvbn-matching.d.ts" />
import { z } from 'zod';
import zxcvbn from 'zxcvbn';
import matching from 'zxcvbn/lib/matching';

/**
 * Password strength validation result
 */
export interface PasswordStrengthResult {
  /**
   * Whether the password meets the minimum strength requirement
   */
  valid: boolean;
  /**
   * Password strength score (0-4)
   * 0: Very weak
   * 1: Weak
   * 2: Fair
   * 3: Good
   * 4: Strong
   */
  score: number;
  /**
   * Optional feedback messages from zxcvbn
   */
  feedback?: string[];
  /**
   * Estimated time to crack (in seconds)
   */
  crackTimeSeconds?: number;
}

/**
 * Password validation configuration schema
 */
export const passwordValidationConfigSchema = z.object({
  /**
   * Minimum password strength score (0-4)
   * 0: Very weak, 1: Weak, 2: Fair, 3: Good, 4: Strong
   */
  minScore: z
    .number()
    .int()
    .min(0, 'Minimum score must be at least 0')
    .max(4, 'Minimum score must not exceed 4'),
});

/**
 * Password validation configuration
 */
export type PasswordValidationConfig = z.infer<typeof passwordValidationConfigSchema>;

/**
 * Password validator interface
 */
export interface PasswordValidator {
  /**
   * Validate password strength using zxcvbn
   *
   * @param password - Password to validate
   * @returns Password strength validation result
   */
  validatePasswordStrength(password: string): PasswordStrengthResult;
}

/**
 * Default password validation configuration
 */
/**
 * Longest password accepted anywhere, in UTF-16 code units (JavaScript string
 * length). NIST SP 800-63B-4 §3.1.1.2 asks verifiers to accept at least 64
 * characters; 256 leaves ample room for passphrases and password managers.
 *
 * The bound exists because a password is attacker-sized input to CPU-bound
 * work: zxcvbn's matchers grow super-linearly with length, and Argon2id
 * hashes every byte. Request schemas reject anything longer before a handler
 * runs (through {@link passwordSchema}); `validatePasswordStrength` enforces it
 * again for any other caller.
 */
export const PASSWORD_MAX_LENGTH = 256;

/**
 * Request-schema field for a password: a string of at most
 * {@link PASSWORD_MAX_LENGTH} UTF-16 code units. Chain `.min(1)` where an empty
 * password must be refused at the schema.
 *
 * `z.string().max()` alone cannot express this bound. Since Zod 4.5, string
 * `.max()`, `.min()` and `.length()` count Unicode code points, so a password
 * of astral characters (emoji, for example) passes `.max(256)` at up to 512
 * code units, and only `validatePasswordStrength`, which counts `.length`,
 * would catch it, on the register path alone. The check below counts
 * `.length` and raises the issue `.max()` raised with Zod 4.4, same code and
 * same message. It stops the checks after it, so an over-long password yields
 * one issue. `.max()` stays only so the generated OpenAPI document keeps
 * `maxLength`; it can never fail for a value the check accepts.
 */
export const passwordSchema = z
  .string()
  .check((ctx) => {
    if (ctx.value.length > PASSWORD_MAX_LENGTH) {
      ctx.issues.push({
        code: 'too_big',
        origin: 'string',
        maximum: PASSWORD_MAX_LENGTH,
        inclusive: true,
        input: ctx.value,
        continue: false,
      });
    }
  })
  .max(PASSWORD_MAX_LENGTH);

/**
 * How much of a password zxcvbn scores. zxcvbn's cost grows super-linearly
 * with input length, and its own guidance is to score a bounded prefix. A
 * 100-character prefix that is weak makes the whole password weak for our
 * purposes (it errs towards rejecting), and one that is strong already
 * saturates zxcvbn's score of 4.
 */
export const ZXCVBN_MAX_INPUT_LENGTH = 100;

/**
 * How many l33t substitution maps zxcvbn tries for one password.
 *
 * Its l33t matcher enumerates every consistent combination of substitutions
 * for the l33t characters present and runs a full dictionary scan per
 * combination, so the cost is driven by WHICH characters occur, not by how
 * many: all 20 substitutes in its table give 736 maps, and scoring a
 * 100-character password made of them held the event loop for seconds. The
 * length bound above does not limit that. Passwords people choose need a
 * handful of maps (`p@ssw0rd` needs one), so their scores do not change; a
 * password with more is scored with the first 16 enumerated, which can only
 * raise its score slightly. zxcvbn-ts bounds the same work with its
 * `l33tMaxSubstitutions` option.
 *
 * A stopgap: scoring still runs on the event loop, now bounded to a few
 * hundred milliseconds in the worst case.
 */
export const ZXCVBN_MAX_L33T_SUBSTITUTIONS = 16;

// zxcvbn 4.4.2 has no option for this cap, but `l33t_match` obtains its maps
// through `this.enumerate_l33t_subs` on the matching module, the same object
// zxcvbn's entry point requires, so the cap is applied there. The tests pin
// that it takes effect, so an upgrade that stops honouring it fails them.
const enumerateL33tSubs = matching.enumerate_l33t_subs;
matching.enumerate_l33t_subs = function (table) {
  return enumerateL33tSubs.call(this, table).slice(0, ZXCVBN_MAX_L33T_SUBSTITUTIONS);
};

export const DEFAULT_PASSWORD_VALIDATION_CONFIG: PasswordValidationConfig = {
  minScore: 2, // Fair
};

/**
 * Create a password validator with the given configuration
 *
 * @param config - Optional partial password validation configuration. Missing values will use defaults.
 * @returns Password validator object with validatePasswordStrength method
 * @throws {z.ZodError} If the configuration is invalid
 *
 * @example
 * ```typescript
 * // Use default minScore (2)
 * const validator = createPasswordValidator();
 *
 * // Override minScore
 * const strictValidator = createPasswordValidator({ minScore: 4 });
 *
 * const result = validator.validatePasswordStrength('mySecurePassword123');
 * if (!result.valid) {
 *   console.log('Password is too weak:', result.feedback);
 * }
 * ```
 */
export function createPasswordValidator(
  config?: Partial<PasswordValidationConfig>
): PasswordValidator {
  // Merge with defaults and validate configuration
  const finalConfig = { ...DEFAULT_PASSWORD_VALIDATION_CONFIG, ...config };
  const validatedConfig = passwordValidationConfigSchema.parse(finalConfig);
  return {
    validatePasswordStrength(password: string): PasswordStrengthResult {
      // Empty password check
      if (!password || password.length === 0) {
        return {
          valid: false,
          score: 0,
          feedback: ['Password cannot be empty'],
        };
      }

      if (password.length > PASSWORD_MAX_LENGTH) {
        return {
          valid: false,
          score: 0,
          feedback: [`Password must be at most ${PASSWORD_MAX_LENGTH} characters`],
        };
      }

      // Use zxcvbn to analyze password strength, on a bounded prefix
      // (see ZXCVBN_MAX_INPUT_LENGTH).
      const analysis = zxcvbn(password.slice(0, ZXCVBN_MAX_INPUT_LENGTH));

      // Extract feedback messages
      const feedback: string[] = [];
      if (analysis.feedback.warning) {
        feedback.push(analysis.feedback.warning);
      }
      if (analysis.feedback.suggestions && analysis.feedback.suggestions.length > 0) {
        feedback.push(...analysis.feedback.suggestions);
      }

      // Extract crack time - zxcvbn returns it as number or string, ensure it's a number
      const crackTime = analysis.crack_times_seconds.offline_slow_hashing_1e4_per_second;
      const crackTimeSeconds =
        typeof crackTime === 'number' ? crackTime : parseFloat(crackTime) || undefined;

      return {
        valid: analysis.score >= validatedConfig.minScore,
        score: analysis.score,
        feedback: feedback.length > 0 ? feedback : undefined,
        crackTimeSeconds,
      };
    },
  };
}
