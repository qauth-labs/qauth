import { z } from 'zod';
import zxcvbn from 'zxcvbn';

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

      // Use zxcvbn to analyze password strength
      const analysis = zxcvbn(password);

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
