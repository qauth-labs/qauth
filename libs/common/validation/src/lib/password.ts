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
 * Default minimum password strength score (2 = Fair)
 * Can be overridden via PASSWORD_MIN_SCORE environment variable
 */
const DEFAULT_MIN_SCORE = 2;

/**
 * Get minimum password strength score from environment or use default
 */
function getMinScore(): number {
  const envScore = process.env['PASSWORD_MIN_SCORE'];
  if (envScore !== undefined) {
    const score = parseInt(envScore, 10);
    if (score >= 0 && score <= 4) {
      return score;
    }
  }
  return DEFAULT_MIN_SCORE;
}

/**
 * Validate password strength using zxcvbn
 *
 * @param password - Password to validate
 * @param minScore - Minimum required score (0-4, defaults to 2)
 * @returns Password strength validation result
 *
 * @example
 * ```typescript
 * const result = validatePasswordStrength('mySecurePassword123');
 * if (!result.valid) {
 *   console.log('Password is too weak:', result.feedback);
 * }
 * ```
 */
export function validatePasswordStrength(
  password: string,
  minScore?: number
): PasswordStrengthResult {
  const requiredScore = minScore ?? getMinScore();

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
    valid: analysis.score >= requiredScore,
    score: analysis.score,
    feedback: feedback.length > 0 ? feedback : undefined,
    crackTimeSeconds,
  };
}
