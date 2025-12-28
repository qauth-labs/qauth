import { z } from 'zod';

/**
 * Email validation schema using Zod
 */
export const emailSchema = z.email('Invalid email format');

/**
 * Normalizes an email address for duplicate detection
 * - Converts to lowercase
 * - Trims whitespace
 *
 * TODO: Consider additional normalization rules for specific providers:
 *   - Gmail: Handle dots and plus addressing (e.g., "user.name@gmail.com" == "username@gmail.com")
 *   - Outlook/Hotmail: Handle plus addressing
 *   - Other providers may have specific normalization requirements
 *
 * @param email - The email address to normalize
 * @returns The normalized email address
 *
 * @example
 * ```typescript
 * const normalized = normalizeEmail('User@Example.com');
 * // Returns: 'user@example.com'
 * ```
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

/**
 * Validate email format
 *
 * @param email - Email address to validate
 * @returns Normalized email if valid
 * @throws ZodError if email is invalid
 *
 * @example
 * ```typescript
 * try {
 *   const normalized = validateEmail('User@Example.com');
 *   // Returns: 'user@example.com'
 * } catch (error) {
 *   // Handle validation error
 * }
 * ```
 */
export function validateEmail(email: string): string {
  const validated = emailSchema.parse(email);
  return normalizeEmail(validated);
}

/**
 * Check if email format is valid (non-throwing)
 *
 * @param email - Email address to check
 * @returns True if email format is valid, false otherwise
 *
 * @example
 * ```typescript
 * if (isValidEmail('user@example.com')) {
 *   // Email is valid
 * }
 * ```
 */
export function isValidEmail(email: string): boolean {
  return emailSchema.safeParse(email).success;
}
