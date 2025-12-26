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
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}
