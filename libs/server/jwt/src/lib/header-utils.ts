/**
 * Extract JWT token from Authorization header
 * Format: "Bearer <token>"
 *
 * @param authHeader - Authorization header value
 * @returns JWT token string or null if header is missing or invalid
 *
 * @example
 * ```typescript
 * const token = extractJWTFromHeader(request.headers.authorization);
 * if (!token) {
 *   throw new Error('Missing or invalid Authorization header');
 * }
 * ```
 */
export function extractJWTFromHeader(authHeader: string | undefined): string | null {
  if (!authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }

  return parts[1];
}
