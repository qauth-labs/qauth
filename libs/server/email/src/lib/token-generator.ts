import * as crypto from 'crypto';

import type { TokenPair } from '../types';

/**
 * Generate a secure verification token pair
 *
 * Generates a 32-byte (256-bit) random token, encodes it as hex (64 characters),
 * and returns both the plain token and its SHA-256 hash.
 *
 * Security considerations:
 * - Uses crypto.randomBytes(32) for high entropy (256 bits)
 * - Hash is stored in database, not the plain token
 * - Token is hex-encoded for URL-safe transmission
 *
 * @returns Token pair with plain token and hashed token
 *
 * @example
 * ```typescript
 * const { token, tokenHash } = generateVerificationToken();
 * // token: "a1b2c3d4e5f6..." (64 chars, send to user)
 * // tokenHash: "9f8e7d6c5b4a..." (64 chars, store in DB)
 * ```
 */
export function generateVerificationToken(): TokenPair {
  // Generate 32 bytes (256 bits) of random data
  const tokenBytes = crypto.randomBytes(32);
  // Encode as hex string (64 characters)
  const token = tokenBytes.toString('hex');
  // Hash the token for secure storage
  const tokenHash = hashToken(token);

  return { token, tokenHash };
}

/**
 * Hash a token using SHA-256
 *
 * This function hashes a token before storing it in the database.
 * This prevents token exposure if the database is compromised.
 *
 * @param token - Plain token string to hash
 * @returns SHA-256 hash of the token (64-character hex string)
 *
 * @example
 * ```typescript
 * const hash = hashToken('a1b2c3d4e5f6...');
 * // Returns: "9f8e7d6c5b4a..." (SHA-256 hash)
 * ```
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Validate token format
 *
 * Checks if a token is a valid 64-character hexadecimal string.
 *
 * @param token - Token string to validate
 * @returns True if token is valid format, false otherwise
 *
 * @example
 * ```typescript
 * isValidTokenFormat('a1b2c3d4e5f6...'); // true (64 hex chars)
 * isValidTokenFormat('invalid'); // false (too short)
 * isValidTokenFormat('a1b2c3d4e5f6...x'); // false (65 chars)
 * ```
 */
export function isValidTokenFormat(token: string): boolean {
  // Must be exactly 64 characters
  if (token?.length !== 64) {
    return false;
  }

  // Must be valid hexadecimal (0-9, a-f, A-F)
  const hexPattern = /^[0-9a-fA-F]{64}$/;
  return hexPattern.test(token);
}

/**
 * Constant-time token comparison
 *
 * Compares two tokens in constant time to prevent timing attacks.
 * Uses crypto.timingSafeEqual for secure comparison.
 *
 * @param token1 - First token to compare
 * @param token2 - Second token to compare
 * @returns True if tokens match, false otherwise
 *
 * @example
 * ```typescript
 * const isValid = constantTimeCompare(storedToken, providedToken);
 * ```
 */
export function constantTimeCompare(token1: string, token2: string): boolean {
  // Validate token formats before comparison
  if (!isValidTokenFormat(token1) || !isValidTokenFormat(token2)) {
    return false;
  }

  // Convert strings to buffers for timing-safe comparison
  const buffer1 = Buffer.from(token1, 'hex');
  const buffer2 = Buffer.from(token2, 'hex');

  // Buffers must be the same length for timingSafeEqual
  if (buffer1.length !== buffer2.length) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(buffer1, buffer2);
  } catch {
    // If comparison fails for any reason, return false
    return false;
  }
}
