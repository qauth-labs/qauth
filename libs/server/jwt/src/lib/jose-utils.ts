import { JWTInvalidError } from '@qauth/shared-errors';
import { decodeJwt as joseDecodeJwt, exportSPKI as joseExportSPKI } from 'jose';

import type { JWTPayload } from '../types/jwt-service';
import type { KeyLike } from '../types/key-management';

/**
 * Decode a JWT token without verification
 * Use this only when you need to read claims from an expired or unverified token
 *
 * WARNING: This does NOT verify the token signature. Only use for:
 * - Reading claims from expired tokens (e.g., logout with expired token)
 * - Debugging/logging purposes
 *
 * @param token - JWT token string to decode
 * @returns Decoded JWT payload
 * @throws JWTInvalidError if token is malformed
 *
 * @example
 * ```typescript
 * try {
 *   const payload = decodeJwtUnsafe(expiredToken);
 *   console.log(payload.sub); // user ID
 * } catch (error) {
 *   // Token is malformed
 * }
 * ```
 */
export function decodeJwtUnsafe(token: string): JWTPayload {
  try {
    const decoded = joseDecodeJwt(token);
    return {
      sub: decoded.sub as string,
      email: decoded['email'] as string,
      email_verified: decoded['email_verified'] as boolean,
      iat: decoded.iat,
      exp: decoded.exp,
      iss: decoded.iss,
    };
  } catch {
    throw new JWTInvalidError('Invalid JWT token format');
  }
}

/**
 * Export a public key to SPKI PEM format
 * Used to derive public key from private key for verification
 *
 * @param key - Key to export (typically a private key from which to extract public key)
 * @returns PEM-encoded SPKI public key string
 *
 * @example
 * ```typescript
 * const privateKey = await importPrivateKey(pemString);
 * const publicKeyPem = await exportPublicKeyPem(privateKey);
 * const publicKey = await importPublicKey(publicKeyPem);
 * ```
 */
export async function exportPublicKeyPem(key: KeyLike): Promise<string> {
  return joseExportSPKI(key);
}
