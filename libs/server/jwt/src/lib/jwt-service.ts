import { JWTExpiredError, JWTInvalidError } from '@qauth/shared-errors';
import { jwtVerify, SignJWT } from 'jose';

import type { JWTPayload, SignAccessTokenPayload } from '../types/jwt-service';
import type { KeyLike } from '../types/key-management';

/**
 * Sign an access token
 *
 * Creates a JWT access token with EdDSA algorithm.
 *
 * @param payload - Payload containing sub, email, and email_verified
 * @param privateKey - EdDSA private key for signing
 * @param issuer - JWT issuer (iss claim)
 * @param expiresIn - Expiration time in seconds
 * @returns Promise resolving to signed JWT token string
 *
 * @example
 * ```typescript
 * const token = await signAccessToken(
 *   { sub: 'user-123', email: 'user@example.com', email_verified: true },
 *   privateKey,
 *   'https://auth.example.com',
 *   900
 * );
 * ```
 */
export async function signAccessToken(
  payload: SignAccessTokenPayload,
  privateKey: KeyLike,
  issuer: string,
  expiresIn: number
): Promise<string> {
  const jwt = new SignJWT({
    sub: payload.sub,
    email: payload.email,
    email_verified: payload.email_verified,
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setExpirationTime(`${expiresIn}s`)
    .setIssuer(issuer);

  return jwt.sign(privateKey);
}

/**
 * Verify and decode an access token
 *
 * Verifies the JWT signature and decodes the payload.
 * Throws JWTExpiredError if the token has expired.
 * Throws JWTInvalidError if the token is invalid or malformed.
 *
 * @param token - JWT token string to verify
 * @param publicKey - EdDSA public key for verification
 * @returns Promise resolving to decoded JWT payload
 * @throws JWTExpiredError if token has expired
 * @throws JWTInvalidError if token is invalid
 *
 * @example
 * ```typescript
 * try {
 *   const payload = await verifyAccessToken(token, publicKey);
 *   console.log(payload.sub); // user ID
 * } catch (error) {
 *   if (error instanceof JWTExpiredError) {
 *     // Handle expiration
 *   } else if (error instanceof JWTInvalidError) {
 *     // Handle invalid token
 *   }
 * }
 * ```
 */
export async function verifyAccessToken(token: string, publicKey: KeyLike): Promise<JWTPayload> {
  try {
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
    });

    return {
      sub: payload.sub as string,
      email: payload['email'] as string,
      email_verified: payload['email_verified'] as boolean,
      iat: payload.iat as number | undefined,
      exp: payload.exp as number | undefined,
      iss: payload.iss as string | undefined,
    };
  } catch (error) {
    if (error instanceof Error) {
      // Check for expiration error (jose throws JWTExpired error)
      if (
        error.name === 'JWTExpired' ||
        error.constructor.name === 'JWTExpired' ||
        error.message.includes('exp') ||
        error.message.includes('expired') ||
        error.message.includes('ExpirationTime')
      ) {
        throw new JWTExpiredError('JWT token has expired');
      }

      // Check for invalid token errors
      if (
        error.name === 'JWTInvalid' ||
        error.constructor.name === 'JWTInvalid' ||
        error.message.includes('invalid') ||
        error.message.includes('malformed') ||
        error.message.includes('signature') ||
        error.message.includes('JWS')
      ) {
        throw new JWTInvalidError(`Invalid JWT token: ${error.message}`);
      }
    }

    // Fallback for unknown errors
    throw new JWTInvalidError('Invalid JWT token');
  }
}
