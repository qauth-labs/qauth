import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
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
  // Build claims. Omit email/email_verified for client_credentials tokens where
  // there is no end-user. Include scope only when granted.
  const claims: Record<string, unknown> = {
    sub: payload.sub,
    client_id: payload.clientId,
  };
  if (payload.email !== undefined) {
    claims['email'] = payload.email;
  }
  if (payload.email_verified !== undefined) {
    claims['email_verified'] = payload.email_verified;
  }
  if (payload.scope !== undefined && payload.scope.length > 0) {
    claims['scope'] = payload.scope;
  }

  let jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setExpirationTime(`${expiresIn}s`)
    .setIssuer(issuer);

  // `aud` claim: array → multi-audience, string → single, otherwise fall back
  // to the client_id (OAuth 2.1 RFC 8707 light-mode default).
  const audience = payload.aud ?? payload.clientId;
  jwt = jwt.setAudience(audience);

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
export async function verifyAccessToken(
  token: string,
  publicKey: KeyLike,
  options: { audience?: string | string[] } = {}
): Promise<JWTPayload> {
  try {
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
    });

    return {
      sub: payload.sub as string,
      email: payload['email'] as string | undefined,
      email_verified: payload['email_verified'] as boolean | undefined,
      clientId: payload['client_id'] as string,
      scope: payload['scope'] as string | undefined,
      aud: payload.aud as string | string[] | undefined,
      iat: payload.iat as number | undefined,
      exp: payload.exp as number | undefined,
      iss: payload.iss as string | undefined,
    };
  } catch (error) {
    if (error instanceof Error) {
      // 'jose' errors have a `code` property, and `JWTExpired` is a specific error name.
      if (error.name === 'JWTExpired') {
        throw new JWTExpiredError('JWT token has expired');
      }

      // Any other error from `jose` can be considered an invalid token error.
      // We can identify them by checking for the `code` property, which is a pattern in `jose`.
      if ('code' in error && typeof error.code === 'string') {
        throw new JWTInvalidError(`Invalid JWT token: ${error.message}`);
      }
    }

    // Fallback for unknown errors
    throw new JWTInvalidError('Invalid JWT token');
  }
}
