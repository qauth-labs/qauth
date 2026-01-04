/**
 * Payload for signing access tokens
 */
export interface SignAccessTokenPayload {
  /** Subject (user ID) */
  sub: string;
  /** User email */
  email: string;
  /** Email verification status */
  email_verified: boolean;
}

/**
 * JWT payload structure, including standard claims
 */
export interface JWTPayload extends SignAccessTokenPayload {
  /** Issued at (timestamp) */
  iat?: number;
  /** Expiration time (timestamp) */
  exp?: number;
  /** Issuer */
  iss?: string;
}
