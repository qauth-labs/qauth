/**
 * JWT payload structure
 */
export interface JWTPayload {
  /** Subject (user ID) */
  sub: string;
  /** User email */
  email: string;
  /** Email verification status */
  email_verified: boolean;
  /** Issued at (timestamp) */
  iat?: number;
  /** Expiration time (timestamp) */
  exp?: number;
  /** Issuer */
  iss?: string;
}

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
