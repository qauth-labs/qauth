/**
 * Payload for signing access tokens
 *
 * When `email` / `email_verified` are omitted, the token is a client-only
 * credential (OAuth 2.1 client_credentials grant) and `sub` equals `clientId`.
 */
export interface SignAccessTokenPayload {
  /** Subject (user ID, or client_id for client_credentials grants) */
  sub: string;
  /** User email (omitted for client_credentials grants) */
  email?: string;
  /** Email verification status (omitted for client_credentials grants) */
  email_verified?: boolean;
  /** OAuth client identifier */
  clientId: string;
  /**
   * Space-separated OAuth scopes (RFC 8693 `scope` claim).
   * Omitted when no scopes were granted.
   */
  scope?: string;
  /**
   * Audience for the JWT (OAuth 2.1 / RFC 8707 light-mode).
   * String or array of strings; falls back to `clientId` when absent.
   */
  aud?: string | string[];
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
