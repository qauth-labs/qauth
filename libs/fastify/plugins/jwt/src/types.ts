import type { JWTPayload } from '@qauth-labs/server-jwt';
import type { FastifyPluginOptions } from 'fastify';

/**
 * JWT plugin configuration options
 */
export interface JwtPluginOptions extends FastifyPluginOptions {
  /** JWT private key in PEM format */
  privateKey: string;
  /** JWT public key in PEM format (optional, can be derived from private key) */
  publicKey?: string;
  /** JWT issuer URL */
  issuer: string;
  /** Access token expiration in seconds */
  accessTokenLifespan: number;
  /** Refresh token expiration in seconds */
  refreshTokenLifespan: number;
}

/**
 * JWT payload structure
 * Re-exported to avoid apps needing direct dependency on @qauth-labs/server-jwt
 */
export type { JWTPayload };

/**
 * JWT utilities interface
 * Provides JWT token generation and refresh token utilities
 */
export interface JwtUtils {
  /**
   * Sign an access token.
   *
   * For user-context grants (authorization_code, refresh_token, password
   * login) pass `email` / `email_verified`. For client_credentials grants
   * omit them and set `sub` to the `clientId`. `scope` is space-separated
   * per RFC 6749. `aud` falls back to `clientId` when undefined.
   */
  signAccessToken(payload: {
    sub: string;
    email?: string;
    email_verified?: boolean;
    clientId: string;
    scope?: string;
    aud?: string | string[];
  }): Promise<string>;
  /**
   * Generate a refresh token pair (token and hash)
   */
  generateRefreshToken(): { token: string; tokenHash: string };
  /**
   * Hash a refresh token
   */
  hashRefreshToken(token: string): string;
  /**
   * Verify an access token and return payload.
   * When `audience` is provided, the token's `aud` claim MUST match
   * (string or array intersection per RFC 7519 §4.1.3).
   * @throws JWTExpiredError if token has expired
   * @throws JWTInvalidError if token is invalid or audience mismatches
   */
  verifyAccessToken(token: string, options?: { audience?: string | string[] }): Promise<JWTPayload>;
  /**
   * Extract JWT token from Authorization header
   * @param authHeader - Authorization header value (e.g., "Bearer <token>")
   * @returns JWT token string or null if header is missing or invalid format
   */
  extractFromHeader(authHeader: string | undefined): string | null;
  /**
   * Decode a JWT token without verification
   * WARNING: This does NOT verify the signature. Only use for:
   * - Reading claims from expired tokens (e.g., logout with expired token)
   * - Debugging/logging purposes
   * @throws JWTInvalidError if token is malformed
   */
  decodeTokenUnsafe(token: string): JWTPayload;
  /**
   * Get access token lifespan in seconds
   */
  getAccessTokenLifespan(): number;
  /**
   * Get refresh token lifespan in seconds
   */
  getRefreshTokenLifespan(): number;
}
