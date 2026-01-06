import type { FastifyPluginOptions } from 'fastify';

/**
 * JWT plugin configuration options
 */
export interface JwtPluginOptions extends FastifyPluginOptions {
  /** JWT private key in PEM format */
  privateKey: string;
  /** JWT issuer URL */
  issuer: string;
  /** Access token expiration in seconds */
  accessTokenLifespan: number;
  /** Refresh token expiration in seconds */
  refreshTokenLifespan: number;
}

/**
 * JWT utilities interface
 * Provides JWT token generation and refresh token utilities
 */
export interface JwtUtils {
  /**
   * Sign an access token
   */
  signAccessToken(payload: {
    sub: string;
    email: string;
    email_verified: boolean;
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
   * Get access token lifespan in seconds
   */
  getAccessTokenLifespan(): number;
  /**
   * Get refresh token lifespan in seconds
   */
  getRefreshTokenLifespan(): number;
}
