/**
 * Security-related constants
 */

/** Authorization code TTL in milliseconds (5 minutes, OAuth 2.1) */
export const AUTHORIZATION_CODE_TTL_MS = 5 * 60 * 1000;

/**
 * Minimum response time in milliseconds to prevent timing attacks
 * Used in authentication endpoints to prevent user enumeration
 */
export const MIN_RESPONSE_TIME_MS = {
  /** Login endpoint minimum response time (500ms) */
  LOGIN: 500,
  /** Resend verification endpoint minimum response time (200ms) */
  RESEND_VERIFICATION: 200,
  /** Refresh endpoint minimum response time (300ms) */
  REFRESH: 300,
  /** Token endpoint minimum response time (300ms) */
  TOKEN: 300,
  /** Introspect endpoint minimum response time (300ms) */
  INTROSPECT: 300,
  /** Userinfo endpoint minimum response time (300ms) */
  USERINFO: 300,
} as const;
