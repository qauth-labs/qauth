/**
 * Security-related constants
 */

/** Authorization code TTL in milliseconds (5 minutes, OAuth 2.1) */
export const AUTHORIZATION_CODE_TTL_MS = 5 * 60 * 1000;

/**
 * Step-up authentication freshness window in milliseconds (ADR-007 §2, #185).
 *
 * When a request triggers a fresh-authentication step-up (`prompt=login` or a
 * dangerous elevated scope), an authentication performed within this window is
 * accepted as "fresh". This both (a) prevents an infinite login→authorize→login
 * redirect loop after the user re-authenticates, and (b) bounds how long a
 * single re-authentication stays valid for issuing a dangerous/elevated grant.
 * Exact `max_age` requests are enforced against their own value and are NOT
 * widened by this window. Two minutes balances usability against the
 * "authenticate immediately before the dangerous operation" intent.
 */
export const STEP_UP_FRESH_AUTH_WINDOW_MS = 2 * 60 * 1000;

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
