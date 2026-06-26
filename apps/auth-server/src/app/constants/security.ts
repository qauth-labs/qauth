/**
 * Security-related constants
 */

/** Authorization code TTL in milliseconds (5 minutes, OAuth 2.1) */
export const AUTHORIZATION_CODE_TTL_MS = 5 * 60 * 1000;

/**
 * Step-up authentication freshness window in milliseconds (ADR-007 §2, #185).
 *
 * When a request triggers a fresh-authentication step-up (`prompt=login` or a
 * dangerous scope), an authentication performed within this window is accepted
 * as "fresh". This both (a) prevents an infinite login→authorize→login redirect
 * loop after the user re-authenticates, and (b) bounds how long a single
 * re-authentication stays valid for issuing a dangerous/elevated grant.
 *
 * Tradeoff: a dangerous scope is satisfied by ANY authentication within this
 * window — including an unrelated login that happened ~110s earlier — so the
 * window is a deliberate usability relaxation of the dangerous-op gate, not a
 * guarantee of an immediate prompt. A relying party (e.g. `mcp-guard`) that
 * needs *exact* immediacy must send `max_age` (e.g. `max_age=0`), which is
 * enforced against its own value at OIDC second-granularity and is NOT widened
 * by this window. Two minutes balances usability against the "authenticate
 * shortly before the dangerous operation" intent.
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
  /**
   * API-key authentication minimum response time (300ms, ADR-008 §6 / #97).
   * Pads the verify path so a present-but-wrong key, a revoked key, an unknown
   * prefix, and a now-forbidden client are indistinguishable by timing.
   */
  API_KEY_AUTH: 300,
} as const;
