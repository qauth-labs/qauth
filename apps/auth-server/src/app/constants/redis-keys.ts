/**
 * Redis key generators for rate limiting and caching
 */
export const REDIS_KEYS = {
  /** Rate limit counter for resend verification requests per email */
  RESEND_RATE_LIMIT: (email: string) => `rate-limit:resend:${email}`,
  /** Last email sent timestamp for minimum interval check */
  LAST_EMAIL_SENT: (email: string) => `last-email-sent:${email}`,
  /** Sliding-window failed-login attempt counter, keyed per identifier (#115) */
  FAILED_LOGIN_ATTEMPTS: (identifier: string) => `failed-login:attempts:${identifier}`,
  /** Active failed-login lockout marker, keyed per identifier (#115) */
  FAILED_LOGIN_LOCKOUT: (identifier: string) => `failed-login:lockout:${identifier}`,
  /**
   * Access-token revocation denylist entry, keyed by the token's `jti`
   * (RFC 7009). Stored with a TTL equal to the token's remaining lifetime so
   * it self-evicts once the token would have expired.
   */
  REVOKED_ACCESS_TOKEN: (jti: string) => `revoked-access-token:${jti}`,
} as const;
