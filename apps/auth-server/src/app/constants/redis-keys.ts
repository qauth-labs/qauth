/**
 * Redis key generators for rate limiting and caching
 */
export const REDIS_KEYS = {
  /** Rate limit counter for resend verification requests per email */
  RESEND_RATE_LIMIT: (email: string) => `rate-limit:resend:${email}`,
  /** Last email sent timestamp for minimum interval check */
  LAST_EMAIL_SENT: (email: string) => `last-email-sent:${email}`,
} as const;
