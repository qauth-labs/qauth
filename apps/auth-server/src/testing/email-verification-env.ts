/**
 * The environment the email-verification routes (`routes/auth/verify.ts`,
 * `routes/auth/verify-page.ts`, `routes/ui/verify.ts`) and the modules under
 * them read. A test file that uses `buildEmailVerificationApp()` mocks
 * `config/env` with it:
 *
 * ```ts
 * vi.mock('../../../config/env', async () => {
 *   const { EMAIL_VERIFICATION_TEST_ENV } = await import('../../../testing/email-verification-env');
 *   return { env: { ...EMAIL_VERIFICATION_TEST_ENV } };
 * });
 * ```
 *
 * A module of its own that imports nothing: the mock factory runs while
 * `config/env` is being loaded, so a module that reached `config/env` from
 * inside it would wait on itself.
 */
export const EMAIL_VERIFICATION_TEST_ENV = {
  VERIFICATION_RATE_LIMIT: 10,
  VERIFICATION_RATE_WINDOW: 900,
  FAILED_LOGIN_TRACKING_ENABLED: true,
  FAILED_LOGIN_MAX_ATTEMPTS: 5,
  FAILED_LOGIN_WINDOW: 900,
  FAILED_LOGIN_LOCKOUT_DURATION: 900,
  SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
  SESSION_COOKIE_TTL: 3600,
  SESSION_COOKIE_SECURE: false,
  SECURITY_HSTS_ENABLED: true,
  SECURITY_HSTS_MAX_AGE: 31536000,
} as const;
