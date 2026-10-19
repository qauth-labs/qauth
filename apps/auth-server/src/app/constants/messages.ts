/**
 * Error messages used across the application
 */
export const ERROR_MESSAGES = {
  RATE_LIMIT_EXCEEDED: 'Please wait before requesting another verification email',
} as const;

/**
 * Success messages used across the application
 */
export const SUCCESS_MESSAGES = {
  RESEND_VERIFICATION:
    'If the email exists and is not verified, a verification email has been sent',
  /**
   * The one answer `POST /auth/register` gives for every address. A new
   * account gets a verification link, an address that already has an account
   * gets a notice (or, while unverified, its verification link again), so the
   * message promises only that the next step is in the inbox.
   */
  REGISTRATION: 'Registration received. Check your inbox for an email with the next step.',
} as const;
