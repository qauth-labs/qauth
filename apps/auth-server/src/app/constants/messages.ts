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
} as const;
