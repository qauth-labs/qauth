type ApiError = { code: string; message: string; details?: string | string[]; status: number };

/**
 * Map an API error from a client-management call into a single user-facing
 * message. `UNAUTHENTICATED` is handled by the route (redirect to login), so
 * callers typically check `error.code === 'UNAUTHENTICATED'` first and only
 * pass other errors here.
 */
export function clientErrorMessage(error: ApiError): string {
  switch (error.code) {
    case 'UNAUTHENTICATED':
      return 'Your session has expired. Please log in again.';
    case 'NOT_FOUND':
      return 'This client was not found, or you do not have access to it.';
    case 'RATE_LIMITED':
      return 'Too many requests. Please wait a moment and try again.';
    case 'VALIDATION_ERROR': {
      if (Array.isArray(error.details) && error.details.length > 0) {
        return error.details.join(' ');
      }
      if (typeof error.details === 'string') return error.details;
      return error.message || 'Some fields are invalid. Please review and try again.';
    }
    case 'NETWORK_ERROR':
      return 'Could not reach the server. Check your connection and try again.';
    default:
      return error.message || 'Something went wrong. Please try again.';
  }
}
