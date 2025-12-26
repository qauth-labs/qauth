/**
 * Helper functions for database error handling
 * These utilities help identify and extract information from database errors
 */

/**
 * Helper function to check if an error is a PostgreSQL unique constraint violation
 */
export function isUniqueConstraintError(error: unknown): boolean {
  if (typeof error === 'object' && error !== null) {
    const pgError = error as { code?: string; constraint?: string };
    return pgError.code === '23505'; // PostgreSQL unique_violation error code
  }
  return false;
}

/**
 * Helper function to extract constraint name from PostgreSQL error
 */
export function extractConstraintName(error: unknown): string | undefined {
  if (typeof error === 'object' && error !== null) {
    const pgError = error as { constraint?: string };
    return pgError.constraint;
  }
  return undefined;
}
