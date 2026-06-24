/**
 * Helper functions for database error handling
 * These utilities help identify and extract information from database errors
 */

/**
 * Walk an error and its `cause` chain, returning the first link that carries a
 * PostgreSQL-style `code`/`constraint`. drizzle-orm (>=0.30) wraps the raw `pg`
 * error in a `DrizzleQueryError`, exposing the original under `.cause`; without
 * unwrapping, the pg fields are invisible on the top-level error.
 */
function findPgError(
  error: unknown,
  depth = 0
): { code?: string; constraint?: string } | undefined {
  // Bound the walk so a cyclic/deep cause chain can't loop forever.
  if (typeof error !== 'object' || error === null || depth > 5) {
    return undefined;
  }
  const candidate = error as { code?: string; constraint?: string; cause?: unknown };
  if (typeof candidate.code === 'string') {
    return candidate;
  }
  return findPgError(candidate.cause, depth + 1);
}

/**
 * Helper function to check if an error is a PostgreSQL unique constraint violation
 */
export function isUniqueConstraintError(error: unknown): boolean {
  // 23505 = PostgreSQL unique_violation. Unwrap drizzle's wrapper first.
  return findPgError(error)?.code === '23505';
}

/**
 * Helper function to extract constraint name from PostgreSQL error
 */
export function extractConstraintName(error: unknown): string | undefined {
  return findPgError(error)?.constraint;
}
