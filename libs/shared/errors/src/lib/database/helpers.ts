/**
 * Helper functions for database error handling
 * These utilities help identify and extract information from database errors
 */

/** PostgreSQL error codes (SQLSTATE) are exactly 5 alphanumeric characters. */
const SQLSTATE_RE = /^[0-9A-Za-z]{5}$/;

/**
 * Shape of a PostgreSQL driver error once unwrapped. `code` is the SQLSTATE and
 * the remaining fields are populated by `pg`/`postgres` on real DB errors.
 */
interface PgErrorLike {
  code?: string;
  constraint?: string;
  detail?: string;
  severity?: string;
  cause?: unknown;
}

/**
 * A link in the cause chain is the actual Postgres error only if it carries a
 * SQLSTATE-shaped `code` OR one of the pg-specific diagnostic fields
 * (`constraint`/`detail`/`severity`). A generic wrapper error (e.g. a Fastify
 * `FST_ERR_*` or a custom `INTERNAL_SERVER_ERROR`) carries a `code` that is not
 * SQLSTATE-shaped and none of the pg fields, so it must be skipped.
 */
function isPgError(candidate: PgErrorLike): boolean {
  return (
    (typeof candidate.code === 'string' && SQLSTATE_RE.test(candidate.code)) ||
    typeof candidate.constraint === 'string' ||
    typeof candidate.detail === 'string' ||
    typeof candidate.severity === 'string'
  );
}

/**
 * Walk an error and its `cause` chain, returning the first link that looks like
 * the raw PostgreSQL error. drizzle-orm (>=0.30) wraps the raw `pg` error in a
 * `DrizzleQueryError`, exposing the original under `.cause`; without unwrapping,
 * the pg fields are invisible on the top-level error.
 *
 * The chain must be walked past any *non-pg* wrapper that happens to carry its
 * own unrelated `code` (such wrappers are common in production), otherwise the
 * wrong error would be returned and the real pg error missed.
 */
function findPgError(error: unknown, depth = 0): PgErrorLike | undefined {
  // Bound the walk so a cyclic/deep cause chain can't loop forever.
  if (typeof error !== 'object' || error === null || depth > 5) {
    return undefined;
  }
  const candidate = error as PgErrorLike;
  if (isPgError(candidate)) {
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
