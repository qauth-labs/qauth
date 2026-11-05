/**
 * Why a breach check could not answer (#635). None of them blocks a sign-in:
 * the caller counts and records it, and lets the sign-in proceed.
 *
 * - `not_configured`: the realm names a source the deployment has not set up,
 *   `local` without `BREACHED_PASSWORD_LIST_PATH` or `k_anonymity` without
 *   `BREACHED_PASSWORD_RANGE_URL`.
 * - `list_not_loaded`: the local list is configured, but no load of it has
 *   succeeded yet (the boot's load failed).
 * - `lookup_blocked`: the egress client refused the range lookup's
 *   destination (its outcome `blocked`: a private address without an
 *   allowlist entry for the realm, a redirect, an oversized answer).
 * - `lookup_failed`: the lookup did not complete (an egress failure, a
 *   timeout) or its host answered with a status other than 200.
 * - `bad_response`: the host answered 200 with a body that is not a range of
 *   `SUFFIX:COUNT` lines.
 */
export const BREACH_CHECK_FAILURE_REASONS = [
  'not_configured',
  'list_not_loaded',
  'lookup_blocked',
  'lookup_failed',
  'bad_response',
] as const;

/** One of {@link BREACH_CHECK_FAILURE_REASONS}. */
export type BreachCheckFailureReason = (typeof BREACH_CHECK_FAILURE_REASONS)[number];

/** Why a range lookup failed: the reasons a lookup itself can have. */
export type BreachLookupFailureReason = Extract<
  BreachCheckFailureReason,
  'lookup_blocked' | 'lookup_failed' | 'bad_response'
>;

/**
 * A malformed or unreadable local breach list. Its message names the line
 * number of a malformed line, never the line's content.
 */
export class BreachListError extends Error {
  /** The 1-based number of the malformed line, when a line is the problem. */
  readonly lineNumber: number | undefined;

  constructor(message: string, options: { lineNumber?: number; cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'BreachListError';
    this.lineNumber = options.lineNumber;
    Object.setPrototypeOf(this, BreachListError.prototype);
  }
}

/**
 * A range lookup that could not answer. Its message names neither the
 * password, nor its digest, nor the prefix sent.
 */
export class BreachLookupError extends Error {
  readonly reason: BreachLookupFailureReason;

  constructor(
    reason: BreachLookupFailureReason,
    message: string,
    options: { cause?: unknown } = {}
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'BreachLookupError';
    this.reason = reason;
    Object.setPrototypeOf(this, BreachLookupError.prototype);
  }
}

/** True when `error` is a {@link BreachLookupError}. */
export function isBreachLookupError(error: unknown): error is BreachLookupError {
  return error instanceof BreachLookupError;
}
