/**
 * Error thrown when operator-supplied CONFIGURATION cannot be used as written —
 * an env variable, a realm row, or any other deployment input that the process
 * must refuse rather than reinterpret.
 *
 * ## Why the offending value goes on `details`, never in `message`
 *
 * A configuration fault is a server fault (500), so its `message` can reach an
 * HTTP response through the global error handler's `statusCode` branch, and it
 * reaches logs and crash reports unconditionally. Configuration values are
 * exactly the class of data that must not travel that way: they are
 * operator-supplied, arbitrarily long, and frequently adjacent to secrets.
 *
 * So `message` states WHAT is wrong and WHICH setting is wrong, in fixed text
 * the author wrote, and every operator-supplied value goes on {@link details},
 * which no response path serializes. An operator reading the structured log
 * still gets the value; a client never does.
 */
export class InvalidConfigurationError extends Error {
  readonly statusCode = 500;
  readonly code = 'INVALID_CONFIGURATION';

  /**
   * Structured, operator-facing context: the offending value, its position, the
   * setting it came from. Logged, never rendered into {@link Error.message}.
   */
  readonly details?: Readonly<Record<string, unknown>>;

  /**
   * @param message - fixed, author-written text. MUST NOT interpolate any
   * operator-supplied value; put those on `details`.
   * @param details - structured context for the operator-facing log.
   */
  constructor(message: string, details?: Readonly<Record<string, unknown>>) {
    super(message);
    this.name = 'InvalidConfigurationError';
    this.details = details;
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, InvalidConfigurationError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidConfigurationError);
    }
  }
}
