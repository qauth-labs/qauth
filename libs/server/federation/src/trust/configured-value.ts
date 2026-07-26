/**
 * Rendering operator-supplied configuration for an error's structured details.
 *
 * Internal to the trust modules — deliberately NOT re-exported from the package
 * index. Its existence is a reminder rather than a utility: a configuration
 * value never belongs in an `Error.message` (see `InvalidConfigurationError`),
 * so anything that wants to report one goes through here on its way to a
 * `details` field.
 */

/** Longest operator-supplied value attached to an error's structured details. */
const MAX_REPORTED_VALUE_LENGTH = 120;

/**
 * Truncate an operator-supplied value before it is attached to an error.
 *
 * Attached to `details`, NEVER interpolated into a message. Truncated because
 * an allowlist entry may be up to 2048 characters and a log line should stay
 * readable.
 *
 * @param value - the operator-supplied value; `unknown` because it reaches this
 * function from JSON and env strings.
 * @returns the value as a string, cut to {@link MAX_REPORTED_VALUE_LENGTH} with
 * an ellipsis when it is longer.
 */
export function summarizeConfiguredValue(value: unknown): string {
  const text = typeof value === 'string' ? value : String(value);
  return text.length > MAX_REPORTED_VALUE_LENGTH
    ? `${text.slice(0, MAX_REPORTED_VALUE_LENGTH)}…`
    : text;
}
