/**
 * Why an answer was refused before the engine read it. Each is a fault of
 * the request, not a refused credential: the transport answers it as a
 * malformed request (`invalid_request` at the FiPA endpoint), never as the
 * step's own error, and the engine counts no failure for it.
 */
export const STEP_ANSWER_ERROR_CODES = [
  /** The answer names a step the transport did not present: unknown, not offered, or left out of what it put on the wire. */
  'not_offered',
  /** The answer's fields do not match the step's answer schema, or do not fit the params it was offered with. */
  'invalid_answer',
] as const;

export type StepAnswerErrorCode = (typeof STEP_ANSWER_ERROR_CODES)[number];

/**
 * An answer's refusal. `code` says why; the message names the step and the
 * member, never a value, so a password or a code never reaches the log.
 */
export class StepAnswerError extends Error {
  readonly code: StepAnswerErrorCode;

  constructor(code: StepAnswerErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'StepAnswerError';
    this.code = code;
  }
}
