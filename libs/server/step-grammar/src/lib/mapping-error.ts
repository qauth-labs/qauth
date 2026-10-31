/**
 * Why a mapper refused to serialise an offer. Each is a fault of the code
 * that built the offer, never of the person signing in: the transport answers
 * it as an internal error, and nothing of it reaches the wire.
 */
export const STEP_MAPPING_ERROR_CODES = [
  /** The offer, a step in it or the round context has a member the grammar does not define. */
  'unknown_member',
  /** A step name no step has. */
  'unknown_step',
  /** A step's params do not match its schema. */
  'invalid_params',
  /** An error that is not in the current step's closed set, or an error on an alternative. */
  'invalid_error',
  /** The same step offered twice, or the current step offered as its own alternative. */
  'duplicate_step',
  /** More alternatives than the step read may carry. */
  'too_many_alternatives',
  /** The current step, or a value of its params, is one this transport does not serve. */
  'not_served',
  /** A bot challenge the client did not list: answered by the engine's delay and 429, never by `redirect_to_web`. */
  'not_negotiated',
  /** A bot challenge offered with alternatives, or as one: it is required, and the pending step resumes after it. */
  'bot_challenge_not_alone',
  /** The transport configuration or the round context is malformed. */
  'invalid_configuration',
] as const;

export type StepMappingErrorCode = (typeof STEP_MAPPING_ERROR_CODES)[number];

/**
 * A mapper's refusal. `code` says why; the message names the step and the
 * member, never a value, so it can go to the log as it is.
 */
export class StepMappingError extends Error {
  readonly code: StepMappingErrorCode;

  constructor(code: StepMappingErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'StepMappingError';
    this.code = code;
  }
}
