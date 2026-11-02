/**
 * The Interaction API's refusals of an answer's body (#616, ADR-017
 * Decision 7), each answered as a bare problem document
 * (`api-conventions/error-classes.ts`, `isBareProblem`): the message is
 * logged, never sent.
 *
 * Kept free of imports so the error registry, and with it the error handler,
 * can load them without loading a route.
 */

/**
 * An answer that does not match the schema of the step it names, names a step
 * the step read did not offer, carries a member the operation does not
 * declare, or repeats a form field: `400`, the `invalid_answer` problem.
 */
export class InvalidAnswerError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_ANSWER';

  constructor(message = 'The answer does not match the step it names.') {
    super(message);
    this.name = 'InvalidAnswerError';
  }
}

/**
 * An answer's body over its bound: 16 KiB, or 64 KiB for an answer to
 * `webauthn_create` (ADR-017 Decision 7): `413`, the `content_too_large`
 * problem.
 */
export class ContentTooLargeError extends Error {
  readonly statusCode = 413;
  readonly code = 'CONTENT_TOO_LARGE';

  constructor(message = 'The body is larger than the answer allows.') {
    super(message);
    this.name = 'ContentTooLargeError';
  }
}
