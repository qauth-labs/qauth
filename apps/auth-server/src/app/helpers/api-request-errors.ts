/**
 * The refusals of the account and developer APIs' list and update conventions
 * (#506, #524), each answered as a problem document
 * (`api-conventions/error-classes.ts`).
 *
 * Kept free of imports so the error registry, and with it the error handler,
 * can load them without loading a route.
 */

/**
 * A list's `cursor` that does not parse, or that another list issued: `400`,
 * the `invalid_cursor` problem document. A cursor is opaque, so the message
 * says nothing about its form.
 */
export class InvalidCursorError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_CURSOR';

  constructor(message = 'The cursor is not one this list issued.') {
    super(message);
    this.name = 'InvalidCursorError';
  }
}

/** One field of a merged update that fails the resource's schema. */
export interface UnprocessableField {
  /** An RFC 6901 JSON Pointer into the merged representation, such as `/client_name`. */
  readonly pointer: string;
  readonly message: string;
}

/**
 * A JSON Merge Patch (RFC 7396) that parses, but whose merged result fails the
 * resource's schema: `422`, the `unprocessable_content` problem document, whose
 * `errors` name each failing field.
 */
export class UnprocessableContentError extends Error {
  readonly statusCode = 422;
  readonly code = 'UNPROCESSABLE_CONTENT';

  constructor(
    readonly fields: readonly UnprocessableField[],
    message = 'The merged result is not a valid representation of the resource.'
  ) {
    super(message);
    this.name = 'UnprocessableContentError';
  }
}

/**
 * A `PATCH` body sent as another media type than
 * `application/merge-patch+json`: `415`, the `unsupported_media_type` problem
 * document. An update of the account and developer APIs is a JSON Merge
 * Patch (RFC 7396), and nothing else.
 */
export class UnsupportedMediaTypeError extends Error {
  readonly statusCode = 415;
  readonly code = 'UNSUPPORTED_MEDIA_TYPE';

  constructor(message = 'An update is a JSON Merge Patch, sent as application/merge-patch+json.') {
    super(message);
    this.name = 'UnsupportedMediaTypeError';
  }
}
