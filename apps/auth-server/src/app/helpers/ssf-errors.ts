/**
 * The refusals of the Shared Signals Framework transmitter's routes (#410)
 * that `@qauth-labs/shared-errors` has no class for. Each carries its status,
 * and the error registry (`api-conventions/error-classes.ts`) maps it to the
 * problem code it answers (#513), next to `SsfRequestError` (400
 * `bad_request`), which the protocol library raises. SSF 1.0 §8.1 gives these
 * statuses and no error body, so every one is a problem document.
 *
 * Kept free of imports so the registry, and with it the error handler, can
 * load them without loading the transmitter.
 */

/**
 * A 404 of the SSF surface: a realm that does not run the transmitter, or a
 * stream the receiver does not have. It names nothing the caller did not
 * send, so it tells no receiver whether another receiver's stream exists.
 * Answered as the `not_found` problem document.
 */
export class SsfNotFoundError extends Error {
  readonly statusCode = 404;

  constructor(message = 'Not found') {
    super(message);
    this.name = 'SsfNotFoundError';
  }
}

/**
 * A second stream for a receiver that has one in the realm (SSF 1.0
 * §8.1.1.1: `409` when the transmitter does not support multiple streams per
 * receiver). Answered as the `conflict` problem document.
 */
export class SsfStreamExistsError extends Error {
  readonly statusCode = 409;

  constructor() {
    super('The receiver already has a stream in this realm');
    this.name = 'SsfStreamExistsError';
  }
}
