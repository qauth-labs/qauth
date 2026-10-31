/**
 * The one answer the Interaction API gives when it will not let a request at
 * an interaction (#592, ADR-019 Decision 6): `410`, the `interaction_expired`
 * problem document (`api-conventions/error-classes.ts`).
 *
 * An unknown id, an expired interaction, a finished one and a flow cookie that
 * does not belong to it all get this same answer, byte for byte, so the answer
 * never tells a caller which: whether an id exists, or whether a cookie is the
 * right one. The reason is logged server-side only, and never with the id or
 * the cookie. The message is fixed and the problem document carries neither a
 * `detail` nor an `instance` (the request path holds the interaction id).
 *
 * Kept free of imports so the registry, and with it the error handler, can
 * load it without loading the interaction store and its configuration.
 */
export class InteractionExpiredError extends Error {
  readonly statusCode = 410;

  constructor() {
    super('The interaction is unknown, expired or finished.');
    this.name = 'InteractionExpiredError';
  }
}
