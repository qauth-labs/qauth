/**
 * The refusals of the admin API's webhook subscription operations (issue
 * #537), answered as a problem document (`api-conventions/error-classes.ts`).
 *
 * Kept free of imports so the error registry, and with it the error handler,
 * can load it without loading a route.
 */

/**
 * A test event for a subscription that is disabled: nothing would be sent,
 * so nothing is queued. `409`, the `conflict` problem document.
 */
export class WebhookSubscriptionDisabledError extends Error {
  readonly statusCode = 409;
  readonly code = 'CONFLICT';

  constructor() {
    super('The webhook subscription is disabled: enable it, then send the test event');
    this.name = 'WebhookSubscriptionDisabledError';
  }
}
