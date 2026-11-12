/**
 * The refusals of a provider plugin's client-assertion key operations
 * (ADR-019 Decision 9, issue #1073), answered as a problem document
 * (`api-conventions/error-classes.ts`).
 *
 * Kept free of imports so the error registry, and with it the error handler,
 * can load it without loading a route.
 */

/**
 * A key operation the realm's keys or the plugin's state do not allow as
 * they stand: `409`, the `conflict` problem document. Its message names the
 * state, such as a `next` key already waiting or a plugin whose
 * configuration names no client assertion, never key material.
 */
export class PluginKeyConflictError extends Error {
  readonly statusCode = 409;
  readonly code = 'CONFLICT';

  constructor(message: string) {
    super(message);
    this.name = 'PluginKeyConflictError';
  }
}
