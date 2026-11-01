import type { UpstreamFailureReason } from '@qauth-labs/server-federation';

/**
 * Why an upstream call or check did not succeed, as the callback reports it
 * to the engine: one of the contract's failure reasons.
 *
 * - `upstream_unavailable`: the provider could not be reached in time, or
 *   the egress client refused or failed the call;
 * - `provider_error`: the provider answered with an OAuth error;
 * - `invalid_response`: the provider's answer failed a check;
 * - `transaction_mismatch`: the callback does not belong to the transaction.
 *
 * The message is for the operator's log and names no secret, code or token.
 */
export class UpstreamOidcError extends Error {
  readonly reason: UpstreamFailureReason;

  constructor(reason: UpstreamFailureReason, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'UpstreamOidcError';
    this.reason = reason;
    Object.setPrototypeOf(this, UpstreamOidcError.prototype);
  }
}

/** Shorthand: an `invalid_response` error. */
export function invalidResponse(message: string, options?: { cause?: unknown }): UpstreamOidcError {
  return new UpstreamOidcError('invalid_response', message, options);
}
