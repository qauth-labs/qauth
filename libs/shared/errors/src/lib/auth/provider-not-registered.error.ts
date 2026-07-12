/**
 * Error thrown when the credential provider registry is asked to resolve a
 * `provider_type` that has no registered `CredentialProvider` implementation
 * (ADR-003).
 *
 * This is a server-side configuration / invariant violation, not a client
 * error: in the auth engine the `provider_type` is chosen server-side, so an
 * unresolved type means the registry was not wired with the expected provider
 * at bootstrap. It therefore carries a 500 status and a generic, leak-safe
 * `message`; the offending type is exposed via `providerType` for server-side
 * logging only — mirroring how `UniqueConstraintError` keeps its constraint
 * name off the wire.
 */
export class ProviderNotRegisteredError extends Error {
  readonly statusCode = 500;
  readonly code = 'PROVIDER_NOT_REGISTERED';
  /**
   * The unresolved provider type. Logged server-side for diagnostics; kept out
   * of the generic wire `message`.
   */
  readonly providerType: string;

  constructor(providerType: string) {
    super('No credential provider is registered for the requested type');
    this.name = 'ProviderNotRegisteredError';
    this.providerType = providerType;
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, ProviderNotRegisteredError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ProviderNotRegisteredError);
    }
  }
}
