/**
 * Error thrown when a second `CredentialProvider` is registered under a `type`
 * that is already present in the credential provider registry (ADR-003).
 *
 * Registration happens once at auth-server bootstrap. A duplicate `type` means
 * two providers would claim the same credential method, letting one silently
 * shadow the other — a provider-confusion footgun in an authentication system —
 * so the registry fails fast. Like `ProviderNotRegisteredError`, this is a
 * server-side configuration error (500) with a generic, leak-safe `message`;
 * the offending type is exposed via `providerType` for server-side logging.
 */
export class ProviderAlreadyRegisteredError extends Error {
  readonly statusCode = 500;
  readonly code = 'PROVIDER_ALREADY_REGISTERED';
  /**
   * The already-registered provider type. Logged server-side for diagnostics;
   * kept out of the generic wire `message`.
   */
  readonly providerType: string;

  constructor(providerType: string) {
    super('A credential provider is already registered for the requested type');
    this.name = 'ProviderAlreadyRegisteredError';
    this.providerType = providerType;
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, ProviderAlreadyRegisteredError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ProviderAlreadyRegisteredError);
    }
  }
}
