/**
 * CredentialProvider abstraction for QAuth authentication methods (ADR-003).
 *
 * Every authentication method (password, wallet, WebAuthn, an AuthMethod)
 * implements {@link CredentialProvider}. The auth engine depends only on this
 * contract: it resolves a provider by `type`, calls `verify()`, and upserts the
 * attributes from `extractAttributes()`. It contains no provider-specific logic,
 * so new providers are added without changing the engine.
 *
 * The types are declared once, in `@qauth-labs/plugin-sdk` (#1009): an
 * AuthMethod plugin, written in its own repository against that package,
 * extends the same `CredentialProvider` the server registers. This module
 * re-exports them and declares none.
 *
 * @see docs/adr/003-credential-provider-interface.md
 */
export type {
  AssuranceLevel,
  CredentialProvider,
  UserAttribute,
  VerifiedIdentity,
} from '@qauth-labs/plugin-sdk';
