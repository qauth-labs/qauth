/**
 * CredentialProvider abstraction for QAuth authentication methods (ADR-003).
 *
 * Every authentication method (password today; wallet and external OIDC later)
 * implements {@link CredentialProvider}. The auth engine depends only on this
 * contract: it resolves a provider by `type`, calls `verify()`, and upserts the
 * attributes from `extractAttributes()`. It contains no provider-specific logic,
 * so new providers are added without changing the engine.
 *
 * @see docs/adr/003-credential-provider-interface.md
 */

/**
 * Level of assurance for a verified identity, aligned with eIDAS Levels of
 * Assurance (LoA) and ISO/IEC 29115. Propagated downstream as the OIDC `acr`
 * claim; `'low'` credentials (e.g. self-asserted email/password) carry no `acr`
 * claim per ADR-003.
 */
export type AssuranceLevel = 'low' | 'substantial' | 'high'; // eIDAS LoA / ISO 29115

/**
 * The result of a successful {@link CredentialProvider.verify} call: a
 * provider-scoped subject identifier, the assurance level of the verification,
 * and the raw claims the provider observed.
 */
export interface VerifiedIdentity {
  /**
   * Subject identifier as known to the upstream provider (e.g. the normalized
   * email for password, a DID for a wallet). Never used directly as the token
   * `sub` — the engine maps it to the internal `users.id`.
   */
  externalSub: string;
  /** Assurance level of this verification (eIDAS LoA / ISO 29115). */
  assuranceLevel: AssuranceLevel;
  /** Unprocessed claims exactly as returned by the provider, before extraction. */
  rawClaims: Record<string, unknown>;
}

/**
 * A single normalized user attribute derived from a {@link VerifiedIdentity},
 * ready to be upserted into `user_attributes`. Trust ordering during claim
 * resolution is driven by `source` and `verified`.
 */
export interface UserAttribute {
  /**
   * Origin of the attribute (e.g. `'self_reported'`, `'wallet'`,
   * `'oidc_google'`). Drives trust ordering during claim resolution.
   */
  source: string;
  /** Attribute key (e.g. `'email'`). */
  attrKey: string;
  /** Attribute value. */
  attrValue: string;
  /** Whether the provider verified this attribute. */
  verified: boolean;
  /** Optional expiry after which the attribute must be re-verified. */
  expiresAt?: Date;
}

/**
 * Strategy interface implemented by every authentication method (ADR-003).
 */
export interface CredentialProvider {
  /**
   * Stable discriminator used to register and resolve this provider in the
   * {@link import('./provider-registry').ProviderRegistry} (e.g. `'password'`,
   * `'wallet'`).
   */
  readonly type: string;
  /**
   * Verify the provider-specific `input` and resolve a normalized
   * {@link VerifiedIdentity}. Implementations reject on verification failure.
   */
  verify(input: unknown): Promise<VerifiedIdentity>;
  /**
   * Derive normalized {@link UserAttribute} rows from a successful verification
   * result, ready to be upserted into `user_attributes`.
   */
  extractAttributes(result: VerifiedIdentity): UserAttribute[];
}
