import type {
  CredentialProvider,
  UserAttribute,
  VerifiedIdentity,
} from './credential-provider.interface';

/**
 * WalletProvider — the `type='wallet'` {@link CredentialProvider} (ADR-004),
 * deliberately shipped as a NON-FUNCTIONAL SKELETON (issue #232).
 *
 * ## Why an unimplemented provider exists
 *
 * Epic #231 splits wallet federation across issues that must be developable in
 * parallel: #233 (SIOPv2 authorization request generation/handling), #234
 * (OID4VP Verifiable Presentation validation, SD-JWT VC), #235 (VC claims
 * normalization into `user_attributes`), #236 (trust registry — per-realm
 * issuer allowlist), #237 (`acr` propagation) and #238 (account linking).
 * ADR-003's promise is that adding a provider is a REGISTRATION, not an
 * auth-engine change, so this module establishes the file, the `type`
 * discriminator and the registry entry up front and the follow-ups fill in the
 * two method bodies against a stable shell. It intentionally contains no
 * protocol logic — no SIOPv2, no OID4VP, no DCQL, no trust registry.
 *
 * ## Fail-closed: both methods THROW, and must keep throwing
 *
 * `verify()` rejects and `extractAttributes()` throws unconditionally. That is
 * a security property, not an oversight:
 *
 * - A stub that resolved a placeholder {@link VerifiedIdentity} would be an
 *   authentication-bypass primitive the moment `WALLET_FEDERATION_ENABLED` is
 *   flipped or a route wires up `resolve('wallet')` — the auth engine upserts
 *   whatever `externalSub` it is handed and mints a token for it, with no
 *   provider-specific second guess (that is exactly ADR-003's design).
 * - A stub that returned `[]` from `extractAttributes()` would look identical
 *   to a working provider handed a credential carrying no claims, silently
 *   dropping identity data instead of failing loudly.
 *
 * So: do NOT soften these into no-ops or placeholder returns to make a caller
 * compile or a test go green. The correct response to hitting one of these
 * throws is to implement #233–#235.
 *
 * ## The ADR-004 model this shell will grow into
 *
 * Wallet-agnostic by construction — any SIOPv2 / OID4VP wallet (EUDI, Lissi,
 * Sphereon, walt-id, …), never EUDI-specific code. `externalSub` is the
 * holder's DID; extracted attributes carry `source = 'wallet'`
 * ({@link WALLET_SOURCE}), the highest ADR-002 trust rank, above the `oidc_*`
 * family and `self_reported`; `assuranceLevel` is the eIDAS LoA that
 * propagates downstream as the OIDC `acr` claim (#237).
 *
 * ## Forward constraint — ADR-004 spec refresh (2026-07-19)
 *
 * ADR-004 was authored 2026-03-11 against then-draft specs and **MUST NOT be
 * implemented as originally written**. Two constraints bind #233–#235:
 *
 * - **DCQL, not Presentation Exchange.** OID4VP 1.0 is Final and its credential
 *   query mechanism is DCQL (Digital Credentials Query Language). The
 *   `presentation_definition` model of OID4VP Draft 22 is superseded and DIF
 *   Presentation Exchange remains a PRE-DRAFT specification, operationally
 *   superseded for OID4VP flows. The presentation-request path MUST be built on
 *   DCQL. QAuth carries no Presentation Exchange dependency today, so this is a
 *   forward constraint, not a migration — there is nothing to unwind, only a
 *   wrong turn to avoid.
 * - **HAIP 1.0 is the testable eIDAS profile.** Generic "OID4VP support" does
 *   not imply conformance: OpenID4VC High Assurance Interoperability Profile
 *   (HAIP) 1.0 constrains credential formats, cryptographic suites and client
 *   authentication beyond base OID4VP, and is the profile the EUDI ecosystem
 *   aligns to. ADR-004's eIDAS claim should be re-stated against HAIP, which is
 *   its falsifiable form.
 *
 * @see docs/adr/004-wallet-agnostic-federation.md — § "Spec status (2026-07-19)"
 * @see docs/adr/003-credential-provider-interface.md
 */

/** `user_credentials.provider_type` / registry key for this provider. */
export const WALLET_PROVIDER_TYPE = 'wallet';

/**
 * `user_attributes.source` for wallet-derived (VC-backed) attributes.
 *
 * This value is load-bearing for claim resolution: `claims/attribute-trust.ts`
 * ranks `'wallet'` above every other source (ADR-002), so changing this literal
 * without changing `rankAttributeSource` would silently demote every
 * wallet-issued attribute to rank 0. `wallet.provider.test.ts` pins the pair.
 */
export const WALLET_SOURCE = 'wallet';

/**
 * Build the fail-closed error thrown by every method of the skeleton.
 *
 * Deliberately a plain `Error` rather than a `@qauth-labs/shared-errors` domain
 * error. Those carry `statusCode`/`code` and are mapped onto the wire by the
 * global error handler, which would frame this as a reachable, client-facing
 * outcome with a stable error contract. It is not one: no route resolves
 * `'wallet'` today, and the provider only enters the registry behind
 * `WALLET_FEDERATION_ENABLED` (off by default). Reaching it means QAuth is
 * mis-wired, and a generic 500 plus a server-side stack trace is precisely the
 * right signal. Minting a `NotImplementedError` in the shared lib would also
 * create permanent public wire surface for a condition that must never occur —
 * and would invite treating "not implemented" as a normal auth outcome.
 *
 * @param method - the {@link CredentialProvider} method that was called.
 * @param followUp - what lands where, so the reader gets the issue number.
 */
function walletSkeletonError(method: string, followUp: string): Error {
  return new Error(
    `WalletProvider.${method}() is not implemented — WalletProvider is a registration-only skeleton (#232). ${followUp} Failing closed: this method never returns a value, so no wallet can authenticate until the follow-ups land.`
  );
}

/**
 * Create the wallet {@link CredentialProvider} shell.
 *
 * Stateless and dependency-free (it holds no HTTP client, no trust registry, no
 * key material), so it is safe to construct at bootstrap and register in the
 * provider registry — registering it is inert, because every method fails
 * closed. See the module JSDoc before adding behaviour here.
 */
export function createWalletProvider(): CredentialProvider {
  return {
    type: WALLET_PROVIDER_TYPE,

    /**
     * NOT IMPLEMENTED — always rejects (see module JSDoc).
     *
     * The `input` is not even inspected: there is no input schema to validate
     * against until #234 fixes the presentation format (SD-JWT VC over OID4VP
     * 1.0, queried with DCQL). Accepting a shape now would freeze the wrong
     * contract for the issues that still have to choose it.
     *
     * @throws Error always — never resolves a {@link VerifiedIdentity}.
     */
    async verify(): Promise<VerifiedIdentity> {
      throw walletSkeletonError(
        'verify',
        'Wallet verification lands in #233 (SIOPv2 authorization request) and #234 (OID4VP presentation validation), with issuer trust in #236.'
      );
    },

    /**
     * NOT IMPLEMENTED — always throws (see module JSDoc).
     *
     * Unreachable in practice while {@link CredentialProvider.verify} rejects:
     * the auth engine only calls this with a `VerifiedIdentity` that `verify()`
     * produced. It throws anyway so that a caller reaching it out of order
     * fails loudly instead of recording an empty attribute set.
     *
     * @throws Error always — never returns attributes, not even `[]`.
     */
    extractAttributes(): UserAttribute[] {
      throw walletSkeletonError(
        'extractAttributes',
        `Normalizing Verifiable Credential claims into user_attributes rows (source='${WALLET_SOURCE}') lands in #235.`
      );
    },
  };
}
