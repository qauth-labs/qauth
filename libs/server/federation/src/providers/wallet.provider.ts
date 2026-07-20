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
 * parallel: #233 (OID4VP 1.0 authorization request generation + `direct_post`
 * response intake), #234
 * (OID4VP Verifiable Presentation validation, SD-JWT VC), #235 (VC claims
 * normalization into `user_attributes`), #236 (trust registry — per-realm
 * issuer allowlist), #237 (`acr` propagation) and #238 (account linking).
 * ADR-003's promise is that adding a provider is a REGISTRATION, not an
 * auth-engine change, so this module establishes the file, the `type`
 * discriminator and the registry entry up front and the follow-ups fill in the
 * two method bodies against a stable shell. It intentionally contains no
 * protocol logic — no OID4VP, no DCQL, no trust registry.
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
 * Wallet-agnostic by construction — any OID4VP wallet (EUDI, Lissi, Sphereon,
 * walt-id, …), never EUDI-specific code. Extracted attributes carry
 * `source = 'wallet'` ({@link WALLET_SOURCE}), the highest ADR-002 trust rank,
 * above the `oidc_*` family and `self_reported`; `assuranceLevel` is the eIDAS
 * LoA that propagates downstream as the OIDC `acr` claim (#237).
 *
 * NOTE: the 2026-03-11 model had `externalSub` = the holder's DID. That does not
 * survive the 2026-07-20 corrections — see the forward constraints below.
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
 *   its falsifiable form — but re-stating the claim in HAIP's terms is not the
 *   same as adopting HAIP, and whether QAuth targets it is OPEN (#296). Read
 *   this as "what conformance would mean", not "conform".
 *
 * ## Forward constraint — ADR-004 correction (2026-07-20)
 *
 * The 2026-07-19 refresh above also asserted that "SIOPv2 remains the
 * self-issued-OP mechanism this ADR describes". **That is wrong** (#295) and is
 * superseded. Three further constraints bind #233–#238:
 *
 * - **OID4VP 1.0 is the mechanism; SIOPv2 is not part of it.** HAIP 1.0 §5:
 *   "The Response type MUST be `vp_token`" — which excludes the
 *   `vp_token id_token` Response Type that carries a Self-Issued ID Token
 *   (OID4VP 1.0 §8). The strings `SIOP`, `Self-Issued` and `id_token` occur zero
 *   times in HAIP 1.0. SIOPv2 is draft 13 (2023-11-28) and never reached Final.
 *   Do NOT implement a SIOPv2 authorization request or consume a self-issued
 *   `id_token`. Note that the `direct_post` in #233's title is the BASE OID4VP
 *   1.0 Response Mode; HAIP 1.0 §5.1 requires the encrypted `direct_post.jwt`
 *   instead. Which one #233 implements follows #296 and the JWE work in #298.
 * - **There is no stable wallet subject identifier.** OID4VP 1.0 §15.5 treats
 *   the issuer signature and the credential-bound public key as linkability
 *   defects that wallets are expected to rotate away; §15.6 tells Verifiers not
 *   to fingerprint the End-User. So `externalSub` CANNOT be keyed on wallet
 *   cryptography (no DID, no JWK thumbprint). The replacement basis for
 *   `user_credentials.external_sub` and account linking (#238) is an OPEN
 *   decision — see #296. Do not invent one here.
 * - **The crypto layer cannot speak the profile yet.** `@qauth-labs/core-crypto`
 *   is EdDSA-only; no signing backend produces `ES256` and there is no JWE
 *   support. HAIP 1.0 §7 requires ES256 at minimum; §5.1 requires response
 *   encryption via `direct_post.jwt`, and §5 constrains it to JWE `alg`
 *   `ECDH-ES` on P-256, `enc` `A128GCM`/`A256GCM`.
 *   Prerequisite, sequenced in #298 — federation code cannot compensate for it.
 *
 * Which profile QAuth targets, and which OID4VP Client Identifier Prefixes it
 * implements, are NOT decided. Nothing above commits QAuth to HAIP conformance;
 * it records what the profile would require. Tracked in #296.
 *
 * @see docs/adr/004-wallet-agnostic-federation.md — §§ "Spec status (2026-07-19)",
 *   "Spec status (2026-07-20)"
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
        'Wallet verification lands in #233 (OID4VP 1.0 authorization request generation + direct_post response intake) and #234 (OID4VP presentation validation), with issuer trust in #236.'
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
