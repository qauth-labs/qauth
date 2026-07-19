/**
 * Standards firewall for hybrid PQC signing (ADR-005, #245; corrected in #274).
 *
 * Every value that tracks an external JOSE specification lives HERE and only
 * here, so a specification bump is a single reviewed edit rather than a scatter
 * of magic strings. The hybrid feature is also flag-gated
 * (`HYBRID_SIGNING_ENABLED`, default off), so churn cannot affect a running
 * deployment.
 *
 * @remarks #274 corrected a mis-attribution: the AKP JWK shape and the
 * `ML-DSA-65` algorithm spelling were previously pinned to the *composite*
 * signature draft, which specifies the concatenated construction QAuth
 * deliberately does NOT implement (see `hybrid-signing.ts`). Both are in fact
 * governed by {@link PQC_JOSE_MLDSA_SPEC}. The emitted wire shape did not
 * change; only the citation was wrong.
 */

/**
 * The governing specification for the ML-DSA JOSE key representation QAuth
 * emits: `kty: 'AKP'`, the `pub` member, and the `ML-DSA-65` algorithm
 * spelling.
 *
 * This is **RFC 9964**, "ML-DSA for JSON Object Signing and Encryption (JOSE)
 * and CBOR Object Signing and Encryption (COSE)" (Standards Track, May 2026).
 * It is the published successor to `draft-ietf-cose-dilithium`, whose final
 * revision was `-11`; the identifiers are therefore **stable and IANA
 * registered**, not draft-churn-prone. RFC 9964 registers `ML-DSA-44`,
 * `ML-DSA-65` and `ML-DSA-87` in the IANA "JSON Web Signature and Encryption
 * Algorithms" registry with usage location `alg`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9964.html
 */
export const PQC_JOSE_MLDSA_SPEC = 'RFC 9964' as const;

/**
 * The governing policy for JOSE algorithm identifiers: **RFC 9864**,
 * "Fully-Specified Algorithms for JSON Object Signing and Encryption (JOSE) and
 * CBOR Object Signing and Encryption (COSE)" (Proposed Standard, October 2025).
 *
 * `ML-DSA-65` is a fully-specified identifier in RFC 9864's sense: it names the
 * parameter set, so no companion curve/parameter member is needed to determine
 * the signing operation. This is why the AKP JWK carries a self-sufficient
 * `alg` rather than a polymorphic identifier plus a `crv`-style discriminator.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9864.html
 */
export const PQC_JOSE_ALG_POLICY_SPEC = 'RFC 9864' as const;

/**
 * The exact member set QAuth emits for a **public** ML-DSA AKP JWK.
 *
 * Per RFC 9964, `kty`, `alg` and `pub` are REQUIRED for AKP keys, and `priv`
 * MUST NOT be present in a public key. `use` is the ordinary RFC 7517 §4.2
 * member (RFC 9964 neither defines nor forbids it) and `kid` is RFC 7517 §4.5,
 * emitted only when the operator configured one.
 *
 * Asserted by the JWKS tests so that adding a member — in particular any
 * private component — is a deliberate, test-breaking change.
 */
export const PQC_AKP_PUBLIC_JWK_MEMBERS = ['kty', 'pub', 'use', 'alg', 'kid'] as const;

/** Protected-header member advertising the parallel PQC algorithm (non-critical). */
export const PQC_HEADER_ALG_MEMBER = 'pqc_alg' as const;

/** Protected-header member carrying the ML-DSA key id, for JWKS resolution (#246). */
export const PQC_HEADER_KID_MEMBER = 'pqc_kid' as const;

/**
 * The `pqc_alg` value for ML-DSA-65. A private QAuth token-header value (never
 * the JWS `alg`, which stays `EdDSA` so stock verifiers accept the token). The
 * spelling follows {@link PQC_JOSE_MLDSA_SPEC}, so a PQC-capable verifier
 * reading `pqc_alg` sees the same IANA-registered identifier it finds in the
 * AKP JWK's `alg`.
 */
export const PQC_ALG_ML_DSA_65 = 'ML-DSA-65' as const;
