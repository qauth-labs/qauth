/**
 * Signature algorithm identifiers understood by the crypto abstraction.
 *
 * ADR-005's PQC roadmap: Phase 1 ships the classical `EdDSA` (JOSE identifier);
 * `ML-DSA-65` (FIPS 204, NIST Level 3) is added by #243 as a byte-level
 * signing backend (see the `SignatureBackend` seam). This is deliberately a
 * named union rather than a bare `string`: it is the extension point where
 * future backends (hybrid composites, #245) are added, and backend dispatch in
 * the `backend-registry` switches EXHAUSTIVELY over it — a newly added
 * algorithm must be handled there before the code compiles. Existing call
 * sites keep compiling unchanged when the union widens.
 *
 * @see docs/adr/005-pqc-hybrid-signing.md
 */
export type SignatureAlgorithm = 'EdDSA' | 'ML-DSA-65';

/**
 * The subset of {@link SignatureAlgorithm}, plus classical JOSE algorithms that
 * are NOT post-quantum backends, that the jose-based JWT token layer (`sign` /
 * `verify` / the key-management import/generate functions) can carry in a
 * compact JWS today: `EdDSA` (Ed25519) and `RS256` (RSASSA-PKCS1-v1_5 + SHA-256).
 *
 * `RS256` (#309) is added to unblock OIDC Basic/Config OP certification (#286):
 * the conformance suite hard-fails an EdDSA-only OP because it requires the ID
 * token to be verifiable as `RS256`. `jose` produces and verifies RS256 JWS
 * natively via `generateKeyPair`/`importPKCS8`/`importSPKI`/`SignJWT`/`jwtVerify`,
 * so widening this union is all the token layer needs — no byte-level backend.
 * RS256 is DELIBERATELY absent from {@link SignatureAlgorithm}: that union is
 * the byte-level `SignatureBackend` dispatch seam (see `backend-registry`), and
 * RS256 is jose-carried, so adding it there would demand a spurious backend.
 *
 * `ES256` (#298) is ECDSA on P-256 with SHA-256. It is added for the WALLET
 * FEDERATION surface (OID4VP / HAIP §7, which names it as the one mandatory
 * signature algorithm) — request-object signing, and verification of
 * wallet-supplied KB-JWTs, credential signatures, and status lists. Practically
 * every wallet's secure element does P-256 and nothing else, so no meaningful
 * interop happens without it.
 *
 * ES256 is DELIBERATELY absent from {@link SignatureAlgorithm}, for exactly the
 * reason `RS256` is: that union is the byte-level `SignatureBackend` dispatch
 * seam, `jose` carries ES256 natively, and adding it there would demand a
 * spurious backend AND drag a wallet-federation algorithm into the ADR-005
 * hybrid-signing path that issues QAuth's OWN tokens. Keeping it out is what
 * makes "QAuth's token issuance stays EdDSA/hybrid" a structural property rather
 * than a convention: `PqcBackendSelection`, `getSignatureBackend`, and
 * `SIGNING_ALGORITHM_MODE` cannot even name `ES256`.
 *
 * Widening this union does NOT widen what any verifier accepts. Acceptance is
 * decided per call site by `VerifyOptions.algorithms`, which every verifier
 * pins explicitly (RFC 9700 / the classic JOSE algorithm-confusion class);
 * `verifyAccessToken` still pins `['EdDSA']` and must keep doing so.
 *
 * `ML-DSA-65` IS a registered JOSE `alg` identifier (RFC 9964), but the `jose`
 * library cannot produce or verify an ML-DSA JWS, so `'ML-DSA-65'` is
 * intentionally EXCLUDED here.
 * Handing a non-JWS algorithm to the token layer is therefore a COMPILE error,
 * not a runtime throw — the strongest algorithm-confusion defence at that
 * boundary. #245 (hybrid composite signing) reaches ML-DSA only through the
 * byte-level `SignatureBackend` seam.
 */
export type JwsAlgorithm = 'EdDSA' | 'RS256' | 'ES256';

/**
 * The elliptic curve every ES256 signature and every ECDH-ES key agreement in
 * this library is pinned to (#298).
 *
 * HAIP §5 mandates P-256 for response-encryption key agreement and §7 mandates
 * `ES256` (which is P-256 by definition, RFC 7518 §3.4) for signatures. `jose`
 * pins the curve itself when importing a JWK for `ES256`, but NOT when importing
 * one for `ECDH-ES` — a P-384 JWK imports happily — so this library validates it
 * explicitly at every JWK boundary. See `importEncryptionPublicJwk`.
 */
export const JOSE_P256_CURVE = 'P-256';

/**
 * JWE key-management (`alg`) identifiers this library supports (#298).
 *
 * `ECDH-ES` — Ephemeral-Static Elliptic Curve Diffie-Hellman in DIRECT key
 * agreement mode (RFC 7518 §4.6): the agreed secret IS the content encryption
 * key, so there is no wrapped CEK. This is what HAIP §5 mandates for
 * `direct_post.jwt` response encryption, and it is deliberately the ONLY member:
 * the key-wrapping variants (`ECDH-ES+A128KW` and friends) are not required by
 * the profile, and `RSA1_5` — the classic JWE attack surface (Bleichenbacher) —
 * must never become reachable.
 */
export const JWE_KEY_AGREEMENT_ALGORITHMS = ['ECDH-ES'] as const;

/** A JWE key-management algorithm this library supports — see {@link JWE_KEY_AGREEMENT_ALGORITHMS}. */
export type JweKeyAgreementAlgorithm = (typeof JWE_KEY_AGREEMENT_ALGORITHMS)[number];

/**
 * JWE content-encryption (`enc`) identifiers this library supports (#298).
 *
 * Both AES-GCM variants HAIP §5 requires a Verifier to advertise in
 * `encrypted_response_enc_values_supported`, and nothing else. The AES-CBC-HMAC
 * family is excluded on purpose: it is not required by the profile, and the
 * encrypt-then-MAC composition has a far worse implementation-error history than
 * a single AEAD.
 */
export const JWE_CONTENT_ENCRYPTION_ALGORITHMS = ['A128GCM', 'A256GCM'] as const;

/** A JWE content-encryption algorithm this library supports — see {@link JWE_CONTENT_ENCRYPTION_ALGORITHMS}. */
export type JweContentEncryptionAlgorithm = (typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS)[number];
