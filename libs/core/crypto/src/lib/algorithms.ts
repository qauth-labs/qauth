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
 * `ML-DSA-65` IS a registered JOSE `alg` identifier (RFC 9964), but the `jose`
 * library cannot produce or verify an ML-DSA JWS, so `'ML-DSA-65'` is
 * intentionally EXCLUDED here.
 * Handing a non-JWS algorithm to the token layer is therefore a COMPILE error,
 * not a runtime throw — the strongest algorithm-confusion defence at that
 * boundary. #245 (hybrid composite signing) reaches ML-DSA only through the
 * byte-level `SignatureBackend` seam.
 */
export type JwsAlgorithm = 'EdDSA' | 'RS256';
