/**
 * Signature algorithm identifiers understood by the crypto abstraction.
 *
 * Phase 1 (ADR-005) ships a single classical algorithm — Ed25519, expressed as
 * the JOSE `EdDSA` identifier. This is deliberately a named union rather than a
 * bare `string`: it is the extension point where future backends (ML-DSA-65,
 * hybrid composites) are added. Callers can never pass an identifier the
 * abstraction does not understand, and the backend dispatch inside `sign` /
 * `verify` / the key functions can switch exhaustively over this union, so a
 * newly added algorithm must be handled there before the code compiles.
 * Existing call sites keep compiling unchanged when the union widens.
 *
 * @see docs/adr/005-pqc-hybrid-signing.md
 */
export type SignatureAlgorithm = 'EdDSA';
