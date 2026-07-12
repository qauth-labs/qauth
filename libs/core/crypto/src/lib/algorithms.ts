/**
 * Signature algorithm identifiers understood by the crypto abstraction.
 *
 * Phase 1 (ADR-005) ships a single classical algorithm — Ed25519, expressed as
 * the JOSE `EdDSA` identifier. This is deliberately a named union rather than a
 * bare `string`: it is the extension point where future backends (ML-DSA-65,
 * hybrid composites) are added. Widening this type forces every `sign` /
 * `verify` / key-generation call site to acknowledge the new algorithm at
 * compile time, instead of silently accepting an unknown identifier.
 *
 * @see docs/adr/005-pqc-hybrid-signing.md
 */
export type SignatureAlgorithm = 'EdDSA';
