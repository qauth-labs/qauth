# ADR-005: Post-Quantum Cryptography - Hybrid Signing Roadmap

**Status:** Accepted
**Date:** 2026-03-18
**Authors:** QAuth Team

## Context

Post-quantum cryptography (PQC) standardization has materially advanced. NIST finalized FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) in August 2024, and FIPS 206 (FN-DSA) is expected to finalize in the 2026-2027 period.

For signatures, the practical migration challenge in identity systems is not only algorithm security but protocol and ecosystem readiness:

- The JOSE/JWT ecosystem is still draft-driven for PQC signatures.
- No major identity provider currently ships PQC-signed OAuth/OIDC tokens in production.
- PQC signatures are substantially larger than Ed25519 signatures, which creates immediate transport and storage constraints (header limits, cookies, and JWKS size).

QAuth signs access tokens and ID tokens as a core function. The roadmap must preserve backward compatibility with existing verifiers while building for rapid standards convergence and future pure-PQC operation.

## Decision

QAuth adopts a three-phase PQC roadmap with crypto-agility requirements effective immediately.

### Phase 1 (2026 MVP): Ed25519 with crypto-agile architecture

Use Ed25519 (`alg: EdDSA`) as the production default while implementing algorithm-agnostic crypto interfaces:

- `sign()`
- `verify()`
- `generateKeyPair()`

Additional Phase 1 requirements:

- Runtime-configurable algorithm selection (no compile-time lock-in).
- JWKS support for mixed key types.
- Reference-token support with RFC 7662 introspection as a first-class path.
- No cryptographic business logic in service-layer TypeScript; only through the dedicated crypto abstraction library.

### Phase 2 (Target: 2027): Hybrid signatures (ML-DSA-65 + Ed25519)

Adopt hybrid/composite signing as JOSE/LAMPS drafts mature:

- Classical signature for compatibility (Ed25519).
- PQC signature for forward security (ML-DSA-65, NIST Level 3).

Key compatibility principles:

- Existing consumers that only verify Ed25519 continue to function during migration.
- PQC-capable consumers can validate ML-DSA signatures.
- Hybrid operation is transitional, not the final target.

Implementation expectations:

- JWKS publishes both classical and PQC-capable key material.
- JWS/JWT representation follows the active JOSE composite draft direction at implementation time.
- Token profiles must be reviewed for size impact before enabling hybrid by default.

### Phase 3 (Target: 2028+): Pure-PQC evaluation and cutover planning

Evaluate pure-PQC token signing based on finalized standards and ecosystem support:

- ML-DSA-first path.
- FN-DSA as a candidate where smaller signatures materially improve token transport and storage constraints.

Final cutover timing depends on:

- JOSE RFC finalization and broad library support.
- Operational viability (token/header/cookie budgets).
- Migration readiness of downstream verifiers.

### Crypto Implementation Strategy

QAuth standardizes on a stable TypeScript crypto abstraction library (`libs/core/crypto`) and permits multiple backends behind it:

- Primary production path: native Node.js bindings (for example via napi-rs).
- Secondary/dev fallback: pure TypeScript implementation when needed for portability or test environments.

The architecture decision is backend-agnostic by design: business logic must not depend on specific cryptographic libraries or implementation technology (native vs WASM).

## Alternatives Considered

### Wait for full ecosystem maturity before starting PQC work

Rejected. This postpones crypto-agility and increases migration risk. Architecture changes required for token size and key agility must start in the 2026 MVP.

### Pure PQC immediately

Rejected. Current OAuth/OIDC verifier ecosystems are not ready for an immediate PQC-only cutover, and compatibility would break for existing integrations.

### Keep self-contained JWTs as the only token model

Rejected. PQC signatures can make token size operationally expensive. Reference tokens with introspection must be available to avoid header and cookie limits becoming blockers.

### Commit to a single crypto backend technology

Rejected. The abstraction layer should allow backend evolution as standards, audits, and performance profiles change.

## Consequences

### Positive

- Preserves compatibility while enabling incremental PQC rollout.
- Reduces architectural risk by introducing crypto-agility now.
- Keeps token strategy viable under larger PQC signature sizes.
- Positions QAuth to adopt finalized JOSE PQC standards quickly.

### Negative

- Additional engineering complexity in dual-algorithm and dual-token-mode support.
- Larger tokens and keys increase pressure on network/header/storage budgets.
- More operational testing required across verifier compatibility matrices.

### Neutral

- Ed25519 remains the classical baseline during migration.
- Existing JWKS and key rotation processes remain, but expand to additional key types.

## Related

- [ADR-001: JWT Key Management Strategy](./001-jwt-key-management.md)
- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [RFC 7662 - OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [IETF draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)
- [IETF draft-prabel-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-prabel-jose-pq-composite-sigs/)
- [IETF draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
