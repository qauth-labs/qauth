# ADR-005: Post-Quantum Cryptography - Hybrid Signing Roadmap

**Status:** Accepted
**Date:** 2026-03-18
**Authors:** QAuth Team

> **Implementation status (2026-06-24):** Accepted as design; not implemented. Phase 1 signs JWTs with Ed25519; the hybrid ML-DSA transition is Phase 5 (long-term per [ADR-007](./007-mcp-first-positioning.md)).
>
> **Amendment (2026-07-18, #243):** The crypto-agile abstraction (`libs/core/crypto`, #242) now has a byte-level `SignatureBackend` seam with a pure-TypeScript **ML-DSA-65** (FIPS 204) backend over `@noble/post-quantum` — shipped _before_ the napi-rs native binding (#244), reversing this ADR's "native primary" framing to prioritize lower release risk. `SIGNING_ALGORITHM_MODE` is the runtime algorithm-selection flag (default `ed25519`, PQC opt-in). This delivers the ML-DSA-65 primitive _capability_ only: QAuth still issues Ed25519-signed JWTs — there is no finalized JOSE `alg` for ML-DSA, so the JWS carrier (#245), JWKS/AKP publication (#246), and introspection-first token posture (#247) remain future work. No ML-DSA-signed token is emitted yet.
>
> **Amendment (2026-07-18, #244):** A native `aws-lc-rs` ML-DSA-65 backend (`libs/core/crypto-native`, napi-rs) now implements the _same_ `SignatureBackend` interface — byte-for-byte interoperable with the noble backend (shared 32-byte seed; cross-verified signatures) and ~30–40× faster. The local binding + benchmark + interop tests ship here; the **per-platform CI prebuild-matrix is the explicitly deferred half** of #244. Backends are swappable with zero business-logic change — the epic's central promise, now proven end-to-end.
>
> **Amendment (2026-07-18, #245) — HYBRID CONSTRUCTION & DELIBERATE DRAFT DEVIATION (for the #248 review):** Hybrid signing uses a **detached PARALLEL** signature, NOT the strict single-alg-id + concatenated-signature composite of the LAMPS/prabel drafts. A hybrid token IS an ordinary Ed25519 compact JWS (JWS `alg` stays `EdDSA`); a stock JOSE verifier validates it unmodified and ignores the non-critical `pqc_alg`/`pqc_kid` protected-header members — QAuth's hard compatibility requirement (AC#2). The ML-DSA-65 signature covers the **identical JWS signing-input** (`base64url(header).base64url(payload)`) and is carried alongside as a separate `pqcSignature` field, never inside the compact string. **Why deviate:** a strict composite is unparseable by an unmodified classical verifier, breaking every existing Ed25519 integration during rollout. **For the security review:** downgrade resistance within a single bearer token is a _verifier-policy_ control (`requirePqc`), not cryptographic, because `pqc_alg` must be non-critical; and a bare bearer token does not carry the detached PQC signature to a resource server, so full PQC verification needs an out-of-band channel (introspection, #247/#249). Key substitution and tamper-with-strip are prevented by the Ed25519 signature covering `pqc_kid` and the shared signing-input. `PQC_JOSE_COMPOSITE_DRAFT` is pinned for the ML-DSA JOSE alg spelling + AKP JWK shape only; its exact revision MUST be reconfirmed on the datatracker before enabling by default. The whole feature is `HYBRID_SIGNING_ENABLED` (default off) until #248 signs off.
>
> **Amendment (2026-07-18, #247) — TOKEN SIZE (MEASURED) & REFERENCE-TOKEN DEFAULT:** Sizes are now measured, not estimated (`libs/server/jwt/src/lib/token-size.bench.test.ts`), on a representative user-context token:
>
> | Artifact                                     | Bytes    | 4 KB cookie | 2 KB URL | 8 KB header     |
> | -------------------------------------------- | -------- | ----------- | -------- | --------------- |
> | Access bearer JWS (`.token`)                 | **716**  | ✅          | ✅       | ✅              |
> | ID-token bearer JWS                          | **576**  | ✅          | ✅       | ✅              |
> | Detached ML-DSA-65 sig (`.pqcSignature`)     | **4412** | ❌ over     | ❌ over  | fits (54%)      |
> | Compound if inlined (`token`+`pqcSignature`) | **5128** | ❌ over     | ❌ over  | fits (reckless) |
>
> The detached design (#245) keeps the **bearer token a plain ~716 B Ed25519 JWS** in every channel; the fixed ~4412 B ML-DSA-65 signature (3309 raw bytes) is the only large artifact and alone overflows a cookie and a URL. **Decision:** `PQC_TOKEN_DELIVERY` selects delivery when hybrid is on; **`reference` (introspection-first, RFC 7662) is the DEFAULT**, so the PQC material travels in an introspection POST body with no header/cookie ceiling. `self-contained` is permitted only with an explicit `PQC_SELF_CONTAINED_ACK=true` (large-buffer, header-only deployments) — enforced fail-fast in `cryptoEnvSchema`, so **no deployment can silently ship tokens that break header/cookie limits** (AC#3). Introspection is confirmed as the correct PQC-delivery channel; wiring live hybrid issuance + returning the PQC component from `/introspect` is the #248/#249 integration, gated on the security review.
>
> **Amendment (2026-07-18, #248) — SECURITY-GATE OUTCOME (VERDICT: CONDITIONAL PASS):** A three-dimension `auth-specialist` security review of the merged PQC surface (#243–247) — construction/downgrade/tamper/confusion, key-lifecycle/backend-swap, and supply-chain/standards/config-gate, with adversarial re-verification of every high/critical claim — found **zero confirmed HIGH/CRITICAL defects**. Independently verified: both signatures cover a byte-identical JWS signing-input that includes the Ed25519-signed `pqc_alg`/`pqc_kid`; `requirePqc=true` provably rejects a stripped PQC signature; private seeds are non-extractable by default and never reach a public path (JWKS is public-only, type-guarded); verify is fail-closed with a single error vocabulary; `aws-lc-rs` is exact-pinned (`=1.17.3`, committed `Cargo.lock`) with no download-and-execute vector; and the config gate genuinely fails fast (default OFF, PQC opt-in). The capability is cryptographically sound, but **`HYBRID_SIGNING_ENABLED` stays default-OFF everywhere pending the pre-default-on checklist** in [`docs/security/005-pqc-hybrid-signing-review.md`](../security/005-pqc-hybrid-signing-review.md). 13 non-blocking findings (4 MEDIUM, 4 LOW, 5 INFO) are logged there; the load-bearing ones before default-on: **correct the JOSE draft pin** (`PQC_JOSE_COMPOSITE_DRAFT` points at the concatenated-composite draft, but the AKP/`ML-DSA-65` JWK shape actually derives from `draft-ietf-cose-dilithium` — no live interop break, but the churn-firewall cites the wrong doc); **make downgrade resistance issuer-signed** (treat the signed `pqc_alg` as binding when live verification is wired, #249); **route the PQC backend through the operator `getSignatureBackend` allowlist**; **unify `MlDsaKey.material()` across the noble/native backends**; and **establish a reproducible/attested native-build channel** before enabling the native backend anywhere. None block merging the surface; each gates the first default-on deployment.

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
