# ADR-005: Post-Quantum Cryptography — Hybrid Signing Roadmap

**Status:** Accepted
**Date:** 2026-03-18
**Revised:** 2026-04-26
**Authors:** QAuth Team

## Context

Post-quantum cryptography (PQC) standardization has materially advanced. NIST finalized FIPS 203
(ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) in August 2024, and FIPS 206 (FN-DSA) is
expected to finalize in the 2026–2027 period.

For signatures, the practical migration challenge in identity systems is not only algorithm
security but protocol and ecosystem readiness:

- The JOSE/JWT ecosystem is still draft-driven for PQC signatures.
- No major identity provider currently ships PQC-signed OAuth/OIDC tokens in production.
- PQC signatures are substantially larger than Ed25519 signatures (ML-DSA-65: ~3,309 B vs
  Ed25519: 64 B), which creates immediate transport and storage constraints (HTTP header limits,
  cookies, and JWKS size).
- OID4VP Verifiable Presentation responses carry their own JWS envelopes; hybrid signing must
  work across both OIDC access/ID tokens **and** VP tokens without breaking existing verifiers.

QAuth signs access tokens, ID tokens, and (Phase 4+) VP response tokens as a core function. The
roadmap must preserve backward compatibility with existing verifiers while building for rapid
standards convergence and future pure-PQC operation.

## Implementation Status

| Phase                                       | Status                                                                      | Target   |
| ------------------------------------------- | --------------------------------------------------------------------------- | -------- |
| Phase 1 — Ed25519 + crypto-agile interfaces | ✅ Ed25519 signing live; `libs/core/crypto` interface **not yet extracted** | MVP 2026 |
| Phase 2 — Hybrid ML-DSA-65 + Ed25519        | 📋 Designed, not implemented                                                | 2027     |
| Phase 3 — Pure-PQC evaluation               | 📋 Planned                                                                  | 2028+    |

> **Gap:** `libs/core/crypto` abstraction library is specified here but not yet present in the
> repository. Current signing logic lives directly in `libs/server/jwt/` using `jose`. Extracting
> it to the abstraction layer is a Phase 1 completion item tracked in the MVP milestone.

## Decision

QAuth adopts a three-phase PQC roadmap with crypto-agility requirements effective immediately.

### Phase 1 (2026 MVP): Ed25519 with crypto-agile architecture

Use Ed25519 (`alg: EdDSA`) as the production default while implementing algorithm-agnostic
crypto interfaces in `libs/core/crypto`:

```typescript
// libs/core/crypto/src/index.ts
export type Algorithm = 'EdDSA' | 'ML-DSA-65' | 'composite-ML-DSA-65+Ed25519';

export interface KeyPair {
  privateKey: CryptoKey | Uint8Array;
  publicKey: CryptoKey | Uint8Array;
  algorithm: Algorithm;
  kid: string;
}

export interface CryptoBackend {
  sign(payload: Uint8Array, privateKey: KeyPair): Promise<Uint8Array>;
  verify(payload: Uint8Array, signature: Uint8Array, publicKey: KeyPair): Promise<boolean>;
  generateKeyPair(algorithm: Algorithm): Promise<KeyPair>;
  toJWK(keyPair: KeyPair): JsonWebKey;
}
```

Additional Phase 1 requirements:

- Runtime-configurable algorithm selection via `CRYPTO_ALGORITHM` env var (no compile-time
  lock-in).
- JWKS endpoint (`/.well-known/jwks.json`) publishes all active public keys with `kid` and `alg`
  fields; supports mixed key types for graceful rotation.
- Reference-token support with RFC 7662 introspection as a first-class path — mandatory for
  the hybrid phase where token size becomes a constraint.
- No cryptographic business logic in service-layer TypeScript; all signing/verification goes
  through `CryptoBackend`.

**Phase 1 backend:** `libs/core/crypto` ships a `JoseCryptoBackend` wrapping the existing
`jose` library for Ed25519. This is the only backend required for MVP.

### Phase 2 (Target: 2027): Hybrid signatures (ML-DSA-65 + Ed25519)

Adopt hybrid/composite signing as JOSE/LAMPS drafts mature:

- Classical signature for backward compatibility (Ed25519).
- PQC signature for forward security (ML-DSA-65, NIST FIPS 204, Level 3 — minimum floor
  recommended by BSI and ANSSI).

**Token representation:** JWS with composite algorithm following
`draft-prabel-jose-pq-composite-sigs` at the revision current at implementation time. The IANA
algorithm identifier will be `id-MLDSA65-Ed25519` (or successor as the draft stabilizes).

**OIDC/OID4VP flow specifics:**

| Token type                  | Signing change                                                             | Verifier impact                                                                                         |
| --------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Access token (JWT)          | Composite header + dual signature                                          | Resource servers checking only Ed25519 `alg` continue to work; PQC-capable verifiers validate ML-DSA-65 |
| ID token                    | Same as access token                                                       | OIDC RPs unaffected if they ignore unknown `alg` values                                                 |
| VP token (OID4VP, Phase 4+) | Composite signing on the inner JWS envelope of the Verifiable Presentation | Wallet verifiers must be updated; QAuth's VP validation endpoint accepts both single and composite      |
| Introspection response      | Reference token → introspection returns claims; no JWT size impact         | No change to introspection consumers                                                                    |

**Key compatibility principles:**

- Existing consumers that only verify Ed25519 continue to function during migration.
- PQC-capable consumers validate ML-DSA-65 signature independently.
- Hybrid operation is transitional, not the final target.

**Implementation:**

- `NativeCompositeBackend` implements `CryptoBackend` using `napi-rs` wrapping `aws-lc-rs`
  (AWS-LC, production-hardened BoringSSL fork with FIPS 140-3 validation in progress).
- `NobleCompositeBackend` implements `CryptoBackend` using `@noble/post-quantum` (pure
  TypeScript, audited) as the dev/CI fallback — no native build tooling required.
- Backend selection: `CRYPTO_BACKEND=native|noble` env var; defaults to `native` in production,
  `noble` in CI.
- JWKS publishes both `Ed25519` and `ML-DSA-65` key entries with distinct `kid` values.

**Token size budget analysis:**

| Component                         | Ed25519    | ML-DSA-65    | Composite    |
| --------------------------------- | ---------- | ------------ | ------------ |
| Signature                         | 64 B       | 3,309 B      | ~3,373 B     |
| JWT header+payload (typical)      | ~300 B     | ~300 B       | ~300 B       |
| Base64url overhead                | ×1.33      | ×1.33        | ×1.33        |
| **Total JWT**                     | **~480 B** | **~4,800 B** | **~4,900 B** |
| HTTP header budget (8 KB typical) | ✅         | ⚠️ tight     | ⚠️ tight     |
| Cookie budget (4 KB)              | ✅         | ❌           | ❌           |

**Mitigation:** Reference tokens (opaque string, ~43 B) with RFC 7662 introspection eliminate
the token-size problem for cookie and header-constrained deployments. QAuth defaults to reference
tokens when `CRYPTO_ALGORITHM=composite-ML-DSA-65+Ed25519`.

### Phase 3 (Target: 2028+): Pure-PQC evaluation and cutover planning

Evaluate pure-PQC token signing based on finalized standards and ecosystem support:

- ML-DSA-65-first path.
- FN-DSA (NIST FIPS 206, ~666 B signatures) as a candidate where smaller signatures make
  self-contained PQC JWTs practical without reference-token fallback.

Final cutover timing depends on:

- JOSE RFC finalization and broad library support.
- Operational viability (token/header/cookie budgets under pure-PQC).
- Migration readiness of downstream verifiers.

### Crypto Implementation Strategy

QAuth standardizes on `libs/core/crypto` as the single abstraction boundary. All backends
implement `CryptoBackend`. Business logic never imports `jose`, `aws-lc-rs`, or
`@noble/post-quantum` directly.

| Backend                  | Package                 | Use case                       |
| ------------------------ | ----------------------- | ------------------------------ |
| `JoseCryptoBackend`      | `jose`                  | Phase 1 production (Ed25519)   |
| `NativeCompositeBackend` | `napi-rs` + `aws-lc-rs` | Phase 2 production (composite) |
| `NobleCompositeBackend`  | `@noble/post-quantum`   | Dev, CI, and WASM environments |

Backend selection is runtime-configurable; swapping the backend requires no changes to
`apps/auth-server` or any other consumer of `libs/core/crypto`.

## Alternatives Considered

### Wait for full ecosystem maturity before starting PQC work

Rejected. This postpones crypto-agility and increases migration risk. Architecture changes
required for token size and key agility must start in the 2026 MVP. NLnet NGI Zero and Sovereign
Tech Fund grant narratives require demonstrable PQC-readiness now.

### Pure PQC immediately

Rejected. Current OAuth/OIDC verifier ecosystems are not ready for an immediate PQC-only
cutover, and compatibility would break for existing integrations. Cookie-constrained deployments
would be completely broken without reference-token fallback.

### Keep self-contained JWTs as the only token model

Rejected. ML-DSA-65 signatures (~3,309 B) make self-contained JWTs operationally expensive.
Reference tokens with introspection must be available to avoid HTTP header and cookie limits
becoming blockers. This is especially acute for OID4VP flows where VP tokens may nest inside
authorization responses.

### Commit to a single crypto backend technology

Rejected. The abstraction layer must allow backend evolution as standards, audits, and
performance profiles change. Locking to `jose` prevents the Phase 2 native-binding path; locking
to `napi-rs` breaks CI environments without Rust toolchains.

### Apply composite signing only to access tokens, not VP tokens

Rejected. Inconsistent PQC coverage across token types creates a partial-security posture that
is harder to reason about and harder to communicate in grant applications and academic papers.
The `CryptoBackend` abstraction applies uniformly across all token types.

## Consequences

### Positive

- Preserves compatibility while enabling incremental PQC rollout.
- Reduces architectural risk by introducing crypto-agility now.
- Keeps token strategy viable under larger PQC signature sizes via reference-token fallback.
- Positions QAuth to adopt finalized JOSE PQC standards quickly.
- Uniform `CryptoBackend` interface across OIDC and OID4VP token types.
- NLnet / Sovereign Tech Fund grant applications can point to a concrete implementation plan
  with measurable milestones (Phase 1 interface extraction, Phase 2 composite backend).

### Negative

- Additional engineering complexity in dual-algorithm and dual-token-mode support.
- Larger tokens and keys increase pressure on network/header/storage budgets (mitigated by
  reference tokens).
- More operational testing required across verifier compatibility matrices.
- `libs/core/crypto` extraction from `libs/server/jwt/` is a refactor that touches every
  signing/verification call site in `apps/auth-server`.

### Neutral

- Ed25519 remains the classical baseline during migration.
- Existing JWKS and key rotation processes remain, but expand to additional key types.
- `JoseCryptoBackend` wraps the existing `jose` dependency — no new runtime dependency for
  Phase 1.

## Related

- [ADR-001: JWT Key Management Strategy](./001-jwt-key-management.md)
- [ADR-004: Wallet-Agnostic VC Federation via SIOPv2/OID4VP](./004-wallet-agnostic-federation.md)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 206 — FN-DSA (draft)](https://csrc.nist.gov/pubs/fips/206/ipd)
- [RFC 7662 — OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [IETF draft-prabel-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-prabel-jose-pq-composite-sigs/)
- [IETF draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
- [IETF draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)
- [aws-lc-rs](https://github.com/aws/aws-lc-rs)
- [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum)
