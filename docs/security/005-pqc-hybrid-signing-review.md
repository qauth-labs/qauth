# Security Gate Review — ADR-005 PQC Hybrid Signing

| Field                    | Value                                                                                                                                         |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Issue                    | [#248](https://github.com/qauth-labs/qauth/issues/248) — security gate for the ADR-005 PQC hybrid-signing surface                             |
| ADR                      | [ADR-005: PQC Hybrid Signing](../adr/005-pqc-hybrid-signing.md)                                                                               |
| Merged work under review | #243 (noble ML-DSA-65 backend), #244 (native `aws-lc-rs` backend), #245 (hybrid construction), #246 (AKP JWKS), #247 (token-size posture)     |
| Review date              | 2026-07-18                                                                                                                                    |
| Method                   | 3 `auth-specialist` dimension reviews + adversarial re-verification of high/critical claims + synthesizer re-read of the merged files         |
| **Verdict**              | **CONDITIONAL PASS** — zero confirmed HIGH/CRITICAL; `HYBRID_SIGNING_ENABLED` stays default-**OFF** pending the pre-default-on checklist (§8) |
| Confirmed blockers       | **0**                                                                                                                                         |
| Findings                 | 4 MEDIUM, 4 LOW, 5 INFO (none gate-blocking)                                                                                                  |

## 1. Scope and gate question

This is the AC#1/AC#2 security gate for the merged PQC hybrid-signing crypto surface. The gate question is narrow and explicit:

> Are there HIGH or CRITICAL crypto defects in the merged code that must block ever flipping `HYBRID_SIGNING_ENABLED` from its default `false` to `true` anywhere?

Surface reviewed (all merged on `main`):

- `libs/core/crypto/src/lib/backends/ml-dsa-65.ts` — noble ML-DSA-65 `SignatureBackend`
- `libs/core/crypto/src/lib/hybrid-signing.ts` — `signHybrid` / `verifyHybrid`, detached-parallel construction
- `libs/core/crypto/src/lib/hybrid-constants.ts` — PQC header members, draft pin
- `libs/core/crypto/src/lib/keys.ts` — `MlDsaKey`, seed-canonical private form
- `libs/core/crypto/src/lib/primitives.ts` — `SignatureBackend` contract + `getSignatureBackend` allowlist
- `libs/core/crypto/src/lib/signing.ts` — `sign()` protected-header merge, `verify()`
- `libs/core/crypto-native/src/{index.ts,lib.rs,addon.ts}`, `Cargo.toml`, `Cargo.lock` — native `aws-lc-rs` backend
- `libs/server/jwt/src/lib/hybrid-jwt-service.ts` — hybrid access/id-token wrappers
- `libs/server/jwt/src/lib/jwks.ts` — AKP JWK export (public-only)
- `libs/fastify/plugins/jwt/src/lib/fastify-plugin-jwt.ts` — boot-time ML-DSA public-key derivation
- `libs/server/config/src/lib/schemas/crypto.ts` — `HYBRID_SIGNING_ENABLED` + posture coupling
- `apps/auth-server/src/app/app.ts`, `apps/auth-server/src/config/env.ts` — boot wiring

## 2. Established design context (not re-litigated)

Per the ADR-005 amendments (#245), the hybrid construction is a **detached-parallel** signature and _deliberately_ not the strict LAMPS/prabel composite: the token is an ordinary Ed25519 compact JWS, the ML-DSA-65 signature is detached in a separate `pqcSignature` field, and `pqc_alg`/`pqc_kid` are **non-critical** protected-header members to preserve stock-JOSE-verifier compatibility (AC#2). Downgrade resistance within a single bearer token is, by documented design, a **verifier-policy** control (`requirePqc`), not a cryptographic one. This review assessed whether that documented mitigation actually holds in code; it did not re-propose the architecture. `HYBRID_SIGNING_ENABLED` defaults **OFF** and hybrid issuance is **not wired into live routes yet**, so no runtime security posture depends on this code today.

## 3. Methodology

Three `auth-specialist` reviewers each took one dimension of the mandated five tasks, reporting findings with `file:line` and a concrete attack/failure path:

1. **Construction / downgrade / tamper / confusion** — the detached-parallel JWS carrier and its resistance to strip, mix-and-match, and algorithm-confusion attacks (#248 task 2, 3a).
2. **Key lifecycle / backend swap** — key generation, storage, export, JWKS, rotation, and the noble↔native backend-swap safety property (#248 task 1, 3b).
3. **Supply chain / standards / config gate** — native-binding provenance and pinning, AKP/JOSE draft conformance, and the `HYBRID_SIGNING_ENABLED` config gate (#248 task 4, 5).

Every claim that could plausibly reach HIGH/CRITICAL was re-tested against a real attack path and against the test suites (`hybrid-signing.test.ts`, `crypto-native/src/index.test.ts`). **Process note:** dimension 3's first automated pass failed on a tooling error (structured-output cap) and was re-run to completion as a focused `auth-specialist` review; its findings are fully incorporated below.

## 4. Threat model and gate criterion

- **CRITICAL** — key/secret exposure, or a trivially forgeable/bypassable signature.
- **HIGH** — exploitable downgrade/confusion/tamper under a realistic threat model, or a supply-chain RCE vector.
- **MEDIUM** — defense-in-depth gap or spec non-conformance without a direct exploit.
- **LOW / INFO** — hardening.

Only HIGH/CRITICAL block the gate.

## 5. Positive security confirmations (independently verified)

- **Signing-input binding.** Both signatures cover a byte-identical preimage: the ML-DSA signature signs `extractJwsSigningInput(token)`, literally sliced from the jose-produced token (`hybrid-signing.ts:70-76,95-96`), and that preimage includes the Ed25519-signed `pqc_alg`/`pqc_kid` header. Any header/payload mutation breaks both signatures; neither half can be swapped (`hybrid-signing.test.ts` mix-and-match and single-byte-mutation both rejected).
- **Algorithm confusion closed.** `verifyHybrid` applies `algorithms: ['EdDSA']` _after_ the options spread (`hybrid-signing.ts:123`), so a caller cannot inject `none`/HS. The single PQC algorithm is checked against a constant and fails closed (`:136-140`). `MlDsaKey.alg` is a structural dispatch discriminant, so a key can only be used with its own algorithm.
- **`requirePqc=true` prevents the strip-downgrade.** An absent/empty PQC signature is rejected (`hybrid-signing.ts:127-132`), tested in `hybrid-signing.test.ts`.
- **No verify oracle.** Both backends normalize a forged signature (`false`) and a malformed input to the _same_ `CryptoVerificationError('invalid')` (`ml-dsa-65.ts:91-108`; native `index.ts:79-90` backed by Rust `lib.rs:60-67` returning `Ok(false)`). Verify uses only public material.
- **No key/secret exposure.** Private keys are non-extractable by default (`keys.ts:66`); `exportKey` throws on a non-extractable private key; the canonical seed never reaches a public path. **JWKS is public-only** and type-guarded (`jwks.ts:48-57`, no `priv`/`d`).
- **Supply chain has no live RCE vector.** `aws-lc-rs` is exact-pinned `=1.17.3` with a committed `Cargo.lock`; no `.node`/`target/` is committed (gitignored, `git ls-files '*.node'` empty); the napi loader resolves **relative to the module** (`addon.ts:14,26-29`) — no cwd/env/`NODE_PATH`/bare-specifier injection. `aws-lc-sys 0.43.0` uses pregenerated bindings (no `bindgen`/libclang).
- **Config gate fails fast and defaults off.** `HYBRID_SIGNING_ENABLED=true` without `SIGNING_ALGORITHM_MODE='ed25519+ml-dsa-65'` **and** a key aborts boot (`crypto.ts` superRefine); the `PQC_SELF_CONTAINED_ACK` guard is `z.enum`-typed and fail-closed (a mis-cased value is a loud parse error). Hybrid cannot be half-configured into silent classical-only signing.

## 6. Findings

All findings are **non-gate-blocking** (0 HIGH/CRITICAL). IDs are referenced by the pre-default-on checklist (§8).

| ID  | Sev    | Title                                                                                                                          | Location                                               |
| --- | ------ | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------ |
| F1  | MEDIUM | Downgrade decision reads only the _unsigned_ transport `pqcSignature`; the Ed25519-authenticated `pqc_alg` header is ignored   | `hybrid-signing.ts:126`                                |
| F2  | MEDIUM | `MlDsaKey.material()` has divergent semantics across noble/native backends — the key **object** is not backend-portable        | `crypto-native/src/index.ts:48`                        |
| F3  | MEDIUM | AKP/`ML-DSA-65` JWK shape is pinned to the wrong (and WG-superseded) IETF draft                                                | `hybrid-constants.ts:23`, `jwks.ts:35`                 |
| F4  | MEDIUM | Native-binding provenance gap: the deferred prebuild matrix has no reproducible-build / attestation / `cargo audit` story      | `crypto-native/Cargo.toml:16`, `addon.ts`              |
| F5  | LOW    | ML-DSA key must be resolved from the _signed_ `pqc_kid` header, not the unsigned `pqcKid` transport field                      | `hybrid-signing.ts:117`                                |
| F6  | LOW    | `sign()` header-merge order lets a caller header override the canonical `alg` or inject `crit`                                 | `signing.ts:70`                                        |
| F7  | LOW    | Runtime algorithm allowlist is bypassed at its live call sites (hardcoded `['ML-DSA-65']` instead of the operator-enabled set) | `fastify-plugin-jwt.ts:87`, `hybrid-signing.ts:96,144` |
| F8  | LOW    | Config gate validates ML-DSA seed _presence_ but not base64url decodability / 32-byte length                                   | `crypto.ts:37`                                         |
| F9  | INFO   | Rotation unimplemented; `kid` uniqueness across OKP/AKP entries unconstrained                                                  | `fastify-plugin-jwt.ts:135`                            |
| F10 | INFO   | Transient ML-DSA private key not zeroized after boot-time public-key derivation                                                | `fastify-plugin-jwt.ts:88`                             |
| F11 | INFO   | Hybrid path hardcodes the noble backend, bypassing `SIGNING_ALGORITHM_MODE` and the native backend                             | `hybrid-signing.ts:1`                                  |
| F12 | INFO   | `unstable` `aws-lc-rs` feature on the signing path — acceptably documented and exact-pinned                                    | `crypto-native/Cargo.toml:14`                          |
| F13 | INFO   | `pqc_alg` / `pqc_kid` are unregistered private JOSE header parameters                                                          | `hybrid-constants.ts:26`                               |

### Notable MEDIUM detail

- **F1 (downgrade-as-policy is not yet issuer-signed).** `verifyHybrid`'s downgrade decision keys on the presence of the transport `pqcSignature`, not on the Ed25519-signed `pqc_alg` in the protected header. Today this is sound because `requirePqc` is the documented control and issuance is unwired; but when live verification lands (#249), a signed `pqc_alg` should be treated as **binding** so downgrade resistance becomes an issuer-signed control rather than a per-call flag. Tracked as checklist item 3.
- **F3 (wrong draft pin).** `PQC_JOSE_COMPOSITE_DRAFT = 'draft-prabel-jose-pq-composite-sigs-02'` is designated as the draft-churn firewall, but `kty:'AKP'` / `pub` / the `ML-DSA-65` alg spelling actually come from **`draft-ietf-cose-dilithium`** ("ML-DSA for JOSE and COSE"); the composite-sigs draft describes the _concatenated composite_ QAuth deliberately does **not** implement, and the individual `-prabel-…-02` pin is stale versus the WG-adopted `draft-ietf-jose-pq-composite-sigs`. The **emitted wire shape happens to match cose-dilithium, so there is no live interop break** — but the safeguard meant to catch draft churn points a future reviewer at the wrong document. Tracked as checklist item 1.

## 7. Backend-swap and key-lifecycle summary

The noble↔native swap is interoperable at the _seed/wire_ level (same 32-byte seed → identical keys; signatures cross-verify — proven by the #244 interop tests), and verification is public-material-only with a single error vocabulary, so there is **no algorithm-confusion or silent wrong-key-accept** across backends. The one latent footgun (F2) is that a `MlDsaKey` **object** produced by one backend is not guaranteed portable to the other's `sign()` because `material()` differs (seed vs expanded secret); this is invisible today (one backend is selected per process) but must be unified or backend-tagged before both are wired live.

## 8. Pre-default-on checklist

`HYBRID_SIGNING_ENABLED` MUST remain default-**OFF** until every item is satisfied. None block the _merged surface_; each blocks the _first default-on deployment_.

1. **Correct the JOSE pin [F3].** Pin the AKP shape + `ML-DSA-65` alg to `draft-ietf-cose-dilithium` (record the exact revision) and reference RFC 9864 (Fully-Specified Algorithms) for alg-identifier policy; rename/drop the misleading composite-sigs constant (use `draft-ietf-jose-pq-composite-sigs` only if a composite path is later added). Then diff the emitted `AkpJwk` against the cose-dilithium example JWK and confirm an independent ML-DSA-in-JOSE verifier resolves `/.well-known/jwks.json`.
2. **Wire hybrid issuance + a PQC-aware verify path** into the live auth-server routes (#247 delivery, #249 introspection/mcp-guard). No default-on is meaningful while issuance/verification are unwired.
3. **Make downgrade resistance issuer-signed [F1].** Surface the Ed25519-verified protected header from `verify()`; in `verifyHybrid` treat a present signed `pqc_alg` as binding regardless of `requirePqc`, cross-checking `hybrid.pqcAlg` against it; add a test that strips `pqcSignature` on a token whose signed header carries `pqc_alg` and asserts rejection even with `requirePqc=false`.
4. **Bind ML-DSA key resolution to the signed `pqc_kid` [F5]**, never `HybridSignedToken.pqcKid`; prefer resolving inside `verifyHybrid` from the verified header, and consider dropping the unsigned `pqcKid` transport field.
5. **Route the PQC backend through `getSignatureBackend('ML-DSA-65', enabledSignatureAlgorithms)` [F7/F11]** at the hybrid call sites and the plugin boot derivation, threading the operator-enabled set from `cryptoEnv`; remove the hardcoded `['ML-DSA-65']`.
6. **Unify `MlDsaKey.material()` across backends [F2]** (both sign from `seed()`, or both store the expanded secret), or tag the backend on `MlDsaKey` and enforce it in `sign()`; add a negative test that a cross-backend key object throws.
7. **Lock the `sign()` header-merge invariant [F6]:** merge as `{ ...header, alg }` so the canonical `alg` always wins, and throw if `options.header` contains a reserved member (`alg`, `crit`, `b64`).
8. **Stand up a trustworthy native-build channel [F4]** before enabling the native backend anywhere: reproducible CI build of the `.node` from pinned source, published checksum + provenance attestation, load-time integrity verification, and `cargo audit` + `cargo deny`/`vet` in CI for `crypto-native`. — **Addressed by #277** (`.github/workflows/crypto-native.yml`, `rust-toolchain.toml`, `deny.toml`, `src/addon-integrity.ts`): pinned toolchain + lock-enforced build, linux determinism probe, `sha256` sidecar + SLSA `attest-build-provenance`, pre-`dlopen` checksum verification defaulting to `enforce`, and `cargo audit`/`cargo deny` over the crate and its cmake/cc build surface. **Residual:** cross-platform determinism (macOS/Windows) and the attestation step itself are only exercised by a real CI run; the full napi triple set is still not cross-compiled.
9. **Validate the seed at the config layer [F8]:** confirm `JWT_MLDSA_PRIVATE_KEY(_PATH)` base64url-decodes to exactly 32 bytes in `cryptoEnvSchema`.
10. **Implement rotation before publishing >1 key [F9/F10]:** JWKS resolution keyed on `(kid, alg/kty)` not `kid` alone, distinct kids across OKP/AKP, retired keys published under their own kid; zeroize the transient boot seed after public-key derivation.
11. **Publish an operator runbook:** set `requirePqc=true` wherever PQC verification is expected, and document that `requirePqc=false` is an explicit accept-classical (Ed25519-floor) posture, not a silent downgrade.

## 9. Verdict

**CONDITIONAL PASS.** Zero confirmed HIGH/CRITICAL defects survived adversarial re-verification across all three dimensions: no key/secret-exposure path and no trivially forgeable or bypassable signature exists in key generation, storage, JWKS export, the detached-parallel construction, the backend seam, or the supply-chain surface. The capability is cryptographically sound. It is **conditional, not a full pass**, because named preconditions (§8) remain before `HYBRID_SIGNING_ENABLED` may default ON anywhere — chiefly: hybrid issuance/verification are unwired; the JOSE draft pin must be corrected and reconfirmed; downgrade resistance must become issuer-signed at the point live verification lands; and the native-binding provenance channel must be established. Per AC#2, with zero open HIGH/CRITICAL findings, the merged surface is cleared to remain in the tree with the flag default-off; the checklist gates the first default-on deployment.

---

_Generated by the #248 security-gate review (3 `auth-specialist` dimensions + adversarial verification). Findings F1–F13 are hardening/pre-default-on items, not merge blockers._
