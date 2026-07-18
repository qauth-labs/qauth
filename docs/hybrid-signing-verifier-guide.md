# Hybrid PQC Signing — Verifier Migration Guide

This guide explains how token **verifiers** behave during QAuth's post-quantum
hybrid-signing rollout (ADR-005): what changes, what doesn't, and what — if
anything — you need to do.

> **TL;DR for existing integrators: nothing is required.** A classical,
> Ed25519-only verifier keeps working **unchanged**. Hybrid signing is designed
> so the bearer token stays an ordinary `EdDSA` JWS that stock JOSE libraries
> validate byte-for-byte. Read on only if you want to _additionally_ validate
> the post-quantum signature.

## Current status (read this first)

Hybrid signing is a **capability that is OFF by default**
(`HYBRID_SIGNING_ENABLED=false`) and is **not yet wired into the live token
routes**. As shipped today, QAuth issues classical Ed25519 access/ID tokens and
serves an EdDSA-only JWKS. This guide describes the behavior you will observe
**once an operator enables hybrid signing**, so you can prepare. Enabling it by
default anywhere is gated on the [security review](./security/005-pqc-hybrid-signing-review.md)
pre-default-on checklist ([ADR-005](./adr/005-pqc-hybrid-signing.md), #248).

## The design in one paragraph

QAuth uses a **detached parallel** hybrid signature, deliberately _not_ the
strict concatenated composite of the JOSE/LAMPS drafts. A hybrid token **is** an
ordinary Ed25519 compact JWS: the JWS `alg` stays `EdDSA`, and a stock verifier
validates it with no changes. The ML-DSA-65 (FIPS 204, NIST Level 3)
post-quantum signature covers the **identical** JWS signing-input and is carried
**alongside** the token — never inside the compact string — and delivered
out-of-band via introspection. Two non-critical protected-header members
(`pqc_alg`, `pqc_kid`) advertise the PQC signature to verifiers that care; a
classical verifier ignores them. This is why existing verifiers need no changes.

## 1. JWKS: mixed key types (`OKP` + `AKP`)

When hybrid signing is configured, `GET /.well-known/jwks.json` publishes the
ML-DSA public key **alongside** the Ed25519 key:

```jsonc
{
  "keys": [
    {
      // Ed25519 signing key — RFC 8037. Verifies the bearer token.
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "…",
      "use": "sig",
      "alg": "EdDSA",
      "kid": "ed-2026",
    },
    {
      // ML-DSA-65 public key — the post-quantum half. Public material only.
      "kty": "AKP",
      "pub": "…", // base64url raw ML-DSA-65 public key (1952 bytes)
      "use": "sig",
      "alg": "ML-DSA-65",
      "kid": "mldsa-2026",
    },
  ],
}
```

**Classical-only verifiers: no action required.** RFC 7517 requires a verifier
to **ignore** JWK entries whose `kty` it does not understand. Every mainstream
JOSE library already does this — it selects the `OKP`/`EdDSA` key by `alg`/`kid`
and skips the `AKP` entry. The `AKP` entry never affects Ed25519 verification.

The `AKP` entry carries **only** the public key (`pub`); it never contains
private material (no `priv`, no `d`).

## 2. Token delivery: reference-token / introspection is the default

The post-quantum signature is large. Measured on a representative token
(`libs/server/jwt/src/lib/token-size.bench.test.ts`, #247):

| Artifact                                 | Bytes    | Fits a 4 KB cookie? | Fits a 2 KB URL? |
| ---------------------------------------- | -------- | ------------------- | ---------------- |
| Access **bearer** JWS (`.token`)         | **716**  | ✅                  | ✅               |
| ID-token bearer JWS                      | **576**  | ✅                  | ✅               |
| Detached **ML-DSA-65** signature         | **4412** | ❌                  | ❌               |
| Compound (bearer + signature), if inline | **5128** | ❌                  | ❌               |

Because the signature is detached, the **bearer token stays ~716 bytes** in
every channel — it never balloons. The 4412-byte ML-DSA signature is delivered
out-of-band. Accordingly:

- **`PQC_TOKEN_DELIVERY=reference` (the default when hybrid is on):** the bearer
  token is validated normally; the PQC component is retrieved and checked via
  **RFC 7662 introspection** (a POST body, with no header/cookie size ceiling).
  This is the recommended posture.
- **`PQC_TOKEN_DELIVERY=self-contained`:** only viable where you control the
  transport and it tolerates a ~4.4 KB payload — i.e. **large-buffer request
  headers, never cookies or URLs**. It requires an explicit
  `PQC_SELF_CONTAINED_ACK=true`, so it can never be selected by accident.

## 3. Draft revision implemented, and churn risk

Post-quantum JOSE is still standardizing. QAuth pins the identifiers it emits so
a draft revision cannot silently change the wire shape:

- **ML-DSA public key in JWKS** (`kty: "AKP"`, `pub` member) and the
  **`ML-DSA-65` algorithm spelling** follow the **`draft-ietf-cose-dilithium`**
  ("ML-DSA for JOSE and COSE") key representation.
- The `pqc_alg` / `pqc_kid` protected-header members are **private, unregistered
  JOSE header parameters**, kept **non-critical** so classical verifiers ignore
  them.

> ⚠️ **Known pin correction (tracked, #248).** The in-code constant is currently
> named `PQC_JOSE_COMPOSITE_DRAFT = 'draft-prabel-jose-pq-composite-sigs-02'`.
> That draft actually describes the _concatenated composite_ construction QAuth
> deliberately does **not** implement; the shape QAuth emits matches
> `draft-ietf-cose-dilithium`. **The emitted wire shape is correct** — there is
> no live interop break — but the constant will be re-pinned to the right
> document (and reconfirmed on the IETF datatracker) before hybrid is enabled by
> default. See the [security review](./security/005-pqc-hybrid-signing-review.md)
> checklist, item 1.

**Because these identifiers may still change before default-on, treat the PQC
member names as provisional** and re-check this guide (and the JWKS you fetch)
when an operator turns hybrid on.

## 4. Migration checklist

### If you are a classical, Ed25519-only verifier

**Nothing is required.** Concretely, confirm only that:

- [ ] You fetch keys from `GET /.well-known/jwks.json` and **select by `kid` /
      `alg`** (as every JOSE library does), rather than assuming a single-entry
      JWKS. You will simply skip the `AKP` entry.
- [ ] You pin the accepted algorithm to `EdDSA` (you should already — it blocks
      `alg` confusion). The bearer token's `alg` stays `EdDSA` under hybrid.

That's it. Your integration is unaffected by the rollout.

### If you want to validate the post-quantum signature

Opt-in, for verifiers that want forward-secure assurance:

- [ ] Read the `AKP` / `ML-DSA-65` public key from JWKS, selecting it by the
      token's signed `pqc_kid` header (not any unsigned transport field).
- [ ] Obtain the detached ML-DSA-65 signature via **introspection** (the default
      delivery channel).
- [ ] Recompute the JWS signing-input — `base64url(header) + "." +
  base64url(payload)` — and verify the ML-DSA-65 signature over those exact
      bytes with the `AKP` public key. (This is the same preimage the Ed25519
      signature covers, so tampering breaks both.)
- [ ] Decide your **downgrade policy**. Verifying the Ed25519 signature is the
      classical floor; require the PQC component (`requirePqc`) wherever you
      expect post-quantum assurance, and treat its absence as a rejection rather
      than a silent downgrade.

> The verifier-side PQC validation path (introspection returning the PQC
> component, and treating a signed `pqc_alg` as binding) is wired as part of the
> live-verification work; until then, this section describes the target
> behavior, not a live endpoint.

## References

- [ADR-005: Post-Quantum Hybrid Signing](./adr/005-pqc-hybrid-signing.md) — the
  roadmap and the #243–248 implementation amendments.
- [Security Gate Review](./security/005-pqc-hybrid-signing-review.md) — the
  reviewed behavior and the pre-default-on checklist.
- [OAuth 2.1 Flow → Introspection](./oauth-flow.md) — the introspection endpoint
  used as the PQC delivery channel.
- [`@qauth-labs/mcp-guard`](../libs/fastify/plugins/mcp-guard/README.md) — the
  resource-server SDK that performs token validation.
