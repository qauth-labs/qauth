---
title: PQC Verifier Guide
description: How token verifiers behave when hybrid post-quantum signing (ADR-005) is enabled — what changes, what doesn't, and what to do if you validate the PQC signature.
sidebar:
  order: 6
lastVerified: '2026-07-27'
---

This guide explains how token **verifiers** behave with QAuth's post-quantum
hybrid-signing feature (ADR-005): what changes, what doesn't, and what — if
anything — you need to do.

> **TL;DR for existing integrators: nothing is required.** A classical,
> Ed25519-only verifier keeps working **unchanged**. Hybrid signing is designed
> so the bearer token stays an ordinary `EdDSA` JWS that stock JOSE libraries
> validate byte-for-byte. Read on only if you want to _additionally_ validate
> the post-quantum signature.

## Current status (read this first)

Hybrid (Ed25519 + ML-DSA-65) signing has **shipped** and is wired into the live
token routes: `POST /oauth/token` and `POST /auth/login` issue hybrid-signed
access tokens whenever it's on, and `POST /oauth/introspect` returns the
detached PQC component for a hybrid token (see
[OAuth 2.1 Flow → Introspection](/integrate/oauth-flow/#token-introspection-rfc-7662)).
It is a **capability that is OFF by default** (`HYBRID_SIGNING_ENABLED=false`),
so a fresh deployment issues classical Ed25519 access/ID tokens and serves an
EdDSA-only JWKS until an operator opts in. ID tokens are always classical
Ed25519 (or RS256, when configured) — only access tokens can carry the PQC
signature. This guide describes the behavior you will observe **once an
operator enables hybrid signing**.

What is _not_ shipped yet: a first-party SDK that performs the PQC signature
check for you. [`@qauth-labs/mcp-guard`](/libs/fastify/plugins/mcp-guard/README.md),
QAuth's own resource-server SDK, verifies the classical Ed25519 signature only.
The "If you want to validate the post-quantum signature" checklist below is
something you implement yourself today.

> The linked [Security Gate Review](/reference/records/security/005-pqc-hybrid-signing-review/)
> predates live issuance (#275); its own dated note explains the gap. Its
> findings and the default-off posture are otherwise still current.

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
| Access **bearer** JWS (`.token`)         | **736**  | ✅                  | ✅               |
| ID-token bearer JWS                      | **592**  | ✅                  | ✅               |
| Detached **ML-DSA-65** signature         | **4412** | ❌                  | ❌               |
| Compound (bearer + signature), if inline | **5148** | ❌                  | ❌               |

Because the signature is detached, the **bearer token stays ~736 bytes** in
every channel — it never balloons. The 4412-byte ML-DSA signature is delivered
out-of-band. Accordingly:

- **`PQC_TOKEN_DELIVERY=reference` (the default when hybrid is on):** the bearer
  token is validated normally; the PQC component is retrieved and checked via
  **RFC 7662 introspection** (a POST body, with no header/cookie size ceiling).
  This is the recommended posture, and is how QAuth's own `/oauth/introspect`
  serves it (`apps/auth-server/src/app/helpers/hybrid-token.ts`).
- **`PQC_TOKEN_DELIVERY=self-contained`:** only viable where you control the
  transport and it tolerates a ~4.4 KB payload — i.e. **large-buffer request
  headers, never cookies or URLs**. It requires an explicit
  `PQC_SELF_CONTAINED_ACK=true`, so it can never be selected by accident.

## 3. Draft revision implemented, and churn risk

Post-quantum JOSE is still standardizing. QAuth pins the identifiers it emits so
a draft revision cannot silently change the wire shape:

- **ML-DSA public key in JWKS** (`kty: "AKP"`, `pub` member) and the
  **`ML-DSA-65` algorithm spelling** follow **[RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html)**
  ("ML-DSA for JOSE and COSE", Standards Track, May 2026 — the published
  successor to `draft-ietf-cose-dilithium`, final revision `-11`). `ML-DSA-65`
  is IANA-registered in the JOSE "JSON Web Signature and Encryption Algorithms"
  registry, and is a _fully-specified_ identifier per
  **[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html)** — `alg` alone
  determines the operation, with no companion parameter member.
- The `pqc_alg` / `pqc_kid` protected-header members are **private, unregistered
  JOSE header parameters**, kept **non-critical** so classical verifiers ignore
  them.

> ✅ **Pin corrected (#274, closes review checklist item 1).** The in-code
> constant was previously named `PQC_JOSE_COMPOSITE_DRAFT` and pointed at
> `draft-prabel-jose-pq-composite-sigs-02` — a draft describing the
> _concatenated composite_ construction QAuth deliberately does **not**
> implement. The emitted wire shape was always correct (there was no interop
> break); only the citation was wrong. The constant is now
> `PQC_JOSE_MLDSA_SPEC = 'RFC 9964'`, with `PQC_JOSE_ALG_POLICY_SPEC = 'RFC 9864'`
> for alg-identifier policy. See the
> [security review](/reference/records/security/005-pqc-hybrid-signing-review/).

**The AKP key members are stable**: RFC 9964 is a published Standards Track
RFC, so `kty`/`alg`/`pub` will not change under you. What remains provisional is
the QAuth-private `pqc_alg` / `pqc_kid` header pair, which is unregistered and
may change — re-check this guide periodically.

If QAuth ever adds a true composite path, that is a _separate_ specification —
[`draft-ietf-jose-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/)
("PQ/T Hybrid Composite Signatures for JOSE and COSE", the WG-adopted successor
to the individual `-prabel-` draft) — and would be pinned under its own constant.

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

Opt-in, for verifiers that want forward-secure assurance. There is no
first-party SDK support for this yet (`mcp-guard` verifies Ed25519 only), so
this is a checklist for building it yourself:

- [ ] Read the `AKP` / `ML-DSA-65` public key from JWKS, selecting it by the
      token's signed `pqc_kid` header (not any unsigned transport field).
- [ ] Obtain the detached ML-DSA-65 signature via **introspection** (the default
      delivery channel, and the only one QAuth's own server implements today).
- [ ] Recompute the JWS signing-input — `base64url(header) + "." +
base64url(payload)` — and verify the ML-DSA-65 signature over those exact
      bytes with the `AKP` public key. (This is the same preimage the Ed25519
      signature covers, so tampering breaks both.)
- [ ] Decide your **downgrade policy**. Verifying the Ed25519 signature is the
      classical floor; require the PQC component wherever you expect
      post-quantum assurance, and treat its absence as a rejection rather than a
      silent downgrade — a token whose signed header advertises `pqc_alg` but
      whose detached signature you cannot retrieve should be treated as
      unverifiable, not as a degraded-but-valid token.

## References

- [ADR-005: Post-Quantum Hybrid Signing](/reference/records/adr/005-pqc-hybrid-signing/) — the
  roadmap and the #243–248 implementation amendments.
- [Security Gate Review](/reference/records/security/005-pqc-hybrid-signing-review/) — the
  reviewed behavior and the pre-default-on checklist.
- [OAuth 2.1 Flow → Introspection](/integrate/oauth-flow/#token-introspection-rfc-7662) — the introspection endpoint
  used as the PQC delivery channel.
- [`@qauth-labs/mcp-guard`](/libs/fastify/plugins/mcp-guard/README.md) —
  the resource-server SDK that performs (classical) token validation.
- [Keys](/operate/keys/) — generating the ML-DSA seed this feature needs.
