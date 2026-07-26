---
title: Keys
description: Generating and configuring QAuth's signing keys — EdDSA (required), RS256 (optional), and the ML-DSA seed (hybrid signing only) — and the PKCS#8 pitfall that wastes an afternoon.
sidebar:
  order: 2
lastVerified: '2026-07-27'
---

QAuth can use up to three signing key types. This page covers generating and
configuring each. What QAuth actually imports is verified against
`libs/core/crypto/src/lib/key-management.ts` and
`libs/server/jwt/src/lib/key-management.ts` — the format requirements below
come from those importers, not from convention.

| Key             | Required?                                                      | Signs                                                 |
| --------------- | -------------------------------------------------------------- | ----------------------------------------------------- |
| EdDSA (Ed25519) | **Yes**                                                        | Access tokens always; ID tokens when RS256 is absent  |
| RS256           | No — only for OIDF Basic/Config OP certification               | ID tokens, when configured (access tokens stay EdDSA) |
| ML-DSA-65 seed  | No — only when `HYBRID_SIGNING_ENABLED=true` (default `false`) | The post-quantum half of a hybrid access token        |

## The PKCS#8 vs PKCS#1 pitfall (read this first)

Every private key QAuth imports — EdDSA and RS256 — goes through jose's
`importPKCS8` (`libs/core/crypto/src/lib/key-management.ts:47-49`), which
requires **PKCS#8** PEM: first line `-----BEGIN PRIVATE KEY-----`.

`openssl genrsa` (and some older Ed25519 recipes) emit **PKCS#1**
(`-----BEGIN RSA PRIVATE KEY-----`), which `importPKCS8` rejects outright. This
is the single most common thing that wastes an afternoon setting QAuth up.

- Generate directly in the right format with `openssl genpkey` (used
  throughout this page), **not** `openssl genrsa` / `openssl gen<alg>`.
- Already have a PKCS#1 key? Convert it:
  ```bash
  openssl pkcs8 -topk8 -nocrypt -in old-rsa-key.pem -out jwt-rs256-private.pem
  ```

Public keys, where you supply one, must be **SPKI PEM**
(`-----BEGIN PUBLIC KEY-----`) — `importSPKI`
(`libs/core/crypto/src/lib/key-management.ts:57-59`). `openssl pkey -pubout`
(used below) always emits this format.

## EdDSA (Ed25519) — required

Signs access tokens unconditionally, and ID tokens whenever an RS256 key is
not configured.

```bash
openssl genpkey -algorithm Ed25519 -out jwt-ed25519-private.pem
openssl pkey -in jwt-ed25519-private.pem -pubout -out jwt-ed25519-public.pem
```

Set `JWT_PRIVATE_KEY` (or `JWT_PRIVATE_KEY_PATH`) to the private key, and
`JWT_PUBLIC_KEY` (or `JWT_PUBLIC_KEY_PATH`) to the public key
(`libs/server/config/src/lib/schemas/jwt.ts:65-83`).

### The EdDSA public key is not actually optional (#359)

`.env.example` and the [OIDF certification runbook](/docs/oidf-op-certification-runbook.md)
both describe `JWT_PUBLIC_KEY` as optional — "if not provided, can be derived
from private key." **Today, omitting it fails at boot.** Set both keys.

What actually happens: when `JWT_PUBLIC_KEY` is unset, the JWT plugin tries to
derive the public half by calling jose's `exportSPKI` directly on the imported
**private** key
(`libs/fastify/plugins/jwt/src/lib/fastify-plugin-jwt.ts:88-95`, via
`exportPublicKeyPem` → `joseExportSPKI`,
`libs/server/jwt/src/lib/jose-utils.ts:77-79`). jose 6 imports a PKCS#8 private
key as a **non-extractable** WebCrypto `CryptoKey`, and a non-extractable key's
public half cannot be re-exported that way — `exportSPKI` throws, which the
plugin catches and rethrows as:

```
Failed to derive public key from private key. Please provide JWT_PUBLIC_KEY in environment variables.
```

The server never starts. This is tracked as
[issue #359](https://github.com/qauth-labs/qauth/issues/359); fixing it is out
of scope for this documentation change. **Until it's fixed, always set both
`JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY`** (or their `_PATH` equivalents) — do
not rely on derivation for the EdDSA key.

The codebase already has the correct fix sitting one file over:
`derivePublicKeyPemFromPrivate`
(`libs/server/jwt/src/lib/key-management.ts:104-106`) uses `node:crypto`'s
`createPublicKey` instead of jose, which works on a non-extractable key because
it operates on the PEM directly. It is, in fact, already used for the **RS256**
key below — which is why RS256's derivation genuinely works. The EdDSA path
just doesn't call it yet.

## RS256 — optional, for OIDF certification

Only needed for OpenID Foundation Basic/Config OP certification, which
hard-fails an EdDSA-only OP on its `id_token` signature test. When configured,
ID tokens switch to RS256 by default; access tokens are unaffected (always
EdDSA).

**Must be ≥2048-bit.**

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-rs256-private.pem
openssl pkey -in jwt-rs256-private.pem -pubout -out jwt-rs256-public.pem
```

Set `JWT_RS256_PRIVATE_KEY` (or `_PATH`); `JWT_RS256_PUBLIC_KEY` (or `_PATH`)
is optional here and **derivation genuinely works** for this key — unlike
EdDSA above, the RS256 public key is derived with `node:crypto`'s
`createPublicKey` (`derivePublicKeyPemFromPrivate`,
`libs/server/jwt/src/lib/key-management.ts:104-106`, wired in at
`libs/fastify/plugins/jwt/src/lib/fastify-plugin-jwt.ts:109-114`), which does
not hit the non-extractable-key problem above. An optional `JWT_RS256_KID`
gives the published RSA JWK a stable `kid`
(`libs/server/config/src/lib/schemas/jwt.ts:113-118`).

For the full certification flow — deploying, driving the conformance suite,
and the residual-uncertainty checklist — see the
[OIDF OP Certification Runbook](/docs/oidf-op-certification-runbook.md).

## ML-DSA-65 seed — only with hybrid signing

Only needed when `HYBRID_SIGNING_ENABLED=true` (default `false` — post-quantum
hybrid signing is opt-in). Unlike EdDSA/RS256, this is not a PEM key: QAuth's
canonical private form is the raw **32-byte seed**, base64url-encoded,
unpadded (`libs/server/config/src/lib/schemas/crypto.ts:46-74` validates
exactly this shape at startup — wrong length or alphabet fails fast with a
clear message, without printing the seed).

Generate 32 CSPRNG bytes and encode them as unpadded base64url:

```bash
openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n'
```

Set the result as `JWT_MLDSA_PRIVATE_KEY` (or point
`JWT_MLDSA_PRIVATE_KEY_PATH` at a file containing it). You also need
`SIGNING_ALGORITHM_MODE=ed25519+ml-dsa-65` — `HYBRID_SIGNING_ENABLED=true`
without both fails fast at boot
(`libs/server/config/src/lib/schemas/crypto.ts:131-146`). An optional
`JWT_MLDSA_KID` names the key in the published JWKS.

**Treat the seed like a private key** — anyone with it can forge the
post-quantum component of a hybrid token. Losing it (without a retired-key
entry configured) breaks verification for any PQC-aware verifier checking
tokens signed under it.

See the [PQC Verifier Guide](/operate/pqc-verifier-guide/) for what changes
for token verifiers once this is on, and the
[Security Gate Review](/docs/security/005-pqc-hybrid-signing-review.md) for
the reviewed behavior and the pre-default-on checklist.

## Environment variables

Verified against `libs/server/config/src/lib/schemas/jwt.ts` and
`libs/server/config/src/lib/schemas/crypto.ts` (both are spread into
`apps/auth-server/src/config/env.ts`).

| Variable                          | Key    | Required?                                                      |
| --------------------------------- | ------ | -------------------------------------------------------------- |
| `JWT_PRIVATE_KEY` / `_PATH`       | EdDSA  | Yes (one of)                                                   |
| `JWT_PUBLIC_KEY` / `_PATH`        | EdDSA  | Schema-optional; **set it anyway** (#359 above)                |
| `JWT_RS256_PRIVATE_KEY` / `_PATH` | RS256  | No                                                             |
| `JWT_RS256_PUBLIC_KEY` / `_PATH`  | RS256  | No — derivation works if omitted                               |
| `JWT_RS256_KID`                   | RS256  | No                                                             |
| `JWT_MLDSA_PRIVATE_KEY` / `_PATH` | ML-DSA | Required only if `HYBRID_SIGNING_ENABLED=true`                 |
| `JWT_MLDSA_KID`                   | ML-DSA | No                                                             |
| `HYBRID_SIGNING_ENABLED`          | —      | No — default `false`                                           |
| `SIGNING_ALGORITHM_MODE`          | —      | No — default `ed25519`; must be `ed25519+ml-dsa-65` for hybrid |

## See also

- [Docker](/operate/docker/) — where these keys get mounted into the stack.
- [Upgrades](/operate/upgrades/) — key material is unaffected by the ADR-002 migration, but back up before any destructive migration regardless.
- [PQC Verifier Guide](/operate/pqc-verifier-guide/) — the ML-DSA key from a verifier's perspective.
