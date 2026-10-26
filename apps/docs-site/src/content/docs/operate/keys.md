---
title: Keys
description: Generating and configuring QAuth's signing keys — EdDSA (required), RS256 (optional), and the ML-DSA seed (hybrid signing only) — and the PKCS#8 pitfall that wastes an afternoon.
sidebar:
  order: 2
lastVerified: '2026-10-24'
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

## The key store

Keys are moving out of environment variables into an encrypted key store in
Postgres, one set per realm and purpose
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
Decision 9). Every stored key is wrapped with a key-encryption key (KEK), so
**set `KEK` or `KEK_PATH` before you upgrade** and keep a copy with your
backups: without it the stored keys cannot be read. Generate one with
`openssl rand -base64 32`. `NODE_ENV=production` refuses to start without it.

`KEK_PROVIDER` picks where the KEK lives. The default, `local`, reads `KEK` or
`KEK_PATH`. An optional adapter package can keep it in a key management
service instead, for example `KEK_PROVIDER=aws-kms` with
`@qauth-labs/keys-aws-kms`, which sends data keys to AWS KMS to be wrapped and
unwrapped while signing stays in QAuth. Its
[guide](https://github.com/qauth-labs/qauth/blob/main/libs/keys/aws-kms/README.md)
gives the settings, the IAM policy of the signer role and what happens when
KMS is unavailable. Choose the provider before the first boot that stores keys:
a key wrapped under one KEK does not open under another until the KEK rotation
(#545) can re-wrap it.

At every boot the server runs a key step for the default realm, on every node,
after the realm's own step and under an advisory lock, so nodes that start
together do it once:

1. It imports each key variable the realm's store does not hold yet:
   `JWT_PRIVATE_KEY` as the Ed25519 signing key, `JWT_RS256_PRIVATE_KEY` as the
   RS256 one, `JWT_MLDSA_PRIVATE_KEY` (with `HYBRID_SIGNING_ENABLED` on) as the
   ML-DSA-65 key of the hybrid pair, and `SESSION_COOKIE_SECRET`, when you set
   it, as the cookie key. A `_PATH` variable counts as its variable. A signing
   key the store lacks replaces the store's active key of its algorithm (see
   "Replacing a signing key" below).
2. It creates the keys the realm still lacks: the event-signing and
   data-at-rest keys, and the cookie key when `SESSION_COOKIE_SECRET` is unset.
   A realm that neither holds nor imports a signing key gets an Ed25519 and an
   RS256 signing key. That needs a deployment without `JWT_PRIVATE_KEY`, which
   the server still requires until token signing moves onto the key store
   (#491), so today every deployment imports its signing key.
3. It logs a warning for each key variable that is still set, naming it.

Each imported key keeps `JWT_RS256_KID` or `JWT_MLDSA_KID` as its `kid` when
set, and otherwise gets the RFC 7638 thumbprint of its public key. The Ed25519
key has a `kid` for the first time, and `/.well-known/jwks.json` publishes it.
The keys themselves do not change, so tokens signed before the upgrade still
verify.

The boot stops, and names the variable, when:

- a key must be imported and no KEK is set: the published development KEK
  would protect nothing;
- `JWT_PUBLIC_KEY` or `JWT_RS256_PUBLIC_KEY` is not the public half of its
  private key;
- a new key comes with a `JWT_RS256_KID` or `JWT_MLDSA_KID` that already
  names a stored key: a new key needs a new `kid`;
- with hybrid signing on, only one of `JWT_PRIVATE_KEY` and
  `JWT_MLDSA_PRIVATE_KEY` holds a new key: the two keys of a pair are stored,
  and replaced, together.

**For now, keep the key variables set.** Tokens are still signed with them
until token signing moves onto the key store (#491), and the session cookie
until #493, and the warning says so. The upgrade guide (#501) says when to
remove them.

### Replacing a signing key

Until rotation through the key store ships (manual rotation #544, emergency
retirement #551), you replace a signing key as before the key store: put the
new key in its variable and restart. At boot, a key variable that holds a key
the store lacks replaces the store's active key of that algorithm. The old key
is retired and leaves the JWKS at once, so tokens it signed stop verifying, as
they did before. Each node logs a warning with the new and the retired `kid`.

- Give a new RS256 or ML-DSA-65 key a new `JWT_RS256_KID` or `JWT_MLDSA_KID`,
  or unset the variable to use the key's thumbprint.
- With hybrid signing on, change `JWT_PRIVATE_KEY` and `JWT_MLDSA_PRIVATE_KEY`
  together. Turning hybrid signing on after the upgrade is such a replacement:
  set a new `JWT_PRIVATE_KEY` along with the ML-DSA-65 key.
- A variable that holds a key the store retired changes nothing in the store,
  and each boot warns about it: the store keeps its active key, which signs once
  token signing moves onto the store. So a node that still has the old value
  during a rolling restart boots, and warns.

### Adding a key: `auth-server:keys:create`

On a host that holds the KEK, with the server's environment, one command
creates a key for a realm, purpose and algorithm, for example an RS256 signing
key for an OpenID Foundation run:

```bash
pnpm nx run auth-server:keys:create --purpose=token_signing --algorithm=RS256
# In the auth-server image, from /app:
tsx src/keys-create.ts --purpose token_signing --algorithm RS256
```

It prints the new key's `kid` and public JWK as one JSON line. `--realm` picks
a realm other than `DEFAULT_REALM_NAME`. A realm has one active key per purpose
and algorithm, so a replacement is created with `--status next`. A `next`
signing key starts signing once rotation through the store ships (#542); until
then, replace a signing key through its variable, as above.

## The PKCS#8 vs PKCS#1 pitfall (read this first)

Every private key QAuth imports — EdDSA and RS256 — goes through jose's
`importPKCS8` (`libs/core/crypto/src/lib/key-management.ts:47-49`), which
requires **PKCS#8** PEM: first line `-----BEGIN PRIVATE KEY-----`.

**PKCS#1** (`-----BEGIN RSA PRIVATE KEY-----`) is what `importPKCS8` rejects
outright — this is the single most common thing that wastes an afternoon
setting QAuth up, if you hit it. Whether you _do_ hit it depends on your
OpenSSL version:

- **OpenSSL 3.0+** (check with `openssl version`): `openssl genrsa` now
  defaults to PKCS#8 output too — you'd have to pass `-traditional` to get
  PKCS#1. On a current OpenSSL, `openssl genrsa 2048 | head -1` already prints
  `-----BEGIN PRIVATE KEY-----`, and this pitfall won't reproduce.
- **OpenSSL 1.1.x and earlier**, or 3.x with `-traditional`: `openssl genrsa`
  (and some older Ed25519 recipes) emit PKCS#1.

Either way, generate directly with `openssl genpkey` (used throughout this
page) — it always emits PKCS#8, regardless of OpenSSL version, so there's no
need to track which behavior your installed version has. If you already have
a PKCS#1 key from somewhere else, convert it:

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

`.env.example` and the [OIDF certification runbook](https://github.com/qauth-labs/qauth/blob/main/docs/oidf-op-certification-runbook.md)
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

The server never starts. (The key step above derives the public key with
`node:crypto` and has no such problem, but the JWT plugin still does until
token signing moves onto the key store.) This is tracked as
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

**Must be ≥2048-bit, and the boot checks it.** The key boot step (#485) refuses
a `JWT_RS256_PRIVATE_KEY` shorter than 2048 bits (RFC 7518 §3.3): the server
stops at startup with an `InvalidConfigurationError` that names the variable and
gives the key's length in its details, and it stores nothing.

Generate a 2048-bit key:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-rs256-private.pem
openssl pkey -in jwt-rs256-private.pem -pubout -out jwt-rs256-public.pem

# The size, if you want to see it:
openssl rsa -in jwt-rs256-private.pem -noout -text | head -1
# → "Private-Key: (2048 bit, 2 primes)" (or larger)
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
[OIDF OP Certification Runbook](https://github.com/qauth-labs/qauth/blob/main/docs/oidf-op-certification-runbook.md).

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
[Security Gate Review](/reference/records/security/005-pqc-hybrid-signing-review/) for
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
- [Service roles](/operate/service-roles/) — which processes may hold these keys once the roles run apart.
