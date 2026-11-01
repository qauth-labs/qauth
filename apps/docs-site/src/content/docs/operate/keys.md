---
title: Keys
description: How QAuth keeps its signing keys in the realm's key store, and how to import your own — EdDSA, RS256 and the ML-DSA seed (hybrid signing only) — with the PKCS#8 pitfall that wastes an afternoon.
sidebar:
  order: 2
lastVerified: '2026-10-26'
---

QAuth signs with up to three signing key types, each realm with its own keys
in its encrypted key store. This page covers how the store gets them and how
to generate and import your own. What QAuth actually imports is verified
against `libs/server/keys/src/lib/environment-keys.ts` — the format
requirements below come from that importer, not from convention.

| Key             | Variable needed?                                              | Signs                                                           |
| --------------- | ------------------------------------------------------------- | --------------------------------------------------------------- |
| EdDSA (Ed25519) | No — generated for a fresh realm                              | Access tokens always; ID tokens when the realm has no RS256 key |
| RS256           | No — generated for a fresh realm; import one to keep yours    | ID tokens, when the realm has one (access tokens stay EdDSA)    |
| ML-DSA-65 seed  | No — generated with the Ed25519 key when hybrid signing is on | The post-quantum half of a hybrid access token                  |

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
KMS is unavailable. `KEK_PROVIDER=vault` with `@qauth-labs/keys-vault` keeps it
in a Vault Transit key instead, logging in with a token file or AppRole; its
[guide](https://github.com/qauth-labs/qauth/blob/main/libs/keys/vault/README.md)
gives the settings, the Vault policy of the signer role and the token renewal.
Choose the provider before the first boot that stores keys:
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
   key or a cookie secret the store lacks replaces the store's active key of
   its kind (see "Replacing a signing key" and "Replacing the cookie key"
   below).
2. It creates the keys the realm still lacks: the event-signing and
   data-at-rest keys, and the cookie key when `SESSION_COOKIE_SECRET` is unset.
   A realm that neither holds nor imports a signing key gets an Ed25519 and an
   RS256 signing key (and, with hybrid signing on, the ML-DSA-65 key of the
   pair), so a fresh deployment needs no key variable at all.
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
  and replaced, together;
- with hybrid signing on, the realm's active Ed25519 signing key has no
  ML-DSA-65 key beside it: tokens would be signed classical-only. Set
  `JWT_PRIVATE_KEY` and `JWT_MLDSA_PRIVATE_KEY` to a new pair, or turn hybrid
  signing off.

### Tokens are signed through the key store

Every access token, ID token and hybrid token is signed with the keys of the
realm it is issued in, by the signer
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
Decision 9). The token's `iss` is the realm's issuer, and its protected header
names the key that signed it in `kid` (a hybrid token also names its ML-DSA-65
key in `pqc_kid`). Each realm publishes its own keys at its own
`/.well-known/jwks.json`, and the server verifies a token only with the keys of
the realm the request is for, so a token one realm issued is refused by
another. A token issued before the upgrade carries no `kid`; it still verifies,
but only against the Ed25519 key that `JWT_PRIVATE_KEY` holds (or
`JWT_PUBLIC_KEY`, on a process without the signer role), the key that signed it,
never against a key the store generated. Keep that variable set until the
tokens issued before the upgrade have expired (the longest access token
lifetime of any realm, a development client's included): the
next release removes this path, and refuses every token without a `kid`.

The server verifies a token with the realm's verification set, picking the key
by the token's `kid` and `alg` together: the realm's active keys, and its
retired keys until their retention ends, when they also leave the JWKS. A
`next` key, published before it signs, verifies nothing, and neither does a
`compromised` key. A hybrid token's ML-DSA-65 key is found the same way, by its
`pqc_kid`. So a rotation through the key store keeps the tokens the old key
signed valid at every endpoint that checks a token, and nobody signs in again:
the old key retires and stays published for its retention (ADR-019: 14 days
after the rotation by default, never less than the longest token lifetime). A
token without a `kid` keeps verifying against the imported key after that key
retires. Rotation through the store ships with #542 and #544; replacing a key
through its variable (below) is not a rotation, and its old key leaves the JWKS
at once. A `next` key verifies nothing and every process reads a realm's key
list again only every 60 seconds, so #542 has to order the activation so that
every process that verifies tokens sees the new key before any signer uses it.
Relying parties cache the JWKS as the
[OAuth 2.1 flow](/integrate/oauth-flow/#caching-the-jwks) page describes.

A key variable never holds a key another realm stores: the key boot step refuses
to import one, naming the variable, so a token signed by one realm's key never
verifies as another realm's.

If `JWT_ISSUER` ends with a slash, the tokens now name the issuer without it,
as discovery does, while the previous release names it with the slash. Upgrade
such a deployment all at once rather than node by node: in a mixed fleet each
release refuses the other's access tokens until they expire. A relying party
that compares `iss` with the slashed form must drop the slash.

The key variables are read only by the key step above: once the store holds a
key, the variable no longer signs anything, and a new key in it is how you
replace the stored one (below). The server boots without them. Remove them
once you no longer need to roll back to a release that signs with them; each
boot warns about every one still set. That includes `SESSION_COOKIE_SECRET`:
since #493 the browser cookies are signed with the realm's cookie key from the
store, and the variable is optional. Production refuses every value QAuth's
examples published (below).

### The browser cookies

The session cookie, the login-CSRF cookie and the wallet-flow cookie are signed
with the realm's `cookie_hmac` key, which the signer hands the browser-facing
role (ADR-019 Decision 9). Each value is `<kid>.<payload>.<mac>`: it names the
key that signed it, and its HMAC-SHA256 covers the cookie's name, the realm id,
the `kid` and the payload, so a value never passes for another cookie or for a
cookie of another realm, even if two realms held the same key. A new cookie is
signed with the realm's current key; a cookie of the previous key, the one the
last rotation retired, still verifies while it is the previous key: until the
next replacement, as no retention limit applies before rotation through the
store ships (#542). A cookie that does not verify is cleared; one that names a
key the process has not read yet is left for the next request.

Each process reads a realm's cookie keys from the signer at most once a minute,
and once more, at most every five seconds, when a cookie names a key it has not
read yet. The session cookie's `Max-Age` is the time left until the session's
absolute end. A cookie an earlier release signed with `SESSION_COOKIE_SECRET`
does not verify: its user signs in again (see the upgrade guide).

A process without the signer role gets the cookie keys from the signer service,
which this release cannot call yet (#497): until it can, its browser routes that
read or set a signed cookie answer 503, and `/auth/logout` there ends the
sessions and tokens but leaves the cookie for the next page to clear.

### Replacing the cookie key

Until rotation through the key store ships, you replace the cookie key through
`SESSION_COOKIE_SECRET`, as for a signing key: set a new secret, at least 32
characters, and restart. At boot, each stored cookie key is opened with the KEK
and compared with the variable in constant time. A secret the store lacks
becomes the active cookie key, and the one it replaces is retired: unlike a
replaced signing key, it stays the realm's previous cookie key and keeps
verifying the cookies it signed until the next replacement, so nobody is signed
out. The node that replaces it logs a warning with the new and the retired
`kid`. A variable that holds a cookie key the store retired changes nothing, and
each boot warns about it, so a node that still has the old value during a
rolling restart boots.

To cut off a leaked cookie secret, replace it twice, restarting after each new
secret: the second replacement drops the leaked key from the previous slot.
A restarted node refuses the cookies it signed at once. A node that keeps
running can accept them for up to about two minutes after the replacement, as
it keeps a realm's cookie keys for up to a minute and the signer it reads them
from keeps its own list for up to a minute too; restart every node to cut that
window. Emergency retirement (#551) will do this in one step.

If `SESSION_COOKIE_SECRET` holds a value from QAuth's own examples
(`.env.example`, or the `.env.docker.example` of earlier releases), anyone can
sign cookies with it: production refuses to start with it. Set a new secret
first, so the boot step replaces the stored key, and only then remove the
variable; removing it alone leaves the stored key as it is.

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
  and each boot warns about it: the store keeps its active key, which signs. So
  a node that still has the old value during a rolling restart boots, and
  warns.

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

Every private key QAuth imports from a variable — EdDSA and RS256 — must be
**PKCS#8** PEM: first line `-----BEGIN PRIVATE KEY-----`.

**PKCS#1** (`-----BEGIN RSA PRIVATE KEY-----`) is refused at boot — this is the
single most common thing that wastes an afternoon setting QAuth up, if you hit
it. Whether you _do_ hit it depends on your
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
(`-----BEGIN PUBLIC KEY-----`). `openssl pkey -pubout` (used below) always
emits this format.

## EdDSA (Ed25519)

Signs access tokens unconditionally, and ID tokens whenever the realm has no
RS256 key. A fresh realm gets one generated; set a variable only to bring the
key a deployment already signs with, or to replace the stored key.

```bash
openssl genpkey -algorithm Ed25519 -out jwt-ed25519-private.pem
openssl pkey -in jwt-ed25519-private.pem -pubout -out jwt-ed25519-public.pem
```

Set `JWT_PRIVATE_KEY` (or `JWT_PRIVATE_KEY_PATH`) to the private key. The key
step derives the public half itself, with `node:crypto`; `JWT_PUBLIC_KEY` (or
`JWT_PUBLIC_KEY_PATH`) is optional, and the boot stops when it is set and is
not the private key's public half.

Before tokens were signed through the key store, the JWT plugin also imported
the key and could not derive its public half, so a boot without
`JWT_PUBLIC_KEY` failed ([issue #359](https://github.com/qauth-labs/qauth/issues/359)).
The plugin no longer holds a key, so that failure no longer happens.

## RS256 — optional, for OIDF certification

OpenID Foundation Basic/Config OP certification hard-fails an EdDSA-only OP on
its `id_token` signature test, so a realm with an RS256 key signs its ID tokens
with RS256; access tokens are unaffected (always EdDSA). A fresh realm gets one
generated. A deployment that upgraded without `JWT_RS256_PRIVATE_KEY` has none
and keeps signing ID tokens with EdDSA, until you import one with the variable
or create one with `auth-server:keys:create`.

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
is optional, as for EdDSA: the key step derives the public half itself. An
optional `JWT_RS256_KID` gives the published RSA JWK a stable `kid`; without
it the key's `kid` is its RFC 7638 thumbprint.

For the full certification flow — deploying, driving the conformance suite,
and the residual-uncertainty checklist — see the
[OIDF OP Certification Runbook](https://github.com/qauth-labs/qauth/blob/main/docs/oidf-op-certification-runbook.md).

## ML-DSA-65 seed — only with hybrid signing

Only used when `HYBRID_SIGNING_ENABLED=true` (default `false` — post-quantum
hybrid signing is opt-in). A fresh realm with hybrid signing on gets the pair
generated; set the variable to import a seed you already have, together with
`JWT_PRIVATE_KEY`. Unlike EdDSA/RS256, this is not a PEM key: QAuth's
canonical private form is the raw **32-byte seed**, base64url-encoded,
unpadded (`libs/server/config/src/lib/schemas/crypto.ts` validates exactly
this shape at startup — wrong length or alphabet fails fast with a clear
message, without printing the seed).

Generate 32 CSPRNG bytes and encode them as unpadded base64url:

```bash
openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n'
```

Set the result as `JWT_MLDSA_PRIVATE_KEY` (or point
`JWT_MLDSA_PRIVATE_KEY_PATH` at a file containing it). Hybrid signing also
needs `SIGNING_ALGORITHM_MODE=ed25519+ml-dsa-65`, or the boot fails fast, and a
realm whose active Ed25519 key has no ML-DSA-65 key beside it refuses to boot.
An optional `JWT_MLDSA_KID` names the key in the published JWKS.

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
| `JWT_PRIVATE_KEY` / `_PATH`       | EdDSA  | No — imported into the key store when set                      |
| `JWT_PUBLIC_KEY` / `_PATH`        | EdDSA  | No — derived from the private key; checked when set            |
| `JWT_RS256_PRIVATE_KEY` / `_PATH` | RS256  | No                                                             |
| `JWT_RS256_PUBLIC_KEY` / `_PATH`  | RS256  | No — derived from the private key; checked when set            |
| `JWT_RS256_KID`                   | RS256  | No                                                             |
| `JWT_MLDSA_PRIVATE_KEY` / `_PATH` | ML-DSA | No — imported with `JWT_PRIVATE_KEY` as a hybrid pair when set |
| `JWT_MLDSA_KID`                   | ML-DSA | No                                                             |
| `HYBRID_SIGNING_ENABLED`          | —      | No — default `false`                                           |
| `SIGNING_ALGORITHM_MODE`          | —      | No — default `ed25519`; must be `ed25519+ml-dsa-65` for hybrid |

## See also

- [Docker](/operate/docker/) — where these keys get mounted into the stack.
- [Upgrades](/operate/upgrades/) — key material is unaffected by the ADR-002 migration, but back up before any destructive migration regardless.
- [PQC Verifier Guide](/operate/pqc-verifier-guide/) — the ML-DSA key from a verifier's perspective.
- [Service roles](/operate/service-roles/) — which processes may hold these keys once the roles run apart.
