# @qauth-labs/server-keys

The keys QAuth stores per realm and purpose: the fixed list of key purposes, key generation,
envelope encryption, the provider of the key-encryption key (KEK) that protects them, and the
signer, the one component that uses them
([ADR-019 Decision 9](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md)).

> **Status:** the library, its default provider, the in-process signer and the key boot step are
> complete. The auth-server registers the signer's wiring,
> [`@qauth-labs/fastify-plugin-signer`](../../fastify/plugins/signer/README.md), for the key boot
> step that imports the environment keys at first boot (#485). Token signing moves onto the signer
> with #491, and the session cookie with #493.

## Entry points

| Import                            | Holds                                                                                                                                               | Who may import it                                                          |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `@qauth-labs/server-keys`         | The `Signer` interface, the caller roles and their policy, the `typ` table, the key purposes, and the typed errors.                                 | Any project.                                                               |
| `@qauth-labs/server-keys/custody` | The KEK provider, envelope encryption, key generation, the key factory, the in-process signer and the storage ports. Everything that touches a KEK. | This library, the signer's wiring and the KEK adapter packages, no others. |

ADR-019 provisions the KEK to the signer role alone, so a rule in `.oxlintrc.json` fails
`nx lint` for an import of `@qauth-labs/server-keys/custody`, or of a deep path into the package,
from any other project. Every other component signs, encrypts and reads keys through `Signer`. The
KEK adapter packages are on that rule's list too, since they implement `KekProvider` and run in the
signer's process: [`@qauth-labs/keys-aws-kms`](../../keys/aws-kms/README.md) (#577) is the first.

## Overview

Each stored key gets its own random 256-bit data key. The data key encrypts the key material with
AES-256-GCM ([NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)), and a
`KekProvider` wraps the data key under the KEK. A KEK rotation therefore re-wraps only the data
keys; the material stays as it is.

- **`sealKeyMaterial` / `openKeyMaterial`**: encrypt and decrypt one key's material. The result has
  the columns `realm_keys` stores: `ciphertext` (with its tag), `iv`, `wrapped_dek`, `kek_ref` and
  `aad_version`.
- **`encodeKeyAad`**: the associated data both GCM operations authenticate. It binds `realmId`,
  `purpose`, `scopeId`, `kid`, `algorithm` and the format version, so a row copied to another
  realm, purpose or key fails to open. The format is fixed, and a test vector pins it.
- **`KekProvider`**: `wrap(dek, aad)`, `unwrap(wrapped, aad, kekRef)` and `health()`. Providers
  wrap data keys only. Signing stays in the signer, because KMS support for EdDSA and ML-DSA varies.
- **`loadKekProvider`**: creates the provider `KEK_PROVIDER` selects.
- **`runKekProviderContract`**: the tests every provider passes.
- **`KEY_PURPOSES`**: the fixed list of key purposes and their rules. See
  [Key purposes](#key-purposes).
- **`generateKeyMaterial`**: a new key of one algorithm, with its `kid`.
- **`createKeyFactory`**: `createKey` and `provisionRealmKeys`, which generate, seal and store keys,
  and `activateNextKey` and `deleteScopedKeys` for the scoped keys. See
  [Creating keys](#creating-keys) and [Scoped keys](#scoped-keys).
- **`bootRealmKeys`**: a realm's key boot step, which imports the key variables and creates the
  standard keys the realm lacks. See [Importing the key variables](#importing-the-key-variables).

The library may import only `scope:core` and `scope:shared` libraries. Its `type:key-custody` tag
carries that rule in `.oxlintrc.json`.

- **`Signer`** and **`createInProcessSigner`**: see [The signer](#the-signer).

## The default provider

`KEK_PROVIDER=local`, the default, keeps the KEK in the signer's memory.

| Variable            | Meaning                                                       |
| ------------------- | ------------------------------------------------------------- |
| `KEK`               | The KEK, as the base64 of 32 random bytes.                    |
| `KEK_PATH`          | A file holding the KEK as base64. It wins over `KEK`.         |
| `KEK_PREVIOUS`      | The KEK in use before a rotation. It only unwraps.            |
| `KEK_PREVIOUS_PATH` | A file holding the previous KEK. It wins over `KEK_PREVIOUS`. |

```console
openssl rand -base64 32 > /run/secrets/qauth-kek
chmod 600 /run/secrets/qauth-kek
```

- A KEK that is not base64 of exactly 32 bytes is refused, with an error that names the variable
  and never the value.
- A KEK file that group or others can read or write gives a warning.
- `kekRef` is the first 8 bytes of the KEK's SHA-256, in hex. It is stored with each key and is
  safe to log. The KEK itself is held as a key object and appears in no property, error or warning.
- Outside production, an unset KEK falls back to `DEV_KEK_DEFAULT`, a published development key,
  with a warning. `NODE_ENV=production` refuses a missing KEK and the development KEK, as `KEK` and
  as `KEK_PREVIOUS`.

During a KEK rotation, set the new KEK as `KEK` and the old one as `KEK_PREVIOUS`. New data keys are
wrapped under the new KEK, and keys wrapped under the old one still open until they are re-wrapped
(#545).

## Usage

```typescript
import { loadKekProvider, openKeyMaterial, sealKeyMaterial } from '@qauth-labs/server-keys/custody';

const provider = await loadKekProvider({
  env: process.env,
  warn: ({ variable, message }) => log.warn({ variable }, message),
});

const identity = { realmId, purpose: 'token_signing', scopeId: null, kid, algorithm: 'EdDSA' };
const sealed = await sealKeyMaterial(provider, pkcs8, identity);
// Store sealed.ciphertext, sealed.iv, sealed.wrappedDek, sealed.kekRef and sealed.aadVersion.

const material = await openKeyMaterial(provider, sealed, identity);
// Import the key, then zero the buffer: material.fill(0).
```

`openKeyMaterial` throws a `KeyDecryptionError` when the identity, the wrapped data key or the
ciphertext does not match, and an `UnknownKekRefError` when no configured KEK has the row's
`kekRef`. It never tries another KEK.

## Writing an adapter

An adapter is an optional package named `@qauth-labs/keys-<name>`, selected with
`KEK_PROVIDER=<name>` and imported only when selected. It exports
`createKekProvider(context): KekProvider`, reads its own settings from `context.env`, and reports
configuration warnings through `context.warn`. It lives under `libs/keys/<name>`, is tagged
`type:kek-adapter` (no project may depend on it) and is added to the key custody guard's
`excludeFiles` in `.oxlintrc.json`. [`@qauth-labs/keys-aws-kms`](../../keys/aws-kms/README.md) is one.

- Bind the associated data. A byte-oriented backend can authenticate `encodeKeyAad(aad)`.
- Return a fresh buffer from every `unwrap`. The caller zeroes it, so never hand out a cached data
  key.
- Map backend failures onto the typed errors: `KeyDecryptionError` for bytes that do not
  authenticate, `UnknownKekRefError` for a reference it holds no key for, `KekUnavailableError` for
  an outage or throttling, and `KekAccessDeniedError` for a refused call. Callers branch on `code`
  (`isKeyCustodyError`), since an adapter may carry its own copy of this library.
- Run the contract against the backend or a test double of it:

```typescript
import { runKekProviderContract } from '@qauth-labs/server-keys/custody';
import { describe, it } from 'vitest';

runKekProviderContract({ name: 'my-adapter', createProvider, describe, it });
```

## Key purposes

`realm_keys.purpose` stores one of these names. The list is part of the wire-level promise once keys
exist, so a purpose that has no consumer yet still has its entry. The first algorithm is the
default.

| Purpose                      | Kind       | Algorithms                    | Scoped | Published | Rotation |
| ---------------------------- | ---------- | ----------------------------- | ------ | --------- | -------- |
| `token_signing`              | signing    | `EdDSA`, `RS256`, `ML-DSA-65` | no     | yes       | 90 days  |
| `event_signing`              | signing    | `EdDSA`, `RS256`              | no     | yes       | 90 days  |
| `federation_entity`          | signing    | `RS256`, `ES256`, `EdDSA`     | no     | yes       | manual   |
| `trust_anchor`               | signing    | `RS256`, `ES256`, `EdDSA`     | no     | yes       | manual   |
| `oid4vp_request_signing`     | signing    | `ES256`                       | no     | yes       | manual   |
| `oid4vp_response_encryption` | encryption | `ECDH-ES`                     | no     | yes       | 90 days  |
| `data_at_rest`               | symmetric  | `A256GCM`                     | no     | no        | 90 days  |
| `cookie_hmac`                | symmetric  | `HS256`                       | no     | no        | 90 days  |
| `webhook_signing`            | symmetric  | `HS256`                       | yes    | no        | manual   |
| `upstream_client_assertion`  | signing    | `RS256`, `ES256`, `EdDSA`     | yes    | yes       | manual   |
| `agent_upstream_identity`    | signing    | `RS256`, `ES256`, `EdDSA`     | yes    | no        | manual   |
| `agent_wrap`                 | symmetric  | `A256GCM`                     | no     | no        | 90 days  |

- **Scoped**: each key belongs to one owner inside the realm, named by `scope_id`: a webhook
  subscription, an upstream provider, or an upstream app identity (ADR-014 §13).
- **Published**: the public half is stored in `realm_public_keys`, where roles that hold no key can
  read it. Its consumer decides where it appears: the JWKS, an entity configuration or client
  metadata.
- **Manual rotation**: someone outside the deployment holds the key or its public half, such as
  the subscriber of a webhook secret, the certificate that names the OID4VP verifier key, or the
  superior whose subordinate statement lists the federation entity keys.
- `ML-DSA-65` is never created alone. It is the second key of a hybrid `token_signing` pair
  (ADR-005).
- Only a federation-operator deployment creates `trust_anchor` keys.

## Creating keys

`createKeyFactory` takes the deployment's switches and returns `createKey`, `provisionRealmKeys`,
`activateNextKey` and `deleteScopedKeys`.

```typescript
import { createKeyFactory } from '@qauth-labs/server-keys/custody';

const keys = createKeyFactory({
  store, // a RealmKeyStore, below
  kekProvider: provider,
  enabledSignatureAlgorithms: cryptoEnv.enabledSignatureAlgorithms, // SIGNING_ALGORITHM_MODE
  hybridSigning: cryptoEnv.HYBRID_SIGNING_ENABLED,
});

await keys.provisionRealmKeys(realmId); // token_signing, event_signing, cookie_hmac, data_at_rest
const [webhook] = await keys.createKey({
  realmId,
  purpose: 'webhook_signing',
  scopeId: subscriptionId,
});
// webhook.secret: 'whsec_…', shown to the subscriber once
await keys.createKey({ realmId, purpose: 'token_signing', algorithm: 'RS256' });
```

`createKey` generates the key, seals it under the KEK, checks that the realm holds no key with the
new `kid`, and writes `realm_keys` and `realm_public_keys` in one transaction. A new key is
`active` unless the caller asks for `next`. It refuses with a `KeyCreationRefusedError` before
anything is generated when:

- the purpose is unknown, or is `trust_anchor` outside a federation-operator deployment;
- the purpose does not allow the algorithm;
- `SIGNING_ALGORITHM_MODE` does not enable the algorithm. The mode governs `EdDSA` and `ML-DSA-65`;
  it does not name the other algorithms;
- a scoped purpose gets no scope id, or an unscoped one gets one.

A `kid` the realm already uses gives a `KeyIdConflictError`. A second `active` key for the same
realm, purpose, scope and algorithm gives an `ActiveKeyConflictError`; a replacement is created as
`next`. A second `next` key for the same realm, purpose, scope and algorithm gives a
`NextKeyConflictError`: a rotation has one key waiting. Nothing is stored in any of these cases.

A `webhook_signing` key's result carries `secret`, the new secret in the Standard Webhooks form
(`whsec_` and the base64 of its 32 bytes). That result is the only place the secret ever appears: no
later call of the factory or the signer returns it. No other purpose's result carries a secret.

With `HYBRID_SIGNING_ENABLED` on, an `EdDSA` `token_signing` key is created with an `ML-DSA-65` key,
and both rows share one `pair_id`.

`provisionRealmKeys` creates a realm's standard keys in one transaction: all of them or none. It
skips a purpose that already holds an active key of its default algorithm (with hybrid signing on,
both keys of the `token_signing` pair), so it can run at every boot. It refuses a realm that holds
only one half of that pair. Two calls for one realm must not run at once: a caller on several nodes
serializes them, as the boot step's advisory lock does (#485). Both functions take an outer
transaction (`tx`) so a realm and its keys can be created together.

`federationOperator` is the seam for the federation-operator deployment. It defaults to `false`;
the federation work names the switch that sets it.

### Scoped keys

A webhook subscription's secrets and an upstream provider's client-assertion keys are scoped keys:
`scope_id` is the subscription id or the provider id. The subscription and provider records belong
to the events and upstream-login work; this library creates, rotates and deletes their keys.

```typescript
const scope = { realmId, purpose: 'webhook_signing', scopeId: subscriptionId } as const;

const [current] = await keys.createKey(scope); // current.secret, shown once
const [next] = await keys.createKey({ ...scope, status: 'next' }); // next.secret, shown once
// ... at least 7 days later:
await keys.activateNextKey(scope); // next signs alone; the old secret is retired

await keys.deleteScopedKeys({ ...scope, tx }); // with the subscription, in its transaction
```

A rotation follows the overlap rules of the automatic rotation (ADR-019, #542):

- It starts with `createKey({ ..., status: 'next' })`. A next client-assertion key is published at
  once, in the provider's JWKS (`getUpstreamJwks`), but does not sign. A next webhook secret is
  shown to the subscriber and signs every message beside the active one, so the receiver can switch
  at any time.
- `activateNextKey` makes the next key `active` and the active key `retired`, in one transaction. It
  refuses with a `KeyChangeRefusedError` (`OVERLAP_NOT_ELAPSED`, with `notBefore`) until the next
  key has been published, or handed out, for `prepublishMs` (default 7 days,
  `DEFAULT_KEY_PREPUBLISH_DAYS`).
- A retired client-assertion key stays in the provider's JWKS for `retiredRetentionMs` (default 14
  days, `DEFAULT_KEY_RETIRED_RETENTION_DAYS`). A retired webhook secret signs nothing more.
- `activateNextKey` takes scoped purposes only; the rotation job of #542 rotates the others. The
  rotation settings of #542 set both windows.

`deleteScopedKeys` deletes every key of one scope, whatever its status, with their public rows. It is
the hook the deletion of a subscription or a provider calls, in the same transaction (`tx`), so the
owner and its keys go together. A signer that holds one of the keys in memory drops it at its next
key-list read, within one refresh interval.

### What is stored

- **`kid`**: the RFC 7638 SHA-256 thumbprint of the public JWK for an asymmetric key, and 128 random
  bits for a symmetric one.
- **Sealed material**: PKCS#8 DER for `EdDSA`, `RS256`, `ES256` and `ECDH-ES`; the 32-byte seed for
  `ML-DSA-65`; 32 random bytes for `HS256` and `A256GCM`. The plaintext is zeroed after sealing.
- **Public JWK**: fully specified, with `kid`, `alg` and `use`, for a published purpose only.

### The store

This library may not import `@qauth-labs/infra-db`, so it writes through a `RealmKeyStore` port
shaped like the realm keys repository (#461): `findByKid`, `listByRealm`, `create`, `updateStatus`
and `deleteByScope`. The signer's wiring builds it from the repository:
`createRepositoryKeyStore(db)` in `@qauth-labs/fastify-plugin-signer`.

## Importing the key variables

Before the key store, a deployment configured its keys in environment variables. ADR-019's answer
on existing issuers imports them once, at the first boot after the upgrade, into the default realm's
store (#485). `bootRealmKeys` is that step; the signer's wiring runs it at every boot, on every node.

```typescript
import { bootRealmKeys } from '@qauth-labs/server-keys/custody';

const result = await bootRealmKeys({
  store, // a RealmKeyBootStore: the factory's store, plus lockRealm and listPublicKeys
  kekProvider,
  enabledSignatureAlgorithms: cryptoEnv.enabledSignatureAlgorithms,
  hybridSigning: cryptoEnv.HYBRID_SIGNING_ENABLED,
  realmId,
  environmentKeys: {
    ed25519: { privateKey: { value: pem, variables: ['JWT_PRIVATE_KEY'] } },
    cookieSecret: { value: secret, variables: ['SESSION_COOKIE_SECRET'] },
  },
});
// result.imported, .replaced, .alreadyStored, .inactive and .generated name keys by kid; no material.
```

| Variable                                           | Becomes                                                                                        |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `JWT_PRIVATE_KEY` (or `_PATH`)                     | The active Ed25519 `token_signing` key.                                                        |
| `JWT_RS256_PRIVATE_KEY` (or `_PATH`)               | The active RS256 `token_signing` key.                                                          |
| `JWT_MLDSA_PRIVATE_KEY` (or `_PATH`)               | With hybrid signing on only: the ML-DSA-65 key, in one hybrid pair with the Ed25519 key.       |
| `SESSION_COOKIE_SECRET`                            | The first `cookie_hmac` key, when the realm has none. Its UTF-8 bytes, so HMACs stay the same. |
| `JWT_PUBLIC_KEY`, `JWT_RS256_PUBLIC_KEY` (`_PATH`) | Nothing: the public key is derived with `node:crypto`, and one that differs stops the boot.    |

- The `kid` is `JWT_RS256_KID` or `JWT_MLDSA_KID` when set, else the RFC 7638 thumbprint, as for a
  generated key. The cookie key gets a random `kid`.
- A signing key counts as stored when the realm has a published key with the same public key,
  whatever its `kid`. So the import happens once, and removing `JWT_RS256_KID` later changes nothing.
- A signing key the store lacks, while the realm has an active key of its algorithm, replaces that
  key: the stored key, and its hybrid partner, are retired and unpublished at once (`replaced`).
  Until rotation through the store ships (manual rotation #544, emergency retirement #551),
  changing the variable is how a deployment replaces a signing key. Tokens are still signed with the
  variables until #491, so the store follows what signs.
- A variable that holds a key the store keeps, but not as its active key (one a replacement
  retired), changes nothing; it is reported in `inactive`.
- It all runs in one transaction under `lockRealm`, a transaction-level advisory lock: nodes that
  boot together import once.
- After the import, `provisionRealmKeys` fills the standard keys still missing. A fresh realm, one
  with no `token_signing` key that imported none, also gets an RS256 `token_signing` key: OpenID
  Connect requires an OP to support RS256 ID tokens.

It stores nothing and throws an `InvalidConfigurationError`, naming the variables and never a value,
when:

- a key must be imported and the KEK is the published development KEK (no `KEK` or `KEK_PATH`);
- a configured public key is not the private key's public half, or an RSA key is shorter than 2048
  bits;
- a variable holds a key the realm marked `compromised`;
- one key of the hybrid pair is new to the store and the other is not: both keys of a pair are
  stored, and replaced, together;
- a new key comes with a configured `kid` (`JWT_RS256_KID`, `JWT_MLDSA_KID`) that is already
  another stored key's: a new key needs a new `kid`.

The `OID4VP_*` keys are not imported here; #546 moves the verifier key into the store.

## The signer

`Signer` is the one interface for private-key work. Every call names the caller's role first:

```typescript
const token = await signer.signJws('api', {
  realmId,
  purpose: 'token_signing',
  typ: 'at+jwt',
  claims: { sub, aud, client_id, scope, iat, exp, jti },
});
```

| Operation                                                                    | Returns                                                                                                                               |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `signJws({ realmId, purpose, typ, algorithm?, claims })`                     | A compact JWS signed by the realm's active key of the purpose. `algorithm` defaults to the purpose's default (`EdDSA`).               |
| `signHybrid({ realmId, typ, claims })`                                       | The detached-parallel hybrid carrier of ADR-005: `{ token, pqcSignature, pqcAlg }`. Needs `HYBRID_SIGNING_ENABLED`.                   |
| `signWebhook({ realmId, subscriptionId, id, timestamp, body })`              | The `webhook-signature` header value. See [Webhook signatures](#webhook-signatures).                                                  |
| `signClientAssertion({ realmId, providerId, audience, algorithm?, claims })` | A `private_key_jwt` client assertion toward an upstream provider. See [Client assertions](#client-assertions).                        |
| `getCookieSecrets(realmId)`                                                  | The active cookie HMAC secret and the most recently retired one, as fresh buffers.                                                    |
| `encrypt({ realmId, plaintext, context? })`                                  | A `data_at_rest` ciphertext that names its key. See [Data at rest](#data-at-rest).                                                    |
| `decrypt({ realmId, ciphertext, context? })`                                 | The plaintext. An `active` or `retired` key decrypts; a `compromised` one is refused.                                                 |
| `getVerificationKeys(realmId, purpose)`                                      | The public keys that may verify the purpose's tokens: `active` keys and `retired` keys still inside their publication window.         |
| `getJwks(realmId)`                                                           | The realm's JWKS: the published `token_signing` and `event_signing` keys inside their window, `next` keys included, in a fixed order. |
| `getUpstreamJwks(realmId, providerId)`                                       | The JWKS of one upstream provider's client-assertion keys, by the same window rules as `getJwks`.                                     |

What the signer guarantees:

- **It names the issuer and the key.** `iss` comes from the realm row and `kid` from the active
  key. A claims set with `iss`, or a request with any field the operation does not take (`kid`,
  `alg`, a header), is refused with `SignerRequestRefusedError`. The claims are serialized once
  before signing, so what is checked is what is signed.
- **Each purpose signs its own token types only** (`JWS_TYP_BY_PURPOSE`). Any other pair is refused.

  | Purpose         | `typ`                        |
  | --------------- | ---------------------------- |
  | `token_signing` | `at+jwt`, `JWT` (ID token)   |
  | `event_signing` | `secevent+jwt`, `logout+jwt` |

- **Each role calls only what `SIGNER_POLICY` grants.** Anything else is a
  `SignerAccessDeniedError`. Every role may read public keys.

  | Role       | May call                                                                                  |
  | ---------- | ----------------------------------------------------------------------------------------- |
  | `local`    | Everything. The caller inside the signer's own process, in a single deployment.           |
  | `web`      | `getCookieSecrets`. It never signs anything.                                              |
  | `api`      | `signJws` for `token_signing`, `signHybrid`, `signClientAssertion`, `encrypt`, `decrypt`. |
  | `delivery` | `signJws` for `event_signing`, `signWebhook`.                                             |
  | `admin`    | Public keys only. The key operations of #544 and #551 add their grants.                   |

  The public keys are `getVerificationKeys`, `getJwks` and `getUpstreamJwks`.

- **No key leaves it.** No operation returns a private key, a key object or symmetric material,
  except the cookie HMAC secret, which ADR-019 hands to the browser-facing role. A webhook secret
  is shown once, by `createKey`, never by the signer. A compromised caller still gets signatures
  for its allowed purposes, never a key. Errors carry roles, purposes, algorithms, realm ids and
  `kid`s only.
- **It never creates a key.** A realm without the key an operation needs gets a
  `SignerKeyNotFoundError`. A realm without an issuer gets a `RealmIssuerNotFoundError`.
- **It never falls back to another key.** A key that does not unwrap fails the call with the KEK
  provider's typed error (`KEY_DECRYPTION_FAILED`, `KEK_UNKNOWN_REF`, `KEK_UNAVAILABLE`,
  `KEK_ACCESS_DENIED`).

### Webhook signatures

`signWebhook` signs one message for one subscription in the
[Standard Webhooks](https://www.standardwebhooks.com/) symmetric form: HMAC-SHA256 over
`id.timestamp.body`, base64, prefixed `v1,`. The delivery role holds no secret (ADR-019 Decision 8):
it sends the message and gets back the value of the `webhook-signature` header.

```typescript
const signature = await signer.signWebhook('delivery', {
  realmId,
  subscriptionId,
  id: event.id, // webhook-id: the same on every retry
  timestamp: Math.floor(Date.now() / 1000), // webhook-timestamp: this attempt
  body, // the exact bytes, or text sent as UTF-8
});
```

- The subscription's `active` secret signs, and during a rotation its `next` secret too. The header
  then carries both signatures, separated by a space, the active one first, so a receiver verifies
  with either secret. The output matches the reference libraries' test vector.
- `id` is printable ASCII without a full stop or a space, at most 255 characters; `timestamp` is
  whole seconds. A body is signed byte for byte; send it as signed.
- The secrets are imported as non-extractable HMAC keys, and only sign.
- If the events work chooses the asymmetric form (`v1a`, Ed25519), the purpose's key kind changes in
  `KEY_PURPOSES` and `signWebhook` signs under `v1a`; the operation, its request and its callers
  stay as they are.

### Client assertions

`signClientAssertion` signs the JWT QAuth sends as a client authenticating with `private_key_jwt`
to an upstream provider ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) §2.2, OpenID Connect
Core §9), with the provider's active key. ADR-019 Decision 12: a provider plugin holds no private key
and asks the signer.

```typescript
const assertion = await signer.signClientAssertion('api', {
  realmId,
  providerId,
  audience: provider.issuer, // the upstream issuer identifier, its sole value
  claims: { jti: randomUUID(), iat, exp: iat + 60 },
});
```

- `iss` and `sub` are the client id the realm's configuration of the provider names. The signer
  reads it through `SignerKeyStore.findUpstreamClient`, at most once per refresh interval; a claims
  set with `iss`, `sub` or `aud` is refused. A realm without a configuration for the provider gets
  an `UpstreamClientNotFoundError`. Until the upstream-login work adds that configuration, the
  repository wiring has none, so no assertion is signed.
- `aud` is `audience`, one string, as draft-ietf-oauth-rfc7523bis §4 requires for client
  authentication. `exp` and `jti` are required.
- The protected header is `alg`, `kid` and `typ: client-authentication+jwt` (`CLIENT_ASSERTION_TYP`,
  rfc7523bis §4). No realm verifier accepts that `typ`, so an assertion is never a QAuth token.
- `algorithm` picks the key, `RS256` by default; the provider may need `ES256` or `EdDSA`.
- `getUpstreamJwks(realmId, providerId)` serves the provider's published keys, for a provider that
  registers QAuth's public key or fetches it from a `jwks_uri`. The realm JWKS never lists them.

### The in-process signer

`createInProcessSigner` (from `/custody`) is the signer of a single deployment.

```typescript
const signer = createInProcessSigner({
  store, // a SignerKeyStore; the wiring builds it from the repositories
  kekProvider,
  enabledSignatureAlgorithms: cryptoEnv.enabledSignatureAlgorithms,
  hybridSigning: cryptoEnv.HYBRID_SIGNING_ENABLED,
});
```

- A key is read and unwrapped the first time a call needs it, then kept in memory under a size limit
  (`keyCacheSize`, default 256 keys). Signing and encryption keys are imported as non-extractable
  WebCrypto keys, and the plaintext material is zeroed as soon as it is imported. Concurrent first
  calls unwrap a key once.
- Which key is active is read at most once per `refreshIntervalMs` (default 60 seconds) per realm
  and purpose, so a signature with a warm cache runs no database query. Concurrent callers share one
  read. A rotation is followed within one interval; the old key stays published and verifiable
  meanwhile. When the key list changes, or the node has no earlier list to compare with, it reads
  its published keys again and drops the answer of any published-key read already running, so it
  never signs with a key its own verification keys leave out. Two nodes can disagree for up to one
  interval, which the rotation schedule (#542) must allow for. The realm's issuer never changes
  once set, so it is read once.
- A key marked `compromised` stops signing, decrypting and appearing in the JWKS at each node's next
  read, not at once. Emergency retirement (#551) adds an invalidation that reaches every node.
- Scoped keys are read per realm, purpose and scope, and unwrapped under their scope: a row moved to
  another subscription, provider or realm does not open. A rotation or a deletion of a scope reaches
  a node within one interval.
- With hybrid signing off, `signHybrid` is refused and the ML-DSA-65 private key is never unwrapped
  (ADR-005, #248 F10).

The remote signer of a distributed deployment (#497) implements the same interface.

### Data at rest

A ciphertext is four parts joined by `.`: the version `v1`, the `kid` of the `data_at_rest` key,
the 96-bit nonce and the AES-256-GCM ciphertext with its 128-bit tag, both base64url. The
associated data binds the realm id, the `kid` and the caller's `context` (at most 1024
characters), each length-prefixed, so a ciphertext decrypts only in the realm and for the context it
was made for. Pass the row it belongs to as `context`, so a ciphertext copied to another row fails.

## Testing

```bash
pnpm nx test server-keys
pnpm nx test-integration server-keys # needs Docker
```
