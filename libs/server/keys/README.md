# @qauth-labs/server-keys

The keys QAuth stores per realm and purpose: the fixed list of key purposes, key generation,
envelope encryption, and the provider of the key-encryption key (KEK) that protects them
([ADR-019 Decision 9](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md)).

> **Status:** the library and its default provider are complete, but nothing calls them yet. The
> signer (#464) and the import of the environment keys at first boot (#485) build on it.

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
- **`createKeyFactory`**: `createKey` and `provisionRealmKeys`, which generate, seal and store keys.
  See [Creating keys](#creating-keys).

The library may import only `scope:core` and `scope:shared` libraries. Its `type:key-custody` tag
carries that rule in `eslint.config.mjs`.

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
import { loadKekProvider, openKeyMaterial, sealKeyMaterial } from '@qauth-labs/server-keys';

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
configuration warnings through `context.warn`.

- Bind the associated data. A byte-oriented backend can authenticate `encodeKeyAad(aad)`.
- Return a fresh buffer from every `unwrap`. The caller zeroes it, so never hand out a cached data
  key.
- Map backend failures onto the typed errors: `KeyDecryptionError` for bytes that do not
  authenticate, `UnknownKekRefError` for a reference it holds no key for, `KekUnavailableError` for
  an outage or throttling, and `KekAccessDeniedError` for a refused call. Callers branch on `code`
  (`isKeyCustodyError`), since an adapter may carry its own copy of this library.
- Run the contract against the backend or a test double of it:

```typescript
import { runKekProviderContract } from '@qauth-labs/server-keys';
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

`createKeyFactory` takes the deployment's switches and returns `createKey` and `provisionRealmKeys`.

```typescript
import { createKeyFactory } from '@qauth-labs/server-keys';

const keys = createKeyFactory({
  store, // a RealmKeyStore, below
  kekProvider: provider,
  enabledSignatureAlgorithms: cryptoEnv.enabledSignatureAlgorithms, // SIGNING_ALGORITHM_MODE
  hybridSigning: cryptoEnv.HYBRID_SIGNING_ENABLED,
});

await keys.provisionRealmKeys(realmId); // token_signing, event_signing, cookie_hmac, data_at_rest
await keys.createKey({ realmId, purpose: 'webhook_signing', scopeId: subscriptionId });
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
`next`. Nothing is stored in either case.

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

### What is stored

- **`kid`**: the RFC 7638 SHA-256 thumbprint of the public JWK for an asymmetric key, and 128 random
  bits for a symmetric one.
- **Sealed material**: PKCS#8 DER for `EdDSA`, `RS256`, `ES256` and `ECDH-ES`; the 32-byte seed for
  `ML-DSA-65`; 32 random bytes for `HS256` and `A256GCM`. The plaintext is zeroed after sealing.
- **Public JWK**: fully specified, with `kid`, `alg` and `use`, for a published purpose only.

### The store

This library may not import `@qauth-labs/infra-db`, so it writes through a `RealmKeyStore` port
shaped like the realm keys repository (#461). The signer's wiring passes the repository:

```typescript
const store: RealmKeyStore<DbClient> = {
  transaction: (work, outer) => (outer ?? db).transaction(work),
  findByKid: repositories.realmKeys.findByKid,
  listByRealm: repositories.realmKeys.listByRealm,
  create: repositories.realmKeys.create,
};
```

## Testing

```bash
pnpm nx test server-keys
pnpm nx test-integration server-keys # needs Docker
```
