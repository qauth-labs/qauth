# @qauth-labs/server-keys

Envelope encryption for the keys QAuth stores, and the provider of the key-encryption key (KEK)
that protects them ([ADR-019 Decision 9](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md)).

> **Status:** the library and its default provider are complete, but nothing calls them yet. The
> key table (#461), key generation (#463) and the signer (#464) build on it.

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

## Testing

```bash
pnpm nx test server-keys
```
