# Core Crypto Library

Algorithm-agnostic cryptographic signing abstraction for QAuth
(`@qauth-labs/core-crypto`). This is the stable seam that decouples token
signing/verification from any specific cryptographic backend, per
[ADR-005](../../../docs/adr/005-pqc-hybrid-signing.md).

## Why

QAuth signs OAuth 2.1 access tokens and OIDC ID tokens as a core function. To
keep crypto-agility (Phase 1 Ed25519 today; hybrid ML-DSA + Ed25519 later)
without rewriting service code on every backend change, all signing,
verification, and key generation go through this small interface. Service layers
(`@qauth-labs/server-jwt` and friends) depend on this abstraction, never on
`jose` (or a future native/WASM backend) directly.

Phase 1 is a pure `jose`/EdDSA backend behind the seam — no PQC yet.

## API

```typescript
import {
  sign,
  verify,
  generateSigningKeyPair,
  importPrivateSigningKey,
  importPublicSigningKey,
  CryptoVerificationError,
  type SignatureAlgorithm,
  type SigningKey,
  type SigningKeyPair,
} from '@qauth-labs/core-crypto';
```

### `sign(claims, privateKey, alg, options): Promise<string>`

Signs an already-shaped claims record into a compact JWT. Stamps the protected
header (`alg`) and the registered `iat` / `exp` / `iss` / `aud` claims only —
all business/claims shaping is the caller's responsibility.

```typescript
const jwt = await sign({ sub: 'user-1', scope: 'openid' }, privateKey, 'EdDSA', {
  issuer: 'https://auth.example.com',
  expiresIn: 900,
  audience: 'client-1',
});
```

### `verify(token, publicKey, options): Promise<Record<string, unknown>>`

Verifies the signature, algorithm, and (when supplied) issuer/audience, and
returns the raw claims. Temporal-claim evaluation can be tuned with
`clockTolerance` (allowed skew in seconds) and `currentDate` (reference time,
useful for deterministic tests). Application-level claim-shape validation is
**not** done here — the caller validates the returned claims. On failure it
throws a `CryptoVerificationError`.

```typescript
const claims = await verify(jwt, publicKey, {
  algorithms: ['EdDSA'],
  issuer: 'https://auth.example.com',
});
```

### `CryptoVerificationError`

Backend-neutral verification error. Branch on `reason` (`'expired' | 'invalid'`)
and, for diagnostic failures, `detail` — never on the underlying backend's error
types. This is what lets callers map verification failures onto their own domain
errors without coupling to `jose`.

### `generateSigningKeyPair(alg, options?)` / `importPrivateSigningKey(pem, alg)` / `importPublicSigningKey(pem, alg)`

Asymmetric key generation and PKCS#8/SPKI PEM import. Generated private keys are
non-extractable by default.

### `exportPublicSigningJwk(publicKey, { alg, kid? })` / `importPublicSigningJwk(jwk, alg)`

JWK serialization for the wallet-federation surface, where verification keys are
published as JWKs rather than PEM. Exports are fully specified (`alg` + `use:
'sig'`), and the importer pins `kty`/`crv` against the **caller-chosen** `alg`,
refuses private key material, and refuses a JWK whose own `alg`/`use` contradicts
the pin.

## ES256 and JWE (#298)

`JwsAlgorithm` is `'EdDSA' | 'RS256' | 'ES256'`. `ES256` (ECDSA P-256 +
SHA-256) exists for the **wallet-federation** surface — OID4VP request-object
signing and verification of wallet-supplied JWTs — because HAIP §7 names it as
the one mandatory signature algorithm and wallet secure elements do P-256.

Two properties are load-bearing and must not be relaxed:

- **ES256 is deliberately absent from `SignatureAlgorithm`.** That union is the
  byte-level `SignatureBackend` dispatch seam behind ADR-005 hybrid signing.
  Keeping ES256 out of it means `getSignatureBackend`, `PqcBackendSelection` and
  `SIGNING_ALGORITHM_MODE` cannot even name it, so QAuth's own token issuance
  stays EdDSA/hybrid as a _structural_ fact rather than a convention.
- **Widening the union widens nothing at any verifier.** Acceptance is decided
  per call site by `VerifyOptions.algorithms`, which every verifier pins
  explicitly. `verifyAccessToken` still pins `['EdDSA']`.

### JWE — `ECDH-ES` (P-256) with `A128GCM` / `A256GCM`

For the OID4VP `direct_post.jwt` encrypted-response mode (HAIP §5). One cipher
suite, allowlisted: key wrapping, `dir`, `RSA1_5` and the AES-CBC-HMAC family are
unreachable, not merely discouraged.

```typescript
// Verifier: one ephemeral key pair per Authorization Request.
const pair = await generateEphemeralEncryptionKeyPair({ kid: requestId });
const clientMetadataJwk = await exportEncryptionPublicJwk(pair);

// Wallet: encrypt the Authorization Response to the published key.
const jwe = await encryptJwe(response, await importEncryptionPublicJwk(clientMetadataJwk), {
  enc: 'A256GCM',
  kid: clientMetadataJwk.kid,
});

// Verifier: decrypt with the algorithms PINNED — both lists are required.
const { payload } = await decryptJwe(jwe, pair.privateKey, {
  keyManagementAlgorithms: ['ECDH-ES'],
  contentEncryptionAlgorithms: ['A128GCM', 'A256GCM'],
});
```

Every failure — wrong key, tampered ciphertext/tag/IV, rejected `alg`/`enc`, a
`zip` header, malformed input, a non-JSON plaintext — throws a
`CryptoDecryptionError` whose `message` is the fixed constant
`CRYPTO_DECRYPTION_ERROR_MESSAGE`. That uniformity is deliberate: a caller able
to tell those apart is a decryption oracle. The backend's own text is kept on the
separate `.detail` field, which **does** distinguish them and is therefore for
local logs only — never for a response to a remote party.

`zip` is refused in **both** directions: `encryptJwe` rejects it as a reserved
protected-header member, and `decryptJwe` rejects an incoming JWE that carries it
(RFC 8725 §3.5, CRIME/BREACH). Decrypt is the attacker-controlled direction — the
per-request encryption public key is published in client metadata by design — so
refusing it only on encrypt would leave anyone who reads that key able to force
decompression on every post.

Ephemeral private keys are non-extractable by default. A multi-instance
deployment that must carry one across HTTP requests generates it with
`{ extractable: true }` and persists `exportEncryptionPrivateJwk` **encrypted at
rest**, scoped to its one request. Age them with
`isEphemeralEncryptionKeyPairExpired`.

## Extending (future PQC work)

Adding a backend/algorithm (e.g. ML-DSA-65, hybrid composites) means widening
`SignatureAlgorithm` and branching inside `sign` / `verify` / the key functions.
Because every call site consumes only this interface, no service-layer code
changes when a backend is added — that is the entire point of the seam.

## Development

```bash
pnpm nx test core-crypto
pnpm nx typecheck core-crypto
pnpm nx lint core-crypto
```

## License

Apache-2.0
