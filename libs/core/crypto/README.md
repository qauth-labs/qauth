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
returns the raw claims. Application-level claim-shape validation is **not**
done here — the caller validates the returned claims. On failure it throws a
`CryptoVerificationError`.

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
