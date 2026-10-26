# JWT Service Library

JWT (JSON Web Token) service library for QAuth with token signing and verification, key import, JWKS export, and refresh token generation. Access tokens are signed with EdDSA (Ed25519). ID tokens are signed with EdDSA or RS256. Signing and verification go through [`@qauth-labs/core-crypto`](../../core/crypto/README.md).

## Overview

The `@qauth-labs/server-jwt` library provides:

- **JWT Signing & Verification** - EdDSA (Ed25519) access tokens, EdDSA or RS256 ID tokens
- **Key Management** - Ed25519 key pair generation, Ed25519 and RS256 PEM import, public key export
- **JWKS export** - public JWKs for Ed25519 (`OKP`), RS256 (`RSA`) and ML-DSA-65 (`AKP`) keys
- **DPoP binding** - the `cnf.jkt` claim of RFC 9449 and the `DPoP` authorization scheme
- **Refresh Token Generation** - Secure refresh token generation with SHA-256 hashing
- **Hybrid post-quantum signing** - detached-parallel ML-DSA-65 + Ed25519 ([ADR-005](../../../docs/adr/005-pqc-hybrid-signing.md)), off by default
- **Type-Safe API** - Full TypeScript support with proper error handling
- **Custom Error Types** - Domain-specific errors for JWT operations

## Where the keys come from

This library takes imported keys as arguments and reads no configuration. In the auth-server, [`@qauth-labs/fastify-plugin-jwt`](../../fastify/plugins/jwt/README.md) imports them from the `JWT_*` key variables. At boot the auth-server also imports those keys into the default realm's encrypted key store. Tokens are still signed with the variables until token signing moves onto the store (#491). See [Keys](https://docs.qauth.dev/operate/keys/) for generating each key.

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import {
  signAccessToken,
  verifyAccessToken,
  generateEdDSAKeyPair,
  generateRefreshToken,
} from '@qauth-labs/server-jwt';
```

## Usage

### Basic JWT Operations

#### Signing Access Tokens

```typescript
import { signAccessToken, generateEdDSAKeyPair } from '@qauth-labs/server-jwt';

// Generate key pair (or import existing keys)
const { privateKey, publicKey } = await generateEdDSAKeyPair();

// Sign an access token
const token = await signAccessToken(
  {
    sub: 'user-123',
    clientId: 'client-abc',
    email: 'user@example.com',
    email_verified: true,
  },
  privateKey,
  'https://auth.example.com', // issuer
  900 // expires in 15 minutes (900 seconds)
);
```

#### Verifying Access Tokens

```typescript
import { verifyAccessToken } from '@qauth-labs/server-jwt';
import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';

try {
  const payload = await verifyAccessToken(token, publicKey);
  console.log(payload.sub); // 'user-123'
  console.log(payload.email); // 'user@example.com'
  console.log(payload.iat); // issued at timestamp
  console.log(payload.exp); // expiration timestamp
} catch (error) {
  if (error instanceof JWTExpiredError) {
    // Token has expired
  } else if (error instanceof JWTInvalidError) {
    // Token is invalid (malformed, wrong signature, etc.)
  }
}
```

### Key Management

#### Generate EdDSA Key Pair

```typescript
import { generateEdDSAKeyPair } from '@qauth-labs/server-jwt';

// Generate non-extractable keys (default, more secure)
const { privateKey, publicKey } = await generateEdDSAKeyPair();

// Generate extractable keys (for testing or key export)
const { privateKey: extractablePrivate, publicKey: extractablePublic } =
  await generateEdDSAKeyPair(true);
```

#### Import Existing Keys

```typescript
import {
  derivePublicKeyPemFromPrivate,
  importPrivateKey,
  importPublicKey,
  importRs256PrivateKey,
  importRs256PublicKey,
} from '@qauth-labs/server-jwt';

// Import an Ed25519 private key from PEM format (PKCS#8)
const privateKey = await importPrivateKey(
  `-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----`
);

// Import an Ed25519 public key from PEM format (SPKI)
const publicKey = await importPublicKey(
  `-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----`
);

// RS256 keys have their own importers; rs256PrivatePem is a PKCS#8 PEM string
const rs256PrivateKey = await importRs256PrivateKey(rs256PrivatePem);
const rs256PublicKey = await importRs256PublicKey(derivePublicKeyPemFromPrivate(rs256PrivatePem));
```

### Refresh Token Generation

```typescript
import {
  generateRefreshToken,
  hashRefreshToken,
  isValidRefreshTokenFormat,
} from '@qauth-labs/server-jwt';

// Generate refresh token pair
const { token, tokenHash } = generateRefreshToken();
// token: "a1b2c3d4e5f6..." (64 hex chars, send to user)
// tokenHash: "9f8e7d6c5b4a..." (64 hex chars, store in DB)

// Hash an existing token
const hash = hashRefreshToken('a1b2c3d4e5f6...');
// Returns: "9f8e7d6c5b4a..." (SHA-256 hash)

// Validate token format
isValidRefreshTokenFormat('a1b2c3d4e5f6...'); // true (64 hex chars)
isValidRefreshTokenFormat('invalid'); // false (wrong format)
```

### Complete Example

```typescript
import {
  signAccessToken,
  verifyAccessToken,
  generateEdDSAKeyPair,
  generateRefreshToken,
} from '@qauth-labs/server-jwt';
import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';

// Setup: Generate or import keys
const { privateKey, publicKey } = await generateEdDSAKeyPair();

// Issue tokens
const accessToken = await signAccessToken(
  {
    sub: 'user-123',
    clientId: 'client-abc',
    email: 'user@example.com',
    email_verified: true,
  },
  privateKey,
  'https://auth.example.com',
  900 // 15 minutes
);

const { token: refreshToken, tokenHash } = generateRefreshToken();

// Store tokenHash, never the plain token, with the refresh token record

// Verify access token
try {
  const payload = await verifyAccessToken(accessToken, publicKey);
  // Token is valid, use payload
} catch (error) {
  if (error instanceof JWTExpiredError) {
    // Use refresh token to get new access token
  } else if (error instanceof JWTInvalidError) {
    // Reject request
  }
}
```

## API

### JWT Service

#### `signAccessToken(payload, privateKey, issuer, expiresIn): Promise<string>`

Signs an access token with the given payload. The protected header carries `typ: at+jwt` (RFC 9068). The payload also gets a fresh `jti`, `client_id` and `token_use: 'access'`.

**Parameters:**

- `payload: SignAccessTokenPayload` - Token payload containing:
  - `sub: string` - Subject (user ID, or the client ID for client_credentials)
  - `clientId: string` - OAuth client identifier, stamped as `client_id`
  - `email?: string` - User email, only under the `email` scope
  - `email_verified?: boolean` - Email verification status, present when `email` is
  - `scope?: string` - Space-separated granted scopes
  - `aud?: string | string[]` - Audience; defaults to `clientId`
  - `act?: ActClaim` - RFC 8693 actor claim, only on delegated tokens
  - `cnf?: { jkt: string }` - RFC 9449 key thumbprint, only on DPoP-bound tokens
- `privateKey: KeyLike` - EdDSA private key for signing
- `issuer: string` - JWT issuer (iss claim)
- `expiresIn: number` - Expiration time in seconds

**Returns:** Promise resolving to signed JWT token string

**Example:**

```typescript
const token = await signAccessToken(
  { sub: 'user-123', clientId: 'client-abc', email: 'user@example.com', email_verified: true },
  privateKey,
  'https://auth.example.com',
  900
);
```

#### `signIdToken(payload, privateKey, issuer, expiresIn, alg?, kid?): Promise<string>`

Signs an OIDC ID token with `typ: JWT` and `token_use: 'id'`.

**Parameters:**

- `payload: SignIdTokenPayload` - `sub`, `audience` (the client ID), and optional `email`, `email_verified`, `name`, `nonce`, `authTime`, `acr`
- `privateKey: KeyLike` - EdDSA or RS256 private key, matching `alg`
- `issuer: string` - JWT issuer (iss claim)
- `expiresIn: number` - Expiration time in seconds
- `alg?: 'EdDSA' | 'RS256'` - Signature algorithm (default: `'EdDSA'`)
- `kid?: string` - Key ID for the protected header, omitted when empty

`authTime` is in epoch milliseconds and becomes `auth_time` in seconds. An empty `acr` is left out.

#### `verifyAccessToken(token, publicKey, options?): Promise<JWTPayload>`

Verifies and decodes an access token. The algorithm is pinned to `EdDSA`. A signed `typ` other than `at+jwt` is always refused.

**Parameters:**

- `token: string` - JWT token string to verify
- `publicKey: KeyLike` - EdDSA public key for verification
- `options.issuer?: string` - Required `iss` value
- `options.audience?: string | string[]` - Required `aud` value
- `options.requireTyp?: boolean` - Also refuse a token without `typ` (default: `false`)

**Returns:** Promise resolving to decoded JWT payload

**Throws:**

- `JWTExpiredError` - If the token has expired
- `JWTInvalidError` - If the token is invalid (malformed, wrong signature, wrong `typ`, malformed claims, etc.)

**Example:**

```typescript
try {
  const payload = await verifyAccessToken(token, publicKey);
} catch (error) {
  if (error instanceof JWTExpiredError) {
    // Handle expiration
  }
}
```

### Key Management

#### `generateEdDSAKeyPair(extractable?): Promise<{ privateKey, publicKey }>`

Generates a new EdDSA (Ed25519) key pair.

**Parameters:**

- `extractable?: boolean` - Whether keys should be extractable (default: `false`)

**Returns:** Promise resolving to key pair object

**Example:**

```typescript
const { privateKey, publicKey } = await generateEdDSAKeyPair();
```

#### `importPrivateKey(pem): Promise<KeyLike>`

Imports an Ed25519 private key from PEM format (PKCS#8). The key is not extractable.

**Parameters:**

- `pem: string` - Private key in PEM format

**Returns:** Promise resolving to `KeyLike` (CryptoKey)

**Example:**

```typescript
const privateKey = await importPrivateKey(
  `-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----`
);
```

#### `importPublicKey(pem): Promise<KeyLike>`

Imports an Ed25519 public key from PEM format (SPKI).

**Parameters:**

- `pem: string` - Public key in PEM format

**Returns:** Promise resolving to `KeyLike` (CryptoKey)

**Example:**

```typescript
const publicKey = await importPublicKey(
  `-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----`
);
```

#### `importRs256PrivateKey(pem)` / `importRs256PublicKey(pem): Promise<KeyLike>`

Import an RS256 private key (PKCS#8 PEM) or public key (SPKI PEM). Only `signIdToken` signs with RS256.

#### `derivePublicKeyPemFromPrivate(privatePem): string`

Derives the SPKI public key PEM from a PKCS#8 private key PEM with `node:crypto`. It works for RSA and Ed25519 keys.

#### `exportPublicKeyPem(key): Promise<string>`

Exports a key as SPKI PEM with `jose`. The key must be extractable, so a key from `importPrivateKey` fails. Use `derivePublicKeyPemFromPrivate` for a PEM private key.

### JWKS

#### `exportPublicJwk(publicKey, kid?): Promise<PublicJwk>` / `exportRs256PublicJwk(publicKey, kid?): Promise<Rs256Jwk>`

Export an Ed25519 key as an `OKP` JWK or an RS256 key as an `RSA` JWK. Both set `use: 'sig'` and `alg`, and add `kid` only when it is not empty. Private members are never published.

#### `assertDistinctJwksKeyIds(keys): void`

Throws when two JWKS entries share a `kid`, or one algorithm has two entries without one.

### Authorization header

#### `extractJWTFromHeader(authHeader): string | null`

Returns the token of an `Authorization: Bearer <token>` header, or `null`.

#### `extractAccessTokenCredential(authHeader, { allowDpop? }): AccessTokenCredential | null`

Returns `{ scheme, token }` for a `Bearer` header. With `allowDpop: true` it also accepts the `DPoP` scheme of RFC 9449.

#### `decodeJwtUnsafe(token)`

Decodes a token without verifying it, for an expired token at logout or for logging. Throws `JWTInvalidError` when the token is malformed or has no string `sub`.

### Refresh Token Generator

#### `generateRefreshToken(): RefreshTokenResult`

Generates a secure refresh token pair (token and hash).

**Returns:** Object with:

- `token: string` - Plain token (64 hex characters, send to user)
- `tokenHash: string` - SHA-256 hash (64 hex characters, store in DB)

**Security Features:**

- 32-byte (256-bit) random tokens using `crypto.randomBytes(32)`
- Hex encoding (64 characters) for URL-safe transmission
- SHA-256 hashing for secure storage
- High entropy prevents brute-force attacks

**Example:**

```typescript
const { token, tokenHash } = generateRefreshToken();
```

#### `hashRefreshToken(token): string`

Hashes a refresh token using SHA-256.

**Parameters:**

- `token: string` - Plain refresh token

**Returns:** SHA-256 hash as hex string (64 characters)

**Example:**

```typescript
const hash = hashRefreshToken('a1b2c3d4e5f6...');
```

#### `isValidRefreshTokenFormat(token): boolean`

Validates that a token is a valid 64-character hexadecimal string.

**Parameters:**

- `token: string` - Token to validate

**Returns:** `true` if valid format, `false` otherwise

**Example:**

```typescript
isValidRefreshTokenFormat('a1b2c3d4e5f6...'); // true
isValidRefreshTokenFormat('invalid'); // false
```

### Hybrid post-quantum signing (ADR-005)

Alongside the classical API above, this library exposes a hybrid surface used
only when an operator sets `HYBRID_SIGNING_ENABLED=true`. A hybrid token **is**
an ordinary Ed25519 compact JWS — the ML-DSA-65 signature is detached and carried
alongside it, never inside the compact string — so classical verifiers are
unaffected. See the
[verifier guide](https://docs.qauth.dev/operate/pqc-verifier-guide/).

Hybrid signing also needs `SIGNING_ALGORITHM_MODE=ed25519+ml-dsa-65` and an
ML-DSA-65 seed in `JWT_MLDSA_PRIVATE_KEY`. Without both, the configuration
refuses to start. See
[the ML-DSA-65 seed](https://docs.qauth.dev/operate/keys/#ml-dsa-65-seed--only-with-hybrid-signing).
Each hybrid function takes `backend` or `options` with
`enabledSignatureAlgorithms`. It refuses to sign or verify ML-DSA-65 when that
list lacks it.

#### `signHybridAccessToken(payload, keys, issuer, expiresIn, backend): Promise<HybridSignedToken>`

Signs an access token with both algorithms. Returns the compact Ed25519 JWS plus
the detached PQC signature; the caller decides how to deliver the latter. The
auth-server delivers it by reference (`PQC_TOKEN_DELIVERY=reference`, the
default). It stores the signature under the token's `jti`, and introspection
returns it as `pqc_signature`.

#### `signHybridIdToken(payload, keys, issuer, expiresIn, backend): Promise<HybridSignedToken>`

The ID-token equivalent. The auth-server does not call it: ID tokens stay
classical.

#### `verifyHybridAccessToken(hybrid, keys, options): Promise<Record<string, unknown>>`

Verifies both signatures over the identical signing input. `options` takes
`enabledSignatureAlgorithms`, `requirePqc`, and optional `issuer` and
`audience`. A token whose signed header carries `pqc_alg` needs a valid
ML-DSA-65 signature, whatever `requirePqc` says. `requirePqc: true` also refuses
a token whose signed header makes no PQC claim. Failures throw
`CryptoVerificationError` from `@qauth-labs/core-crypto`, not the JWT errors.

#### `exportMlDsaPublicJwk(publicKey, kid?): AkpJwk` / `selectJwksKey(keys, { kid?, alg }): PublishedJwk | undefined`

Publish the ML-DSA public key as an `AKP` JWK alongside the Ed25519 `OKP` entry,
and select the right key when verifying against a mixed JWKS. `selectJwksKey`
matches on both `kid` and `alg`, and returns `undefined` unless exactly one
entry matches. The JWT plugin publishes the `AKP` entry whenever it is given an
ML-DSA-65 seed. The auth-server passes the seed only when
`HYBRID_SIGNING_ENABLED` is on.

## Types

### `SignAccessTokenPayload`

Payload structure for signing access tokens.

```typescript
interface SignAccessTokenPayload {
  sub: string; // Subject (user ID, or client ID for client_credentials)
  email?: string; // User email (only under the `email` scope)
  email_verified?: boolean; // Email verification status (present when `email` is)
  clientId: string; // OAuth client identifier
  scope?: string; // Space-separated granted scopes
  aud?: string | string[]; // Audience; falls back to `clientId`
  act?: ActClaim; // RFC 8693 actor, only on delegated tokens
  cnf?: ConfirmationClaim; // RFC 9449 `{ jkt }`, only on DPoP-bound tokens
}
```

### `JWTPayload`

JWT payload structure including standard claims.

```typescript
interface JWTPayload extends SignAccessTokenPayload {
  iat?: number; // Issued at (timestamp)
  exp?: number; // Expiration time (timestamp)
  iss?: string; // Issuer
  jti?: string; // Unique token ID, used for revocation
  token_use?: string; // 'access' on access tokens
}
```

### `KeyLike`

Type alias for `CryptoKey` (from Web Crypto API).

```typescript
type KeyLike = CryptoKey;
```

### `RefreshTokenResult`

Result from refresh token generation.

```typescript
interface RefreshTokenResult {
  token: string; // Plain token (64 hex chars)
  tokenHash: string; // SHA-256 hash (64 hex chars)
}
```

## Error Handling

The library uses custom error types from `@qauth-labs/shared-errors`:

### `JWTExpiredError`

Thrown when a JWT token has expired.

```typescript
import { JWTExpiredError } from '@qauth-labs/shared-errors';

try {
  await verifyAccessToken(token, publicKey);
} catch (error) {
  if (error instanceof JWTExpiredError) {
    // Token expired
    console.error(error.message); // "JWT token has expired"
    console.error(error.statusCode); // 401
    console.error(error.code); // "JWT_EXPIRED"
  }
}
```

### `JWTInvalidError`

Thrown when a JWT token is invalid (malformed, wrong signature, etc.).

```typescript
import { JWTInvalidError } from '@qauth-labs/shared-errors';

try {
  await verifyAccessToken(token, publicKey);
} catch (error) {
  if (error instanceof JWTInvalidError) {
    // Token invalid
    console.error(error.message); // "Invalid JWT token: ..."
    console.error(error.statusCode); // 401
    console.error(error.code); // "JWT_INVALID"
  }
}
```

## Security Considerations

1. **Never store private keys in code** - Use environment variables or secure key management services
2. **Use non-extractable keys in production** - Only use `extractable: true` for testing or key export scenarios
3. **Store refresh token hashes, not plain tokens** - Always hash refresh tokens before storing in database
4. **Validate token format** - Use `isValidRefreshTokenFormat` before processing refresh tokens
5. **Handle errors properly** - Always catch and handle `JWTExpiredError` and `JWTInvalidError`
6. **Use appropriate expiration times** - Access tokens should have short expiration (15-60 minutes), refresh tokens longer (7-30 days)
7. **Rotate keys periodically** - Implement key rotation strategy for long-term security

## Best Practices

1. **Key Management** - Store keys securely (environment variables, secrets manager) and never commit them to version control
2. **Token Expiration** - Use short-lived access tokens (15-60 minutes) and longer-lived refresh tokens (7-30 days)
3. **Error Handling** - Always handle `JWTExpiredError` and `JWTInvalidError` appropriately in your application
4. **Refresh Token Storage** - Store only the hash of refresh tokens in the database, never the plain token
5. **Token Validation** - Validate refresh token format before processing to prevent injection attacks
6. **Key Rotation** - Implement a key rotation strategy to maintain security over time

## Development

### Running Tests

```bash
pnpm nx test server-jwt
```

### Type Checking

```bash
pnpm nx typecheck server-jwt
```

## Dependencies

- `@qauth-labs/core-crypto`: signing, verification, key generation and import, hybrid ML-DSA-65 signing
- `jose`: unverified decoding, SPKI export and JWK export
- `zod`: claim-shape validation of verified access tokens
- `@qauth-labs/shared-errors`: Custom error types for JWT operations

## Related Libraries

- [`@qauth-labs/core-crypto`](../../core/crypto/README.md): the signing abstraction this library calls
- [`@qauth-labs/fastify-plugin-jwt`](../../fastify/plugins/jwt/README.md): the Fastify plugin that wires this library into the auth-server
- [`@qauth-labs/server-config`](../config/README.md): JWT and signing configuration schemas (`jwtEnvSchema`, `cryptoEnvSchema`)
- [`@qauth-labs/shared-errors`](../../shared/errors/README.md): JWT error types (`JWTExpiredError`, `JWTInvalidError`)

## License

Apache-2.0
