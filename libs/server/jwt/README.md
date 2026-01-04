# JWT Service Library

JWT (JSON Web Token) service library for QAuth with EdDSA signing, key management, and refresh token generation. This library provides secure token generation and verification using Ed25519 algorithm.

## Overview

The `@qauth/server-jwt` library provides:

- **JWT Signing & Verification** - EdDSA (Ed25519) based JWT operations
- **Key Management** - EdDSA key pair generation and import/export utilities
- **Refresh Token Generation** - Secure refresh token generation with SHA-256 hashing
- **Type-Safe API** - Full TypeScript support with proper error handling
- **Custom Error Types** - Domain-specific errors for JWT operations

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import {
  signAccessToken,
  verifyAccessToken,
  generateEdDSAKeyPair,
  generateRefreshToken,
} from '@qauth/server-jwt';
```

## Usage

### Basic JWT Operations

#### Signing Access Tokens

```typescript
import { signAccessToken, generateEdDSAKeyPair } from '@qauth/server-jwt';

// Generate key pair (or import existing keys)
const { privateKey, publicKey } = await generateEdDSAKeyPair();

// Sign an access token
const token = await signAccessToken(
  {
    sub: 'user-123',
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
import { verifyAccessToken } from '@qauth/server-jwt';
import { JWTExpiredError, JWTInvalidError } from '@qauth/shared-errors';

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
import { generateEdDSAKeyPair } from '@qauth/server-jwt';

// Generate non-extractable keys (default, more secure)
const { privateKey, publicKey } = await generateEdDSAKeyPair();

// Generate extractable keys (for testing or key export)
const { privateKey: extractablePrivate, publicKey: extractablePublic } =
  await generateEdDSAKeyPair(true);
```

#### Import Existing Keys

```typescript
import { importPrivateKey, importPublicKey } from '@qauth/server-jwt';

// Import private key from PEM format (PKCS#8)
const privateKey = await importPrivateKey(
  `-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----`
);

// Import public key from PEM format (SPKI)
const publicKey = await importPublicKey(
  `-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----`
);
```

### Refresh Token Generation

```typescript
import {
  generateRefreshToken,
  hashRefreshToken,
  isValidRefreshTokenFormat,
} from '@qauth/server-jwt';

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
} from '@qauth/server-jwt';
import { JWTExpiredError, JWTInvalidError } from '@qauth/shared-errors';

// Setup: Generate or import keys
const { privateKey, publicKey } = await generateEdDSAKeyPair();

// Issue tokens
const accessToken = await signAccessToken(
  {
    sub: 'user-123',
    email: 'user@example.com',
    email_verified: true,
  },
  privateKey,
  'https://auth.example.com',
  900 // 15 minutes
);

const { token: refreshToken, tokenHash } = generateRefreshToken();

// Store refreshTokenHash in database
await db.insert(refreshTokens).values({
  userId: 'user-123',
  tokenHash,
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
});

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

Signs an access token with the given payload.

**Parameters:**

- `payload: SignAccessTokenPayload` - Token payload containing:
  - `sub: string` - Subject (user ID)
  - `email: string` - User email
  - `email_verified: boolean` - Email verification status
- `privateKey: KeyLike` - EdDSA private key for signing
- `issuer: string` - JWT issuer (iss claim)
- `expiresIn: number` - Expiration time in seconds

**Returns:** Promise resolving to signed JWT token string

**Example:**

```typescript
const token = await signAccessToken(
  { sub: 'user-123', email: 'user@example.com', email_verified: true },
  privateKey,
  'https://auth.example.com',
  900
);
```

#### `verifyAccessToken(token, publicKey): Promise<JWTPayload>`

Verifies and decodes an access token.

**Parameters:**

- `token: string` - JWT token string to verify
- `publicKey: KeyLike` - EdDSA public key for verification

**Returns:** Promise resolving to decoded JWT payload

**Throws:**

- `JWTExpiredError` - If the token has expired
- `JWTInvalidError` - If the token is invalid (malformed, wrong signature, etc.)

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

Imports a private key from PEM format (PKCS#8).

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

Imports a public key from PEM format (SPKI).

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

## Types

### `SignAccessTokenPayload`

Payload structure for signing access tokens.

```typescript
interface SignAccessTokenPayload {
  sub: string; // Subject (user ID)
  email: string; // User email
  email_verified: boolean; // Email verification status
}
```

### `JWTPayload`

JWT payload structure including standard claims.

```typescript
interface JWTPayload extends SignAccessTokenPayload {
  iat?: number; // Issued at (timestamp)
  exp?: number; // Expiration time (timestamp)
  iss?: string; // Issuer
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

The library uses custom error types from `@qauth/shared-errors`:

### `JWTExpiredError`

Thrown when a JWT token has expired.

```typescript
import { JWTExpiredError } from '@qauth/shared-errors';

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
import { JWTInvalidError } from '@qauth/shared-errors';

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

- `jose`: JWT operations with EdDSA support
- `@qauth/shared-errors`: Custom error types for JWT operations

## Related Libraries

- [`@qauth/server-config`](../config/README.md): JWT configuration schema (`jwtEnvSchema`)
- [`@qauth/shared-errors`](../../shared/errors/README.md): JWT error types (`JWTExpiredError`, `JWTInvalidError`)

## License

Apache-2.0
