# @qauth-labs/server-pkce

PKCE (Proof Key for Code Exchange, [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636))
primitives for the QAuth OAuth 2.1 authorization-code flow.

## Overview

OAuth 2.1 makes PKCE mandatory for the authorization-code grant. This library
provides small, dependency-free helpers (built on Node's `node:crypto`) for the
`S256` PKCE method:

- generate a cryptographically random **code verifier**,
- derive the corresponding **code challenge** (`BASE64URL(SHA256(verifier))`),
- validate verifier format per RFC 7636,
- and verify a verifier against a stored challenge using a **timing-safe**
  comparison.

Only the `S256` method is supported (the OAuth 2.1 / BCP recommendation); the
plaintext method is intentionally not implemented.

## Installation

This library is part of the QAuth monorepo and is automatically available to
other projects within the workspace.

```typescript
import { generatePkcePair } from '@qauth-labs/server-pkce';
```

## Usage

### Generate a PKCE pair (client side)

```typescript
import { generatePkcePair } from '@qauth-labs/server-pkce';

const { codeVerifier, codeChallenge } = generatePkcePair();

// Store codeVerifier locally (e.g. session); send the challenge on /authorize:
//   GET /oauth/authorize?...&code_challenge=<codeChallenge>&code_challenge_method=S256
// Then send codeVerifier to /oauth/token when exchanging the authorization code.
```

### Verify a verifier against a stored challenge (server side)

At authorize time the server stores `code_challenge`. At token time the client
presents `code_verifier`; the server verifies it:

```typescript
import { verifyCodeChallenge } from '@qauth-labs/server-pkce';

const ok = verifyCodeChallenge(presentedVerifier, storedChallenge);
if (!ok) {
  // Reject the token request (invalid_grant)
}
```

### Lower-level helpers

```typescript
import {
  generateCodeVerifier,
  generateCodeChallenge,
  isValidCodeVerifierFormat,
} from '@qauth-labs/server-pkce';

const verifier = generateCodeVerifier(); // 43-char base64url string
const challenge = generateCodeChallenge(verifier); // BASE64URL(SHA256(verifier))

isValidCodeVerifierFormat(verifier); // true
isValidCodeVerifierFormat('short'); // false (must be 43–128 chars of [A-Za-z0-9._~-])
```

## API

### `generatePkcePair(): PkcePair`

Generates a fresh verifier + matching `S256` challenge. Returns
`{ codeVerifier, codeChallenge }`.

### `generateCodeVerifier(): string`

Generates a cryptographically random code verifier: 32 random octets (256 bits)
encoded as base64url, yielding a 43-character string.

### `generateCodeChallenge(verifier: string): string`

Computes the `S256` code challenge: `BASE64URL(SHA256(ASCII(verifier)))`, a
43-character base64url string. **Throws** `Error('Invalid code verifier format')`
if `verifier` is not a valid RFC 7636 verifier.

### `verifyCodeChallenge(verifier: string, storedChallenge: string): boolean`

Verifies `verifier` against a previously stored challenge using a timing-safe
comparison (`crypto.timingSafeEqual`). Returns `false` (does **not** throw) for an
invalid verifier format or a length mismatch.

### `isValidCodeVerifierFormat(verifier: unknown): boolean`

Validates that `verifier` is a string of 43–128 characters from the RFC 7636
unreserved set `[A-Za-z0-9._~-]`. Returns `false` for non-strings and `null`/`undefined`.

### `PkcePair` (type)

```typescript
interface PkcePair {
  /** Cryptographically random string (43 chars base64url); sent to the token endpoint. */
  codeVerifier: string;
  /** BASE64URL(SHA256(codeVerifier)); sent in the authorize request as code_challenge. */
  codeChallenge: string;
}
```

## Development

### Running unit tests

```bash
pnpm nx test server-pkce
```

## License

Apache-2.0
