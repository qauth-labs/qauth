# fastify-plugin-pkce

Fastify plugin wrapping `@qauth/server-pkce` for OAuth 2.1 PKCE operations.

## Usage

```typescript
import { pkcePlugin } from '@qauth/fastify-plugin-pkce';

await fastify.register(pkcePlugin);

// Verify code challenge at token endpoint
const isValid = fastify.pkceUtils.verifyCodeChallenge(codeVerifier, storedChallenge);

// Generate PKCE pair (for testing/client utilities)
const { codeVerifier, codeChallenge } = fastify.pkceUtils.generatePkcePair();
```

## Decorated Properties

- `fastify.pkceUtils.generateCodeVerifier()` - Generate random code verifier
- `fastify.pkceUtils.generateCodeChallenge(verifier)` - Compute S256 challenge
- `fastify.pkceUtils.generatePkcePair()` - Generate verifier + challenge pair
- `fastify.pkceUtils.isValidCodeVerifierFormat(verifier)` - Validate format
- `fastify.pkceUtils.verifyCodeChallenge(verifier, challenge)` - Verify PKCE (timing-safe)
