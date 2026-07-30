# JWT Plugin

Fastify plugin wrapping `@qauth-labs/server-jwt` for JWT signing, verification, and route protection.

## Usage

```typescript
import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';

await fastify.register(jwtPlugin, {
  privateKey: env.JWT_PRIVATE_KEY,
  publicKey: env.JWT_PUBLIC_KEY, // optional, derived from private key if omitted
  issuer: env.JWT_ISSUER,
  accessTokenLifespan: env.ACCESS_TOKEN_LIFESPAN,
  refreshTokenLifespan: env.REFRESH_TOKEN_LIFESPAN,
});

// Sign an access token. `sub` and `clientId` are required; `email` /
// `email_verified` are optional and omitted for client_credentials grants.
//
// Since ADR-002 (#230) the `users` row carries no email — resolve it from
// `user_attributes` in the trust order (wallet > oidc_* > self_reported) and
// omit both claims entirely when there is no verified address.
const token = await fastify.jwtUtils.signAccessToken({
  sub: user.id,
  clientId: client.clientId,
  ...(verifiedEmail ? { email: verifiedEmail, email_verified: true } : {}),
});

// Protect a route with requireJwt preHandler
fastify.get('/userinfo', {
  preHandler: [fastify.requireJwt],
  handler: async (request) => {
    // request.jwtPayload is guaranteed to be set
    return { sub: request.jwtPayload!.sub };
  },
});
```

## Options

| Option                 | Type     | Required | Description                                         |
| ---------------------- | -------- | -------- | --------------------------------------------------- |
| `privateKey`           | `string` | yes      | EdDSA private key in PEM format                     |
| `publicKey`            | `string` | no       | EdDSA public key in PEM format (derived if omitted) |
| `issuer`               | `string` | yes      | JWT `iss` claim                                     |
| `accessTokenLifespan`  | `number` | yes      | Access token TTL in seconds                         |
| `refreshTokenLifespan` | `number` | yes      | Refresh token TTL in seconds                        |

## Decorated Properties

### `fastify.jwtUtils`

- `signAccessToken(payload)` - Sign an EdDSA access token
- `verifyAccessToken(token)` - Verify and decode an access token
- `generateRefreshToken()` - Generate a refresh token pair `{ token, tokenHash }`
- `hashRefreshToken(token)` - Hash a refresh token
- `extractFromHeader(authHeader)` - Extract Bearer token from `Authorization` header
- `decodeTokenUnsafe(token)` - Decode without verification (expired tokens, debugging)
- `getAccessTokenLifespan()` - Get configured access token TTL
- `getRefreshTokenLifespan()` - Get configured refresh token TTL

### `fastify.requireJwt`

PreHandler that extracts and verifies the Bearer token from the `Authorization` header. On success, sets `request.jwtPayload` with the verified `JWTPayload`. Throws `JWTInvalidError` (401) on missing/malformed header, and lets `JWTExpiredError` (401) propagate for expired tokens.
