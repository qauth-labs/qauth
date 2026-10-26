# JWT Plugin

Fastify plugin wrapping `@qauth-labs/server-jwt` for JWT signing, verification, and route protection.
It also serves the JWKS, and can sign hybrid ML-DSA-65 + Ed25519 tokens and accept DPoP-bound tokens.

## Usage

```typescript
import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';

await fastify.register(jwtPlugin, {
  privateKey: env.JWT_PRIVATE_KEY,
  publicKey: env.JWT_PUBLIC_KEY, // set it: registration fails without it (see Keys below)
  issuer: env.JWT_ISSUER,
  accessTokenLifespan: env.ACCESS_TOKEN_LIFESPAN,
  refreshTokenLifespan: env.REFRESH_TOKEN_LIFESPAN,
});

// Sign an access token. `sub` and `clientId` are required; `email` /
// `email_verified` are optional. Pass them only when the grant includes the
// `email` scope, and never for client_credentials grants.
//
// Since ADR-002 (#230) the `users` row carries no email — resolve it from
// `user_attributes` in the trust order (wallet > oidc_* > self_reported) and
// omit both claims entirely when there is no verified address.
const token = await fastify.jwtUtils.signAccessToken({
  sub: user.id,
  clientId: client.clientId,
  ...(emailScopeGranted && verifiedEmail ? { email: verifiedEmail, email_verified: true } : {}),
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

The auth-server's source for each option is named in parentheses.

| Option                       | Type                            | Required         | Description                                                                                       |
| ---------------------------- | ------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------- |
| `privateKey`                 | `string`                        | yes              | Ed25519 private key, PKCS#8 PEM (`JWT_PRIVATE_KEY`)                                               |
| `publicKey`                  | `string`                        | no, but set it   | Ed25519 public key, SPKI PEM (`JWT_PUBLIC_KEY`); registration fails without it                    |
| `issuer`                     | `string`                        | yes              | JWT `iss` claim (`JWT_ISSUER`)                                                                    |
| `accessTokenLifespan`        | `number`                        | yes              | Access and ID token TTL in seconds (`ACCESS_TOKEN_LIFESPAN`)                                      |
| `refreshTokenLifespan`       | `number`                        | yes              | Refresh token TTL in seconds (`REFRESH_TOKEN_LIFESPAN`)                                           |
| `keyId`                      | `string`                        | no               | `kid` of the Ed25519 key in the JWKS and in hybrid token headers (its RFC 7638 thumbprint)        |
| `rs256PrivateKey`            | `string`                        | no               | RS256 private key, PKCS#8 PEM; ID tokens are then signed with RS256 (`JWT_RS256_PRIVATE_KEY`)     |
| `rs256PublicKey`             | `string`                        | no               | RS256 public key, SPKI PEM; derived from `rs256PrivateKey` when omitted (`JWT_RS256_PUBLIC_KEY`)  |
| `rs256KeyId`                 | `string`                        | no               | `kid` of the RS256 key in the JWKS and ID token header (`JWT_RS256_KID`, else its thumbprint)     |
| `requireAccessTokenTyp`      | `boolean`                       | no               | Also refuse access tokens without `typ: at+jwt` (default `false`; not set by the auth-server)     |
| `mlDsaSeed`                  | `string`                        | no               | ML-DSA-65 seed, base64url, 32 bytes; publishes an `AKP` JWK (`JWT_MLDSA_PRIVATE_KEY`)             |
| `mlDsaKeyId`                 | `string`                        | no               | `kid` of the ML-DSA-65 key, stamped as `pqc_kid` (`JWT_MLDSA_KID`)                                |
| `hybridSigningEnabled`       | `boolean`                       | no               | Issue hybrid access tokens; needs `mlDsaSeed` (`HYBRID_SIGNING_ENABLED`, default `false`)         |
| `enabledSignatureAlgorithms` | `readonly SignatureAlgorithm[]` | with `mlDsaSeed` | Enabled signature algorithms (`SIGNING_ALGORITHM_MODE`)                                           |
| `retiredKeys`                | `{ publicKey, keyId }[]`        | no               | Retired Ed25519 public keys, SPKI PEM, kept in the JWKS under their own `kid`                     |
| `retiredMlDsaPublicKeys`     | `{ publicKey, keyId }[]`        | no               | Retired ML-DSA-65 public keys, base64url, kept in the JWKS; read only with `mlDsaSeed`            |
| `isTokenRevoked`             | function                        | no               | `(jti) => boolean`, sync or async; `requireJwt` refuses a revoked token (the revocation denylist) |
| `verifyDpopProof`            | function                        | no               | `(request, token, claims) => Promise<void>`; turns on the `DPoP` scheme (set when `DPOP_ENABLED`) |

## Keys and signing modes

- Access tokens are always signed with the Ed25519 key.
- With `rs256PrivateKey`, ID tokens are signed with RS256 and carry `rs256KeyId` as `kid`. Without it, they use the Ed25519 key.
- With `hybridSigningEnabled`, `signHybridAccessToken` adds a detached ML-DSA-65 signature. Registration fails without `mlDsaSeed`.
- `mlDsaSeed` needs `enabledSignatureAlgorithms` with `ML-DSA-65` in it, or registration fails.
- With `mlDsaSeed` and hybrid signing off, only the ML-DSA-65 public key is kept, for the JWKS.
- `getJwks()` lists the Ed25519 key, the RS256 key, the retired Ed25519 keys, then the ML-DSA-65 keys. It throws when two keys share a `kid`.
- Registration fails without `publicKey`: the plugin cannot export the public half of an imported Ed25519 private key. See [the EdDSA public key](https://docs.qauth.dev/operate/keys/#the-eddsa-public-key-is-not-actually-optional-359).

The auth-server passes the ML-DSA-65 seed only when `HYBRID_SIGNING_ENABLED` is on. At boot it also imports the `JWT_*` keys into the default realm's encrypted key store. Tokens are still signed with the variables until token signing moves onto the store (#491). See [Keys](https://docs.qauth.dev/operate/keys/) and the [PQC verifier guide](https://docs.qauth.dev/operate/pqc-verifier-guide/).

## DPoP

With `verifyDpopProof` set, `requireJwt` also accepts `Authorization: DPoP <token>` (RFC 9449). The token must carry `cnf.jkt`, and `verifyDpopProof` must accept the request's DPoP proof. The auth-server sets it when `DPOP_ENABLED` is on (default `false`). A DPoP-bound token sent as a Bearer token is refused either way. A route that reads a Bearer token by hand calls the exported `refuseBoundTokenAsBearer(claims)`.

## Decorated Properties

### `fastify.jwtUtils`

- `signAccessToken(payload)` - Sign an EdDSA access token; `expiresInOverride` can shorten its lifetime
- `signIdToken(payload)` - Sign an ID token with RS256 when configured, otherwise EdDSA
- `isHybridSigningEnabled()` - Whether hybrid issuance is on
- `signHybridAccessToken(payload)` - Sign a hybrid access token; throws when hybrid signing is off
- `verifyHybridAccessToken(hybrid, options)` - Verify both signatures; throws `JWTInvalidError` without `mlDsaSeed`
- `verifyAccessToken(token, options?)` - Verify and decode an access token; `options` takes `issuer` and `audience`
- `generateRefreshToken()` - Generate a refresh token pair `{ token, tokenHash }`
- `hashRefreshToken(token)` - Hash a refresh token
- `extractFromHeader(authHeader)` - Extract Bearer token from `Authorization` header
- `extractCredentialFromHeader(authHeader)` - Extract `{ scheme, token }`; `DPoP` only with `verifyDpopProof`
- `decodeTokenUnsafe(token)` - Decode without verification (expired tokens, debugging)
- `getAccessTokenLifespan()` - Get configured access token TTL
- `getRefreshTokenLifespan()` - Get configured refresh token TTL
- `getIssuer()` - Get the configured issuer
- `getIdTokenSigningAlgValuesSupported()` - `['RS256', 'EdDSA']` with an RS256 key, otherwise `['EdDSA']`
- `getJwks()` - Build the JWKS document for `/.well-known/jwks.json`

### `fastify.requireJwt`

PreHandler that extracts and verifies the access token from the `Authorization` header. It requires the configured `issuer`, then runs `isTokenRevoked` when set. A `DPoP` credential goes to `verifyDpopProof`; a Bearer token with `cnf` is refused. On success, sets `request.jwtPayload` with the verified `JWTPayload`. Throws `JWTInvalidError` (401) on a missing or malformed header, a revoked token, or a binding failure. It lets `JWTExpiredError` (401) and errors from `verifyDpopProof` propagate.
