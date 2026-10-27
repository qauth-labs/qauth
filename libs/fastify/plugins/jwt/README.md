# JWT Plugin

Fastify plugin wrapping `@qauth-labs/server-jwt` for JWT signing, verification, and route protection.
It also serves each realm's JWKS, and can sign hybrid ML-DSA-65 + Ed25519 tokens and accept DPoP-bound tokens.

The plugin holds no key (ADR-019 Decision 9). Every token is signed through the signer for its
realm, which sets `iss` from the realm row and `kid` from the realm's active key, and every token
is verified with the public keys the signer lists for the realm. A realm's tokens therefore verify
only in that realm.

## Usage

```typescript
import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';

await fastify.register(jwtPlugin, {
  signer: fastify.signer, // @qauth-labs/fastify-plugin-signer
  requestRealm: (request) => ({ id: request.realm.id, issuer: request.realm.issuer }),
  accessTokenLifespan: env.ACCESS_TOKEN_LIFESPAN,
  refreshTokenLifespan: env.REFRESH_TOKEN_LIFESPAN,
});

// Sign an access token for a realm. `sub` and `clientId` are required;
// `email` / `email_verified` are optional. Pass them only when the grant
// includes the `email` scope, and never for client_credentials grants.
//
// Since ADR-002 (#230) the `users` row carries no email — resolve it from
// `user_attributes` in the trust order (wallet > oidc_* > self_reported) and
// omit both claims entirely when there is no verified address.
const token = await fastify.jwtUtils.signAccessToken(realm, {
  sub: user.id,
  clientId: client.clientId,
  ...(emailScopeGranted && verifiedEmail ? { email: verifiedEmail, email_verified: true } : {}),
});

// Protect a route with requireJwt preHandler: the token must be one of the
// request realm's.
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

| Option                       | Type                            | Required | Description                                                                                       |
| ---------------------------- | ------------------------------- | -------- | ------------------------------------------------------------------------------------------------- |
| `signer`                     | `TokenSigner`                   | yes      | Signs every token and lists each realm's verification keys and JWKS (`fastify.signer`)            |
| `requestRealm`               | `(request) => TokenRealm`       | yes      | The realm (`id`, `issuer`) a request belongs to, for `requireJwt` (`request.realm`)               |
| `accessTokenLifespan`        | `number`                        | yes      | Access and ID token TTL in seconds (`ACCESS_TOKEN_LIFESPAN`)                                      |
| `refreshTokenLifespan`       | `number`                        | yes      | Refresh token TTL in seconds (`REFRESH_TOKEN_LIFESPAN`)                                           |
| `requireAccessTokenTyp`      | `boolean`                       | no       | Also refuse access tokens without `typ: at+jwt` (default `false`; not set by the auth-server)     |
| `hybridSigningEnabled`       | `boolean`                       | no       | Issue hybrid access tokens with the realm's pair (`HYBRID_SIGNING_ENABLED`, default `false`)      |
| `enabledSignatureAlgorithms` | `readonly SignatureAlgorithm[]` | no       | Enabled signature algorithms (`SIGNING_ALGORITHM_MODE`); ML-DSA-65 in it for hybrid signing       |
| `isTokenRevoked`             | function                        | no       | `(jti) => boolean`, sync or async; `requireJwt` refuses a revoked token (the revocation denylist) |
| `verifyDpopProof`            | function                        | no       | `(request, token, claims) => Promise<void>`; turns on the `DPoP` scheme (set when `DPOP_ENABLED`) |

## Keys and signing modes

- The realm's keys live in its encrypted key store; the plugin is given none. The auth-server's
  key boot step imports the `JWT_*` variables into the default realm's store, and a fresh realm
  gets generated keys. See [Keys](https://docs.qauth.dev/operate/keys/).
- Access tokens are always signed with the realm's active Ed25519 key, and carry its `kid`.
- A realm with an active RS256 key signs its ID tokens with RS256, under that key's `kid`. Without
  one, they use the Ed25519 key.
- With `hybridSigningEnabled`, `signHybridAccessToken` adds a detached ML-DSA-65 signature with
  the realm's hybrid pair, naming the ML-DSA-65 key in `pqc_kid`. Registration fails unless
  `enabledSignatureAlgorithms` has `ML-DSA-65` in it.
- Verification picks the realm's key by the token's `kid` among its `active` and still-published
  `retired` keys. A token with no `kid`, from before tokens named their key, is tried against each
  of the realm's Ed25519 keys.
- `getJwks(realm)` is the realm's JWKS as the signer serves it.
- On a process without the `signer` role (#495), the auth-server's `signer` refuses every signature with 503 `temporarily_unavailable`, and reads each realm's verification keys and JWKS from its published public keys, without a KEK. The plugin passes the 503 on, and still verifies the realm's tokens.

See [Keys](https://docs.qauth.dev/operate/keys/) and the
[PQC verifier guide](https://docs.qauth.dev/operate/pqc-verifier-guide/).

## DPoP

With `verifyDpopProof` set, `requireJwt` also accepts `Authorization: DPoP <token>` (RFC 9449). The token must carry `cnf.jkt`, and `verifyDpopProof` must accept the request's DPoP proof. The auth-server sets it when `DPOP_ENABLED` is on (default `false`). A DPoP-bound token sent as a Bearer token is refused either way. A route that reads a Bearer token by hand calls the exported `refuseBoundTokenAsBearer(claims)`.

## Decorated Properties

### `fastify.jwtUtils`

- `signAccessToken(realm, payload)` - Sign an EdDSA access token; `expiresInOverride` can shorten its lifetime
- `signIdToken(realm, payload)` - Sign an ID token with RS256 when the realm has an RS256 key, otherwise EdDSA
- `isHybridSigningEnabled()` - Whether hybrid issuance is on
- `signHybridAccessToken(realm, payload)` - Sign a hybrid access token; throws when hybrid signing is off
- `verifyHybridAccessToken(realm, hybrid, options)` - Verify both signatures; throws `JWTInvalidError` without ML-DSA-65 enabled
- `verifyAccessToken(realm, token, options?)` - Verify and decode an access token of the realm, under its issuer; `options` takes `audience`
- `generateRefreshToken()` - Generate a refresh token pair `{ token, tokenHash }`
- `hashRefreshToken(token)` - Hash a refresh token
- `extractFromHeader(authHeader)` - Extract Bearer token from `Authorization` header
- `extractCredentialFromHeader(authHeader)` - Extract `{ scheme, token }`; `DPoP` only with `verifyDpopProof`
- `decodeTokenUnsafe(token)` - Decode without verification (expired tokens, debugging)
- `getAccessTokenLifespan()` - Get configured access token TTL
- `getRefreshTokenLifespan()` - Get configured refresh token TTL
- `getIdTokenSigningAlgValuesSupported(realm)` - `['RS256', 'EdDSA']` when the realm has an RS256 key, otherwise `['EdDSA']`
- `getJwks(realm)` - The realm's JWKS document for `/.well-known/jwks.json`

### `fastify.requireJwt`

PreHandler that extracts and verifies the access token from the `Authorization` header, with the keys of the request's realm. It requires that realm's issuer, then runs `isTokenRevoked` when set. A `DPoP` credential goes to `verifyDpopProof`; a Bearer token with `cnf` is refused. On success, sets `request.jwtPayload` with the verified `JWTPayload`. Throws `MissingAccessTokenError` (401) when the request carries no credential (no `Authorization` header, no token in it, or a scheme the plugin does not take), and `JWTInvalidError` (401) for a token that does not verify, is revoked, or fails its binding. It lets `JWTExpiredError` (401) and errors from `verifyDpopProof` propagate. `verifyRequestAccessToken` throws the same.

### `fastify.verifyRequestAccessToken(request, policy?)`

The checks `requireJwt` makes, returning the verified `JWTPayload` instead of setting `request.jwtPayload`. A route that needs a stricter check passes an `AccessTokenCheckPolicy`:

- `acceptIssuer(issuer, request)` replaces the comparison with the issuer of the request's realm. It runs after the signature check with that realm's keys, and a token with no `iss` is refused before it is called. Since the keys are always the request realm's, it can narrow which tokens pass, never admit another realm's.
- `requireTyp: true` requires the RFC 9068 `typ: at+jwt` header whatever `requireAccessTokenTyp` says. It can only tighten that setting.

The signature, expiry, revocation and DPoP checks always run. The auth server's API family guards (`requireFamilyToken`) are built on it.
