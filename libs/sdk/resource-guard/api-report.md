# API report: `@qauth-labs/resource-guard`

Every name each entry point exports. `src/api-report.test.ts` compares this
list with the entry points and fails when they differ, so a change to the
public API always changes this file in the same pull request. A name marked
`(type)` exists only for TypeScript.

## `@qauth-labs/resource-guard`

The framework-agnostic core (`src/index.ts`). It never imports Fastify.

- `BearerErrorCode` (type)
- `buildProtectedResourceMetadata`
- `buildWwwAuthenticate`
- `ChallengeParams` (type)
- `extractBearerToken`
- `FetchLike` (type)
- `hasRequiredScopes`
- `InsufficientScopeError`
- `IntrospectionClientCredentials` (type)
- `IntrospectionError`
- `IntrospectionValidator`
- `IntrospectionValidatorOptions` (type)
- `InvalidTokenError`
- `JwtValidator`
- `JwtValidatorOptions` (type)
- `metadataPathForResource`
- `metadataUrlForResource`
- `missingScopes`
- `MissingTokenError`
- `parseScopes`
- `PRM_WELL_KNOWN_PREFIX`
- `ProtectedResourceMetadata` (type)
- `ResourceGuard`
- `ResourceGuardConfig` (type)
- `ResourceGuardConfigError`
- `ResourceGuardError`
- `ValidatedToken` (type)
- `ValidationMode` (type)

## `@qauth-labs/resource-guard/fastify`

The Fastify 5 plugin (`src/fastify.ts`). It needs `fastify`, an optional peer
dependency of the package.

- `default`
- `ResourceGuardPluginOptions` (type)
- `resourceGuardPlugin`
- `sendBearerChallenge`
