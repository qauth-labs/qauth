/**
 * `@qauth-labs/resource-guard` — the resource-server-side SDK for wiring an
 * MCP server (or any OAuth 2.1 resource server) to a self-hosted QAuth
 * authorization server.
 *
 * Two entry points:
 *
 * - this one, the framework-agnostic core: {@link ResourceGuard}, the
 *   validators, the RFC 9728 metadata and RFC 6750 challenge helpers. It never
 *   imports Fastify.
 * - `@qauth-labs/resource-guard/fastify` — the Fastify 5 plugin, which serves
 *   RFC 9728 metadata and decorates the instance with `requireBearer` /
 *   `requireScopes` preHandlers. `fastify` is an optional peer dependency,
 *   needed only for that entry.
 *
 * See the package README and `examples/memory-mcp` for usage.
 */

// Framework-agnostic core.
export { extractBearerToken, ResourceGuard } from './lib/core.js';

// Errors (for `instanceof` checks and custom error handling).
export {
  type BearerErrorCode,
  InsufficientScopeError,
  IntrospectionError,
  InvalidTokenError,
  MissingTokenError,
  ResourceGuardConfigError,
  ResourceGuardError,
} from './lib/errors.js';

// RFC 9728 metadata helpers.
export {
  buildProtectedResourceMetadata,
  metadataPathForResource,
  metadataUrlForResource,
  PRM_WELL_KNOWN_PREFIX,
  type ProtectedResourceMetadata,
} from './lib/metadata.js';

// Challenge construction (RFC 6750 §3.1).
export { buildWwwAuthenticate, type ChallengeParams } from './lib/challenge.js';

// Scope helpers.
export { hasRequiredScopes, missingScopes, parseScopes } from './lib/scope.js';

// Validators (advanced / custom wiring).
export {
  IntrospectionValidator,
  type IntrospectionValidatorOptions,
} from './lib/introspection-validator.js';
export { JwtValidator, type JwtValidatorOptions } from './lib/jwt-validator.js';

// Public config & result types.
export type {
  FetchLike,
  IntrospectionClientCredentials,
  ResourceGuardConfig,
  ValidatedToken,
  ValidationMode,
} from './types.js';
