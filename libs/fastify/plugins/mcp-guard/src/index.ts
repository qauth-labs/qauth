/**
 * `@qauth-labs/mcp-guard` — the resource-server-side SDK for wiring an MCP
 * server to a self-hosted QAuth OAuth 2.1 authorization server.
 *
 * Two entry points:
 *
 * - {@link mcpGuardPlugin} — a Fastify 5 plugin (default export) that serves
 *   RFC 9728 metadata and decorates the instance with `requireBearer` /
 *   `requireScopes` preHandlers.
 * - {@link McpGuard} — the framework-agnostic core, for non-Fastify hosts.
 *
 * See the package README and `examples/memory-mcp` for usage.
 */

// Fastify adapter (default + named).
export {
  default,
  mcpGuardPlugin,
  type McpGuardPluginOptions,
  sendBearerChallenge,
} from './lib/fastify-plugin-mcp-guard';

// Framework-agnostic core.
export { extractBearerToken, McpGuard } from './lib/core';

// Errors (for `instanceof` checks and custom error handling).
export {
  type BearerErrorCode,
  InsufficientScopeError,
  IntrospectionError,
  InvalidTokenError,
  McpGuardConfigError,
  McpGuardError,
  MissingTokenError,
} from './lib/errors';

// RFC 9728 metadata helpers.
export {
  buildProtectedResourceMetadata,
  metadataPathForResource,
  metadataUrlForResource,
  PRM_WELL_KNOWN_PREFIX,
  type ProtectedResourceMetadata,
} from './lib/metadata';

// Challenge construction (RFC 6750 §3.1).
export { buildWwwAuthenticate, type ChallengeParams } from './lib/challenge';

// Scope helpers.
export { hasRequiredScopes, missingScopes, parseScopes } from './lib/scope';

// Validators (advanced / custom wiring).
export {
  IntrospectionValidator,
  type IntrospectionValidatorOptions,
} from './lib/introspection-validator';
export { JwtValidator, type JwtValidatorOptions } from './lib/jwt-validator';

// Public config & result types.
export type {
  FetchLike,
  IntrospectionClientCredentials,
  McpGuardConfig,
  ValidatedToken,
  ValidationMode,
} from './types';
