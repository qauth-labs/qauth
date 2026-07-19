/**
 * Framework-agnostic core of `mcp-guard`.
 *
 * `McpGuard` encapsulates everything that does not depend on a web framework:
 * config resolution, validator selection (JWT vs introspection), bearer
 * extraction, the RFC 9728 metadata document, and scope enforcement / step-up.
 * The Fastify plugin is a thin adapter over this; other frameworks can wrap it
 * identically.
 *
 * No-passthrough guarantee: this core only ever *validates* an inbound token
 * and returns its claims. It never returns or forwards the raw token to an
 * upstream call site, and audience binding is enforced by both validators, so
 * a token minted for another resource cannot be replayed here.
 */

import type { McpGuardConfig, ValidatedToken, ValidationMode } from '../types';
import { challengeForError } from './challenge';
import {
  InsufficientScopeError,
  McpGuardConfigError,
  type McpGuardError,
  MissingTokenError,
} from './errors';
import { IntrospectionValidator } from './introspection-validator';
import { JwtValidator } from './jwt-validator';
import {
  buildProtectedResourceMetadata,
  metadataPathForResource,
  metadataUrlForResource,
  type ProtectedResourceMetadata,
} from './metadata';
import { hasRequiredScopes, missingScopes } from './scope';

function stripTrailingSlash(value: string): string {
  return value.length > 1 && value.endsWith('/') ? value.slice(0, -1) : value;
}

/** A token validator: JWT-backed or introspection-backed. */
interface TokenValidator {
  validate(token: string): Promise<ValidatedToken>;
}

/**
 * Extract a bearer token from an `Authorization` header value (RFC 6750 §2.1).
 * The scheme match is case-insensitive; the credential is returned verbatim.
 * Returns `null` when the header is absent or not a non-empty Bearer.
 */
export function extractBearerToken(authorization: string | undefined | null): string | null {
  if (!authorization) {
    return null;
  }
  const match = /^Bearer[ ]+(.+)$/i.exec(authorization.trim());
  if (!match) {
    return null;
  }
  const token = match[1].trim();
  return token.length > 0 ? token : null;
}

export class McpGuard {
  /** Canonical resource identifier (`aud` tokens must carry). */
  readonly resource: string;
  /** Canonical AS issuer identifier. */
  readonly authorizationServer: string;
  /** Default scopes required for any access. */
  readonly requiredScopes: string[];
  readonly validationMode: ValidationMode;

  private readonly validator: TokenValidator;
  private readonly metadata: ProtectedResourceMetadata;

  constructor(config: McpGuardConfig) {
    if (!config.resource) {
      throw new McpGuardConfigError('`resource` is required');
    }
    if (!config.authorizationServer) {
      throw new McpGuardConfigError('`authorizationServer` is required');
    }

    this.resource = stripTrailingSlash(config.resource);
    this.authorizationServer = stripTrailingSlash(config.authorizationServer);
    this.requiredScopes = config.requiredScopes ?? [];
    this.validationMode = config.validationMode ?? 'jwt';

    this.validator = this.buildValidator(config);

    this.metadata = buildProtectedResourceMetadata({
      resource: this.resource,
      authorizationServer: this.authorizationServer,
      scopesSupported: this.requiredScopes.length > 0 ? this.requiredScopes : undefined,
    });
  }

  private buildValidator(config: McpGuardConfig): TokenValidator {
    if (this.validationMode === 'introspection') {
      if (!config.introspectionClient) {
        throw new McpGuardConfigError(
          'introspection mode requires `introspectionClient` credentials (RFC 7662 client auth)'
        );
      }
      return new IntrospectionValidator({
        endpoint: config.introspectionEndpoint ?? `${this.authorizationServer}/oauth/introspect`,
        audience: this.resource,
        client: config.introspectionClient,
        fetch: config.fetch,
      });
    }

    // Default: local JWT verification against the AS JWKS.
    return new JwtValidator({
      jwksUri: config.jwksUri ?? `${this.authorizationServer}/.well-known/jwks.json`,
      issuer: this.authorizationServer,
      audience: this.resource,
      allowedAlgorithms: config.allowedAlgorithms,
      cacheTtlMs: config.jwksCacheTtlMs,
      // #283 rollout switch. Default-off here mirrors the validator's own
      // default; a wrong `typ` is rejected either way.
      requireAccessTokenTyp: config.requireAccessTokenTyp === true,
      // The injectable FetchLike is API-compatible with what jose calls; the
      // cast is safe because we only use `(url, init) => Promise<Response-ish>`.
      fetch: config.fetch as never,
    });
  }

  /** The RFC 9728 PRM document for this resource. */
  getProtectedResourceMetadata(): ProtectedResourceMetadata {
    // Return a copy so callers cannot mutate cached state.
    return {
      ...this.metadata,
      authorization_servers: [...this.metadata.authorization_servers],
      ...(this.metadata.scopes_supported
        ? { scopes_supported: [...this.metadata.scopes_supported] }
        : {}),
    };
  }

  /** Well-known PRM path for this resource (RFC 9728 §3.1). */
  getMetadataPath(): string {
    return metadataPathForResource(this.resource);
  }

  /** Absolute PRM URL advertised in the `resource_metadata` challenge param. */
  getMetadataUrl(): string {
    return metadataUrlForResource(this.resource);
  }

  /**
   * Build the `WWW-Authenticate` header value for a guard error, with the
   * `resource_metadata` pointer baked in. The Fastify adapter calls this to
   * set the header on 401 / 403 responses.
   */
  challengeHeader(error: McpGuardError): string {
    return challengeForError(error, this.getMetadataUrl());
  }

  /**
   * Authenticate and authorize a request from its `Authorization` header.
   *
   * @param authorization the raw header value.
   * @param scopes additional per-operation scopes to require on top of the
   *   guard's default `requiredScopes` (the step-up surface).
   * @returns the validated, audience-bound token claims.
   * @throws {MissingTokenError} when no bearer is present (→ 401, bare challenge).
   * @throws {InvalidTokenError} when validation fails (→ 401 `invalid_token`).
   * @throws {InsufficientScopeError} when scopes are insufficient
   *   (→ 403 `insufficient_scope` step-up challenge).
   */
  async authenticate(
    authorization: string | undefined | null,
    scopes: string[] = []
  ): Promise<ValidatedToken> {
    const token = extractBearerToken(authorization);
    if (!token) {
      throw new MissingTokenError();
    }
    const validated = await this.validator.validate(token);
    this.assertScopes(validated, scopes);
    return validated;
  }

  /**
   * Assert that a previously validated token satisfies a scope set. Use this
   * for incremental, mid-handler step-up checks (e.g. a privileged tool call)
   * where the token was already validated by {@link authenticate}.
   *
   * @throws {InsufficientScopeError} listing every scope the request needs.
   */
  assertScopes(token: ValidatedToken, scopes: string[] = []): void {
    // The challenge advertises the FULL required set (defaults + step-up) so
    // the client can request a single, sufficient authorization in one round.
    const required = dedupe([...this.requiredScopes, ...scopes]);
    if (hasRequiredScopes(token.scopes, required)) {
      return;
    }
    throw new InsufficientScopeError(required, missingScopes(token.scopes, required));
  }
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}
