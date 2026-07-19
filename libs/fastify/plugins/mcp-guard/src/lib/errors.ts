/**
 * Error model for `mcp-guard`.
 *
 * These map directly to the Bearer-token error responses defined by
 * RFC 6750 §3.1 and refined by the MCP Authorization profile (2025-11-25):
 *
 * - `MissingTokenError`      → 401, no `error` code (RFC 6750: a bare
 *   `WWW-Authenticate: Bearer` challenge when no credentials were sent).
 * - `InvalidTokenError`      → 401, `error="invalid_token"` (malformed,
 *   expired, bad signature, wrong issuer, or wrong audience).
 * - `InsufficientScopeError` → 403, `error="insufficient_scope"` with the
 *   set of scopes that would satisfy the request (step-up challenge).
 *
 * The classes are intentionally self-contained (no dependency on the QAuth
 * AS error model) so the SDK stays portable for external MCP-server authors.
 */

/** Discriminant for the Bearer challenge an error should produce. */
export type BearerErrorCode = 'invalid_token' | 'insufficient_scope';

/** Base class for all guard rejections that should surface a Bearer challenge. */
export abstract class McpGuardError extends Error {
  /** HTTP status the RS should return. */
  abstract readonly statusCode: 401 | 403;
  /**
   * RFC 6750 `error` parameter for the `WWW-Authenticate` header, or
   * `undefined` for a credential-absent challenge (no `error` per §3.1).
   */
  abstract readonly bearerError?: BearerErrorCode;

  protected constructor(message: string) {
    super(message);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, new.target);
    }
  }
}

/**
 * No bearer credentials were presented. RFC 6750 §3: respond 401 with a bare
 * `WWW-Authenticate: Bearer` challenge (no `error` code), pointing the client
 * at the resource metadata so it can discover the AS and authenticate.
 *
 * The error carries the scopes the attempted route requires so the challenge
 * can advertise them (#284). MCP Authorization ("Scope Selection Strategy")
 * says the RS SHOULD do this, letting a client authorize correctly on its
 * first attempt instead of fetching the PRM document and guessing.
 */
export class MissingTokenError extends McpGuardError {
  readonly statusCode = 401 as const;
  readonly bearerError = undefined;
  /**
   * Scopes the attempted operation requires (guard defaults + any per-route
   * step-up), for the `scope` challenge parameter. Empty when the route
   * requires none — the challenge then omits `scope` entirely rather than
   * emitting a meaningless `scope=""`.
   */
  readonly requiredScopes: string[];

  constructor(requiredScopes: string[] = [], message = 'No bearer token presented') {
    super(message);
    this.requiredScopes = requiredScopes;
  }
}

/**
 * The presented token is unusable: malformed, expired, bad signature, wrong
 * issuer, or — critically for no-passthrough — not audience-bound to this
 * resource (RFC 8707). RFC 6750 §3.1: 401 `error="invalid_token"`.
 *
 * The human-readable `reason` is suitable for the optional
 * `error_description` challenge parameter and for logs; it must never echo
 * the token itself.
 */
export class InvalidTokenError extends McpGuardError {
  readonly statusCode = 401 as const;
  readonly bearerError = 'invalid_token' as const;
  /** Short reason for `error_description` / structured logs. */
  readonly reason: string;

  constructor(reason: string) {
    super(`Invalid bearer token: ${reason}`);
    this.reason = reason;
  }
}

/**
 * The token is valid but lacks one or more required scopes. RFC 6750 §3.1:
 * 403 `error="insufficient_scope"`, advertising the scopes that would satisfy
 * the request — the MCP 2025-11-25 incremental-consent step-up signal.
 */
export class InsufficientScopeError extends McpGuardError {
  readonly statusCode = 403 as const;
  readonly bearerError = 'insufficient_scope' as const;
  /** Full set of scopes the request requires (for the `scope` challenge param). */
  readonly requiredScopes: string[];
  /** Subset of {@link requiredScopes} the token did not satisfy. */
  readonly missingScopes: string[];

  constructor(requiredScopes: string[], missingScopes: string[]) {
    super(`Insufficient scope; missing: ${missingScopes.join(' ')}`);
    this.requiredScopes = requiredScopes;
    this.missingScopes = missingScopes;
  }
}

/**
 * Configuration error raised at setup time (e.g. introspection mode without
 * client credentials). Not a Bearer challenge — it is a programming error in
 * the host application and should surface as a 500 / startup failure.
 */
export class McpGuardConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'McpGuardConfigError';
    Object.setPrototypeOf(this, McpGuardConfigError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, McpGuardConfigError);
    }
  }
}

/**
 * An operational failure while validating a token *that is not the token's
 * fault*: the authorization server was unreachable, returned a non-2xx (e.g.
 * because THIS resource server's introspection credentials are misconfigured),
 * or sent a malformed response.
 *
 * Crucially this is **not** an {@link McpGuardError}, so it does not produce a
 * 401 `invalid_token` Bearer challenge. Blaming the client's token for an
 * RS/AS-side fault is wrong HTTP semantics (RFC 6750 §3.1) and can drive
 * clients into futile token-refresh loops (OWASP A10, mishandling exceptional
 * conditions). It propagates to the host's error handler and should surface as
 * a 5xx so operators see — and clients are told — that the failure is
 * server-side, not a bad credential.
 *
 * The message is short and non-sensitive; the token is never echoed.
 */
export class IntrospectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IntrospectionError';
    Object.setPrototypeOf(this, IntrospectionError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, IntrospectionError);
    }
  }
}
