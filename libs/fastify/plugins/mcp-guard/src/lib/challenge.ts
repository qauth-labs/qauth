/**
 * `WWW-Authenticate: Bearer` challenge construction.
 *
 * RFC 6750 §3 defines the challenge sent with a 401/403 to a Bearer-protected
 * resource. RFC 9728 §5.1 adds the `resource_metadata` parameter so the client
 * can discover the AS. Under MCP 2025-11-25 this header is OPTIONAL when the
 * resource exposes the `.well-known` PRM document, but emitting it is the
 * fastest path for a client and is recommended — `mcp-guard` always emits it.
 */

import type { McpGuardError } from './errors';
import { advertisableScopes } from './scope';

export interface ChallengeParams {
  /** Absolute URL of the RFC 9728 PRM document (`resource_metadata`). */
  resourceMetadataUrl: string;
  /** RFC 6750 `error` code; omit for a credential-absent challenge. */
  error?: string;
  /** Human-readable `error_description` (never include the token). */
  errorDescription?: string;
  /** Space-separated scopes that would satisfy the request (`scope`). */
  scope?: string[];
}

/**
 * Escape a value for an HTTP `auth-param` quoted-string (RFC 7235 / RFC 9110).
 * Only `"` and `\` are special inside a quoted-string; the values we emit
 * (URLs, fixed error codes, scope tokens) contain neither in practice, but we
 * escape defensively to keep the header well-formed and uninjectable.
 */
function quote(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * Build the `WWW-Authenticate` header value. Parameter order follows common
 * practice (`error` first, then descriptors); RFC 6750 does not mandate order.
 */
export function buildWwwAuthenticate(params: ChallengeParams): string {
  const parts: string[] = [];
  if (params.error) {
    parts.push(`error=${quote(params.error)}`);
  }
  if (params.errorDescription) {
    parts.push(`error_description=${quote(params.errorDescription)}`);
  }
  if (params.scope && params.scope.length > 0) {
    parts.push(`scope=${quote(params.scope.join(' '))}`);
  }
  parts.push(`resource_metadata=${quote(params.resourceMetadataUrl)}`);
  return `Bearer ${parts.join(', ')}`;
}

/**
 * Derive the `WWW-Authenticate` value for a guard error. Centralises the
 * RFC 6750 §3.1 mapping so the Fastify layer and any other adapter stay
 * consistent. `InsufficientScopeError` and `MissingTokenError` both contribute
 * the `scope` challenge (see below).
 */
export function challengeForError(error: McpGuardError, resourceMetadataUrl: string): string {
  const params: ChallengeParams = { resourceMetadataUrl };
  if (error.bearerError) {
    params.error = error.bearerError;
  }
  // Only attach a description for token errors; a bare 401 (missing token)
  // carries no `error`, and we avoid leaking validator internals beyond the
  // short, non-sensitive reason already on the error.
  if (error.bearerError === 'invalid_token' && 'reason' in error) {
    params.errorDescription = (error as { reason: string }).reason;
  }
  // `scope` is advertised on the 403 step-up challenge and — since #284 — on
  // the credential-absent 401 as well: MCP Authorization ("Scope Selection
  // Strategy") says the RS SHOULD tell an unauthenticated client what the
  // operation needs, so it can authorize in one round instead of fetching PRM
  // and guessing. The 401 still carries NO `error` parameter: RFC 6750 §3.1
  // omits it when no credentials were presented, and only `scope` is added.
  //
  // `invalid_token` is deliberately excluded — the client already holds a
  // token, so the remedy is re-authentication, not a wider scope set, and
  // repeating the requirement there would invite pointless re-consent loops.
  if (error.bearerError !== 'invalid_token' && 'requiredScopes' in error) {
    // `buildWwwAuthenticate` omits an empty `scope`, so a route with no
    // configured scopes yields a bare challenge rather than `scope=""`.
    params.scope = advertisableScopes((error as { requiredScopes: string[] }).requiredScopes);
  }
  return buildWwwAuthenticate(params);
}
