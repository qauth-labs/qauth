/**
 * Scope utilities. OAuth scopes are a space-delimited, case-sensitive set
 * (RFC 6749 §3.3). QAuth emits the `scope` claim as a single space-separated
 * string; introspection returns the same shape (RFC 7662 §2.2).
 */

/**
 * Parse a scope claim into a de-duplicated list. Accepts the wire string
 * form, an already-split array, or `undefined`/empty (→ no scopes). Splits on
 * any run of ASCII whitespace and discards empty segments.
 */
export function parseScopes(scope: string | string[] | undefined | null): string[] {
  if (scope == null) {
    return [];
  }
  const tokens = Array.isArray(scope) ? scope : scope.split(/\s+/);
  const seen = new Set<string>();
  for (const token of tokens) {
    const trimmed = token.trim();
    if (trimmed.length > 0) {
      seen.add(trimmed);
    }
  }
  return [...seen];
}

/**
 * Return the required scopes the granted set does not satisfy. Empty result
 * means the granted set is sufficient. Matching is exact and case-sensitive
 * per RFC 6749 §3.3 (no hierarchical/prefix semantics).
 */
export function missingScopes(granted: string[], required: string[]): string[] {
  if (required.length === 0) {
    return [];
  }
  const grantedSet = new Set(granted);
  return required.filter((scope) => !grantedSet.has(scope));
}

/** True when every required scope is present in the granted set. */
export function hasRequiredScopes(granted: string[], required: string[]): boolean {
  return missingScopes(granted, required).length === 0;
}

/**
 * Scopes that describe the client's relationship with the *authorization
 * server* rather than anything this resource will authorize, and which must
 * therefore never be advertised as a resource requirement (#284).
 *
 * MCP Authorization ("Scope Selection Strategy") names `offline_access`
 * explicitly: it only governs whether the AS issues a refresh token, so putting
 * it in a challenge or in PRM `scopes_supported` would tell a client to obtain
 * consent that has no bearing on the call it is trying to make.
 */
const NON_RESOURCE_SCOPES: ReadonlySet<string> = new Set(['offline_access']);

/**
 * Filter a scope list down to what is meaningful to advertise as a resource
 * requirement — see {@link NON_RESOURCE_SCOPES}.
 *
 * This is applied at the two *advertisement* surfaces only (the
 * `WWW-Authenticate` challenge and PRM `scopes_supported`), never to
 * enforcement: a host that configures such a scope still has it checked
 * against the token, so this cannot widen access.
 */
export function advertisableScopes(scopes: string[]): string[] {
  return scopes.filter((scope) => !NON_RESOURCE_SCOPES.has(scope));
}
