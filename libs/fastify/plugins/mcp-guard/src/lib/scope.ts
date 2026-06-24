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
