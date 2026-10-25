/**
 * The reserved `admin:` scope prefix (ADR-019 Decision 7, issue #507).
 *
 * The admin API's scopes are `admin:read`, `admin:write` and `admin:security`.
 * Every scope that starts with `admin:` is reserved for them, so no client can
 * obtain a scope that reads like an admin grant through a path that grants it
 * without an operator: dynamic registration and Client ID Metadata Documents
 * refuse it, a realm's dynamic registration allowlist cannot hold it, and
 * discovery never lists it.
 *
 * The prefix is matched without regard to case. An OAuth scope is
 * case-sensitive (RFC 6749 §3.3), so `Admin:security` would never satisfy
 * `admin:security`, but a consent screen that shows it would read as one.
 *
 * The auth server's admin scopes (`helpers/admin-scopes.ts`), the environment
 * schema, the realms repository and the `realms` row's CHECK constraint all
 * apply this rule, so none of them accepts what another refuses.
 */

/** The prefix of every admin scope. */
export const RESERVED_ADMIN_SCOPE_PREFIX = 'admin:';

/** Whether `scope` starts with the reserved `admin:` prefix, in any case. */
export function isReservedAdminScope(scope: string): boolean {
  return (
    scope.slice(0, RESERVED_ADMIN_SCOPE_PREFIX.length).toLowerCase() === RESERVED_ADMIN_SCOPE_PREFIX
  );
}

/** The entries of `scopes` that carry the reserved prefix, in their order. */
export function reservedAdminScopesIn(scopes: Iterable<string>): string[] {
  return [...scopes].filter(isReservedAdminScope);
}
