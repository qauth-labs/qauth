/**
 * The reserved `admin:` scope prefix (ADR-019 Decision 7, issue #507).
 *
 * The admin API's scopes are `admin:read`, `admin:write` and `admin:security`.
 * Every scope that starts with `admin:` is reserved for them, so no client can
 * obtain a scope that reads like an admin grant through a path that grants it
 * without an operator: dynamic registration, Client ID Metadata Documents and
 * the developer API refuse it, a realm's dynamic registration allowlist cannot
 * hold it, and discovery never lists it.
 *
 * The prefix is matched without regard to the case of its ASCII letters. An
 * OAuth scope is case-sensitive (RFC 6749 §3.3), so `Admin:security` would
 * never satisfy `admin:security`, but a consent screen that shows it would
 * read as one. A scope is ASCII by its grammar (RFC 6749 §3.3), and the match
 * folds ASCII letters only, so it does not depend on a locale, as the CHECK's
 * `[aA][dD][mM][iI][nN]:` class does not either.
 *
 * The auth server's admin scopes (`helpers/admin-scopes.ts`), the environment
 * schema, the realms repository and the `realms` row's CHECK constraint all
 * apply this rule, so none of them accepts what another refuses.
 */

/** The prefix of every admin scope. */
export const RESERVED_ADMIN_SCOPE_PREFIX = 'admin:';

/**
 * `admin:` at the start, ASCII letters in any case. Without the `u` flag, `i`
 * folds no character outside ASCII onto an ASCII letter.
 */
const RESERVED_ADMIN_SCOPE = /^admin:/i;

/** Whether `scope` starts with the reserved `admin:` prefix, in any case. */
export function isReservedAdminScope(scope: string): boolean {
  return RESERVED_ADMIN_SCOPE.test(scope);
}

/** The entries of `scopes` that carry the reserved prefix, in their order. */
export function reservedAdminScopesIn(scopes: Iterable<string>): string[] {
  return [...scopes].filter(isReservedAdminScope);
}
