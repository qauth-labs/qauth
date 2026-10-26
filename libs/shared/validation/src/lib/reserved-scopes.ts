/**
 * The reserved `qauth:` scope namespace (ADR-019 Decision 7, issue #507).
 *
 * QAuth's own scopes live in the `qauth:` namespace: the admin API's are
 * `qauth:admin:read`, `qauth:admin:write` and `qauth:admin:security`. Every
 * scope in that namespace is QAuth's, so no client can obtain one through a
 * path that grants scopes without an operator. A realm's dynamic registration
 * allowlist cannot hold one, so dynamic registration drops one like any scope
 * outside the allowlist and the developer API refuses one the same way; a
 * Client ID Metadata Document's `scope` is never stored, so one there is
 * ignored; and discovery never lists one. Other servers' scopes that merely
 * look administrative, such as GitHub's `admin:org`, are ordinary scopes.
 *
 * The namespace is matched without regard to the case of its ASCII letters.
 * An OAuth scope is case-sensitive (RFC 6749 §3.3), so `QAuth:admin:security`
 * would never satisfy `qauth:admin:security`, but a consent screen that shows
 * it would read as one. A scope is ASCII by its grammar (RFC 6749 §3.3), and
 * the match folds ASCII letters only, so it does not depend on a locale, as
 * the CHECK's `[qQ][aA][uU][tT][hH]:` class does not either.
 *
 * The auth server's admin scopes (`helpers/admin-scopes.ts`), the environment
 * schema, the realms repository and the `realms` row's CHECK constraint all
 * apply this rule, so none of them accepts what another refuses.
 */

/** The namespace of every QAuth-defined scope. */
export const QAUTH_SCOPE_NAMESPACE = 'qauth:';

/**
 * `qauth:` at the start, ASCII letters in any case. Without the `u` flag, `i`
 * folds no character outside ASCII onto an ASCII letter.
 */
const RESERVED_QAUTH_SCOPE = /^qauth:/i;

/** Whether `scope` is in the reserved `qauth:` namespace, in any case. */
export function isReservedQauthScope(scope: string): boolean {
  return RESERVED_QAUTH_SCOPE.test(scope);
}

/** The entries of `scopes` in the reserved `qauth:` namespace, in their order. */
export function reservedQauthScopesIn(scopes: Iterable<string>): string[] {
  return [...scopes].filter(isReservedQauthScope);
}
