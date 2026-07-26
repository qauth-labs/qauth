/**
 * The `return_to` open-redirect guard, shared by every browser sign-in surface
 * (issues #150, #239).
 *
 * The value this accepts reaches `reply.redirect(...)` for a freshly
 * authenticated user, so anything it lets through is a place this server will
 * send someone who has just proven who they are. It lives in one module because
 * there is now more than one way to sign in — the password form and the wallet
 * flow — and two copies of an allowlist are two chances to relax one of them.
 */

/**
 * Is `value` a safe same-origin relative path to return to after sign-in?
 *
 * Allowlist-shaped: a single leading `/` and nothing that a browser would
 * resolve cross-origin. Callers fall back to `/` for everything it rejects.
 */
export function isSafeReturnTo(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (value.length === 0) return false;
  // Disallow absolute URLs, protocol-relative, or anything that doesn't
  // start with a single `/`. This keeps us off the open-redirector list.
  if (!value.startsWith('/')) return false;
  if (value.startsWith('//')) return false;
  // `/\evil.example` is protocol-relative too. The WHATWG URL parser folds `\`
  // into `/` for special schemes, so a browser resolving
  // `Location: /\evil.example` against `https://auth.example.com` navigates to
  // `https://evil.example` — the exact bypass the `//` check above exists to
  // stop, spelled differently. Verified against Node's URL implementation,
  // which is the same algorithm browsers use:
  // `new URL('/\\evil.example/x', 'https://auth.example.com').host === 'evil.example'`.
  if (value.startsWith('/\\')) return false;
  return true;
}

/** {@link isSafeReturnTo}, with the fallback applied. */
export function resolveReturnTo(value: unknown): string {
  return isSafeReturnTo(value) ? value : '/';
}
