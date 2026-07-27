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
 * Highest code point the URL parser DISCARDS before it parses anything.
 *
 * Tab, LF and CR are removed from ANYWHERE in a URL, and C0 controls and space
 * are trimmed off both ends — all of it before the first `/` is ever looked at.
 * A prefix check against the raw string is therefore not a check against what
 * the browser will resolve: one discarded character sitting between two slashes
 * reads as a single-slash relative path here and is protocol-relative by the
 * time it reaches a browser.
 *
 * We reject the whole C0-plus-space class rather than the three characters that
 * are actually stripped today, because a guard enumerating exactly today's
 * offenders is a guard the next spelling walks through. Nothing this server puts
 * in a `return_to` contains one — paths and percent-encoded queries only.
 */
const URL_DISCARDED_CHARACTER_MAX = 0x20;

/** Does `value` carry a character the URL parser would drop before parsing? */
function hasUrlDiscardedCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    if (value.charCodeAt(i) <= URL_DISCARDED_CHARACTER_MAX) return true;
  }
  return false;
}

/**
 * Base for the same-origin check below. RFC 2606 reserves `.invalid`, so it can
 * never be a real destination: a value that resolves away from this origin would
 * have left ours too.
 */
const SAME_ORIGIN_SENTINEL = 'https://return-to.invalid';

/**
 * Is `value` a safe same-origin relative path to return to after sign-in?
 *
 * Allowlist-shaped: a single leading `/` and nothing that a browser would
 * resolve cross-origin. Callers fall back to `/` for everything it rejects.
 */
export function isSafeReturnTo(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (value.length === 0) return false;
  // Before any prefix check, because the prefix a browser sees is not
  // necessarily the one written here. See {@link URL_DISCARDED_CHARACTER_MAX}.
  if (hasUrlDiscardedCharacter(value)) return false;
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
  // Normalize-then-compare backstop. The checks above name the bypasses we know
  // about; this is what still holds when there turns out to be another one.
  // Resolve the value the way a browser resolves a `Location` header and require
  // the origin not to have moved.
  try {
    if (new URL(value, SAME_ORIGIN_SENTINEL).origin !== SAME_ORIGIN_SENTINEL) return false;
  } catch {
    // Unparseable is not a place we are willing to send anyone.
    return false;
  }
  return true;
}

/** {@link isSafeReturnTo}, with the fallback applied. */
export function resolveReturnTo(value: unknown): string {
  return isSafeReturnTo(value) ? value : '/';
}
