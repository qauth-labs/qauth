import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import type { FastifyReply, FastifyRequest } from 'fastify';

import { env } from '../../config/env';

/**
 * Cookie name used to carry the browser session id (issue #150).
 *
 * The `__Host-` prefix binds the cookie to the current origin with strict
 * requirements enforced by browsers:
 *   - `Secure` attribute MUST be set
 *   - `Path=/` MUST be set
 *   - no `Domain` attribute
 * This gives us free CSRF-ish isolation across subdomains and prevents a
 * sibling origin from overwriting the session.
 */
export const SESSION_COOKIE_NAME = '__Host-qauth_session';

/**
 * Payload stored server-side in Redis keyed by session id. We never put the
 * userId in the cookie itself — the cookie only carries the session id +
 * HMAC. Binding the authenticated user to the cookie only via the Redis
 * lookup keeps revocation cheap (delete the key) and avoids leaking the
 * user id if the signing secret is ever compromised.
 */
export interface BrowserSessionData {
  userId: string;
  email: string;
  sessionId: string;
  createdAt: number;
  /** Monotonic nonce for CSRF double-submit cookie (rotated on consent POST). */
  csrfToken?: string;
  /**
   * CSRF token for the cookie-authed JSON API (e.g. `DELETE /consents/:id`).
   * Distinct from {@link csrfToken} (which the consent screen burns after use)
   * so the two flows don't invalidate each other. Long-lived per session —
   * minted lazily by the GET that lists consents, validated via the
   * `X-CSRF-Token` header on state-changing JSON requests. The custom header
   * forces a CORS preflight, so naive cross-site CSRF is blocked even before
   * the token comparison runs.
   */
  apiCsrfToken?: string;
  /**
   * The exact scope set rendered on the most recent consent screen for a given
   * client, keyed by `client_id`. The consent POST handler grants ONLY these
   * scopes — the hidden `scope` form field is attacker-controllable, so the
   * granted set is bound to what the user actually saw, not to what is POSTed.
   */
  consentScopes?: Record<string, string[]>;
  [key: string]: unknown;
}

const SEPARATOR = '.';

function hmac(value: string): string {
  return createHmac('sha256', env.SESSION_COOKIE_SECRET).update(value).digest('base64url');
}

/**
 * Sign the given session id, returning a cookie value of the form
 * `<sessionId>.<hmac>`. Verification is timing-safe.
 */
export function signSessionId(sessionId: string): string {
  return `${sessionId}${SEPARATOR}${hmac(sessionId)}`;
}

/**
 * Verify a signed cookie value and return the session id if the signature
 * is valid, otherwise null. Never throws — callers treat null as "no
 * authenticated session".
 */
export function verifySignedSessionId(cookieValue: string | undefined | null): string | null {
  if (!cookieValue) return null;
  const idx = cookieValue.lastIndexOf(SEPARATOR);
  if (idx <= 0 || idx === cookieValue.length - 1) return null;

  const sessionId = cookieValue.slice(0, idx);
  const providedSig = cookieValue.slice(idx + 1);
  const expectedSig = hmac(sessionId);

  const providedBuf = Buffer.from(providedSig, 'base64url');
  const expectedBuf = Buffer.from(expectedSig, 'base64url');
  if (providedBuf.length !== expectedBuf.length) return null;
  if (!timingSafeEqual(providedBuf, expectedBuf)) return null;
  return sessionId;
}

/**
 * Parse the `Cookie` header and return the raw value of the given cookie
 * name, or undefined. Avoids adding @fastify/cookie just for read access.
 */
export function readCookie(request: FastifyRequest, name: string): string | undefined {
  const header = request.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const k = trimmed.slice(0, eq);
    if (k !== name) continue;
    return decodeURIComponent(trimmed.slice(eq + 1));
  }
  return undefined;
}

/**
 * Resolve whether the session cookie's `Secure` attribute is set.
 *
 * ADR-008 §5 (#197) T3 relaxation seam, CLIENT-SCOPED. Secure cookies are a T3
 * control. The session cookie is GLOBAL — it is minted at `/ui/login`, which
 * carries NO `client_id` (only a `return_to`) — so there is no client whose
 * environment could safely relax it there. We therefore DEFAULT TO STRICT:
 * `env.SESSION_COOKIE_SECURE` (true in production) governs the attribute, and a
 * caller may relax it ONLY by passing an explicit `secureOverride === false`
 * derived from a resolved `development`-profile policy on a surface that
 * unambiguously has a client in scope. No such caller exists today, so the
 * cookie stays strict everywhere — the deliberate fail-safe for a global
 * control. (Local plain-HTTP dev already relaxes it via `SESSION_COOKIE_SECURE`.)
 *
 * @param secureOverride When `false`, force-disable `Secure` (a deliberate
 *   client-scoped development relaxation). When omitted/`true`, the strict
 *   `env.SESSION_COOKIE_SECURE` default applies.
 */
function resolveCookieSecure(secureOverride?: boolean): boolean {
  if (secureOverride === false) return false;
  return env.SESSION_COOKIE_SECURE;
}

/**
 * Emit a Set-Cookie header for the signed session. Attributes match the
 * issue #150 spec: __Host-, Secure (configurable for local dev),
 * HttpOnly, SameSite=Lax, Path=/.
 *
 * @param secureOverride see {@link resolveCookieSecure} — a client-scoped
 *   development relaxation of the `Secure` attribute (defaults to strict).
 */
export function setSessionCookie(
  reply: FastifyReply,
  sessionId: string,
  secureOverride?: boolean
): void {
  const attrs = [
    `${SESSION_COOKIE_NAME}=${signSessionId(sessionId)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${env.SESSION_COOKIE_TTL}`,
  ];
  // __Host- prefix requires Secure. Tests may turn this off for in-process
  // assertions but production must have it set.
  if (resolveCookieSecure(secureOverride)) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/**
 * Clear the session cookie. Used on logout and when a session id fails to
 * resolve to a Redis entry (stale cookie).
 */
export function clearSessionCookie(reply: FastifyReply): void {
  const attrs = [`${SESSION_COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/**
 * Generate a CSRF token suitable for the consent form's hidden input. The
 * same value is also stored in the session payload; on POST the server
 * compares the two in a timing-safe way (double-submit cookie pattern).
 */
export function generateCsrfToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Timing-safe comparison of CSRF tokens. Returns false for any
 * length-mismatched or missing input without short-circuiting.
 */
export function csrfTokensEqual(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Cookie carrying the CSRF token for the PRE-authentication login form.
 *
 * The login page has no session yet, so the consent screen's session-bound
 * double-submit pattern cannot be reused. Instead we use a SIGNED double-submit
 * cookie: this `__Host-`-prefixed cookie holds the HMAC-signed CSRF token, and
 * the form's hidden field holds the same raw token. On POST the server verifies
 * the cookie signature (so an attacker who cannot read the victim's cookie
 * cannot forge a matching pair) and timing-compares the cookie token against
 * the submitted one. This defends against login CSRF (forced login into an
 * attacker-controlled account) without any server-side state.
 */
export const LOGIN_CSRF_COOKIE_NAME = '__Host-qauth_login_csrf';

/**
 * Emit the signed login-CSRF cookie. `Secure` follows the same global default
 * as the session cookie (`env.SESSION_COOKIE_SECURE`); `__Host-` requires it in
 * production. SameSite=Lax + HttpOnly mirror the session cookie. The value is
 * `<token>.<hmac>` using the same secret/scheme as the session id.
 */
export function setLoginCsrfCookie(reply: FastifyReply, token: string): void {
  const attrs = [
    `${LOGIN_CSRF_COOKIE_NAME}=${token}${SEPARATOR}${hmac(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${env.SESSION_COOKIE_TTL}`,
  ];
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/**
 * Clear the login-CSRF cookie (burned after a successful login POST).
 */
export function clearLoginCsrfCookie(reply: FastifyReply): void {
  const attrs = [`${LOGIN_CSRF_COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/**
 * Verify the signed login-CSRF cookie value and return the embedded token if
 * the signature is valid, otherwise null. Same `<token>.<hmac>` scheme +
 * timing-safe verification as {@link verifySignedSessionId}.
 */
export function verifyLoginCsrfCookie(cookieValue: string | undefined | null): string | null {
  if (!cookieValue) return null;
  const idx = cookieValue.lastIndexOf(SEPARATOR);
  if (idx <= 0 || idx === cookieValue.length - 1) return null;

  const token = cookieValue.slice(0, idx);
  const providedSig = cookieValue.slice(idx + 1);
  const expectedSig = hmac(token);

  const providedBuf = Buffer.from(providedSig, 'base64url');
  const expectedBuf = Buffer.from(expectedSig, 'base64url');
  if (providedBuf.length !== expectedBuf.length) return null;
  if (!timingSafeEqual(providedBuf, expectedBuf)) return null;
  return token;
}
