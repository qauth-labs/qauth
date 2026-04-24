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
 * Emit a Set-Cookie header for the signed session. Attributes match the
 * issue #150 spec: __Host-, Secure (configurable for local dev),
 * HttpOnly, SameSite=Lax, Path=/.
 */
export function setSessionCookie(reply: FastifyReply, sessionId: string): void {
  const attrs = [
    `${SESSION_COOKIE_NAME}=${signSessionId(sessionId)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${env.SESSION_COOKIE_TTL}`,
  ];
  // __Host- prefix requires Secure. Tests may turn this off for in-process
  // assertions but production must have it set.
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
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
