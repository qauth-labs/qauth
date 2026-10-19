import { createHmac, timingSafeEqual } from 'node:crypto';

import { env } from './config';

export const SESSION_COOKIE_NAME = '__Host-qauth_portal_session';

export interface PortalSessionPayload {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

const SEPARATOR = '.';

function hmac(value: string): string {
  // `config.ts` throws on startup (SSR) if this is unset, but the exported type
  // stays `string | undefined` because the bundler can pull this server-only
  // module into a client chunk where process.env is empty. This module is only
  // reached on the server, so re-assert here to satisfy the type checker and
  // fail loudly rather than HMAC with an undefined key.
  const secret = env.PORTAL_SESSION_SECRET;
  if (!secret) {
    throw new Error('PORTAL_SESSION_SECRET is not configured');
  }
  return createHmac('sha256', secret).update(value).digest('base64url');
}

export function signSession(payload: PortalSessionPayload): string {
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = hmac(encodedPayload);
  return `${encodedPayload}${SEPARATOR}${signature}`;
}

export function verifySession(value: string): PortalSessionPayload | null {
  const idx = value.lastIndexOf(SEPARATOR);
  if (idx <= 0 || idx === value.length - 1) return null;

  const encodedPayload = value.slice(0, idx);
  const providedSig = value.slice(idx + 1);
  const expectedSig = hmac(encodedPayload);

  const providedBuf = Buffer.from(providedSig, 'base64url');
  const expectedBuf = Buffer.from(expectedSig, 'base64url');
  if (providedBuf.length !== expectedBuf.length) return null;
  if (!timingSafeEqual(providedBuf, expectedBuf)) return null;

  try {
    return JSON.parse(
      Buffer.from(encodedPayload, 'base64url').toString('utf8')
    ) as PortalSessionPayload;
  } catch {
    return null;
  }
}

// `Secure` is always emitted: the `__Host-` prefix requires it (RFC 6265bis
// §4.1.3.2). Browsers reject any `Set-Cookie` header for a `__Host-` cookie
// without `Secure`, even on localhost. Dev over plain HTTP must therefore
// loop back through localhost (which browsers treat as a secure context) or
// use a TLS-terminating proxy.
export function setSessionCookieHeader(payload: PortalSessionPayload): string {
  const value = signSession(payload);
  return [
    `${SESSION_COOKIE_NAME}=${value}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${env.PORTAL_SESSION_TTL}`,
  ].join('; ');
}

export function clearSessionCookieHeader(): string {
  return [
    `${SESSION_COOKIE_NAME}=`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Max-Age=0',
  ].join('; ');
}

// Strip what a browser strips around a cookie-pair — SP and HTAB (RFC 6265
// §5.2) — and nothing else. NOT `String.prototype.trim()`: that also removes
// U+00A0, which is how Node's latin-1 header decoding delivers the byte 0xA0.
// A browser keeps that byte as part of the name, so `<A0>__Host-x` does not
// START with `__Host-` there and a sibling host may set it with `Domain=`;
// trimming it would read that cookie as the `__Host-` one. A loop rather than
// a regex: `[ \t]+$` backtracks quadratically on a long run of spaces.
function stripCookieWhitespace(pair: string): string {
  let start = 0;
  let end = pair.length;
  while (start < end && (pair[start] === ' ' || pair[start] === '\t')) start += 1;
  while (end > start && (pair[end - 1] === ' ' || pair[end - 1] === '\t')) end -= 1;
  return pair.slice(start, end);
}

export function readSessionCookie(cookieHeader: string | undefined): PortalSessionPayload | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const trimmed = stripCookieWhitespace(part);
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq);
    if (key !== SESSION_COOKIE_NAME) continue;
    const rawValue = trimmed.slice(eq + 1);
    return verifySession(decodeURIComponent(rawValue));
  }
  return null;
}
