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
  return createHmac('sha256', env.PORTAL_SESSION_SECRET).update(value).digest('base64url');
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

export function readSessionCookie(cookieHeader: string | undefined): PortalSessionPayload | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq);
    if (key !== SESSION_COOKIE_NAME) continue;
    const rawValue = trimmed.slice(eq + 1);
    return verifySession(decodeURIComponent(rawValue));
  }
  return null;
}
