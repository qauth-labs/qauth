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

export function setSessionCookieHeader(payload: PortalSessionPayload): string {
  const value = signSession(payload);
  const attrs = [
    `${SESSION_COOKIE_NAME}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${env.PORTAL_SESSION_TTL}`,
  ];
  if (process.env['NODE_ENV'] === 'production') attrs.push('Secure');
  return attrs.join('; ');
}

export function clearSessionCookieHeader(): string {
  const attrs = [`${SESSION_COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (process.env['NODE_ENV'] === 'production') attrs.push('Secure');
  return attrs.join('; ');
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
