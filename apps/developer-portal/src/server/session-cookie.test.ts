import { describe, expect, it, vi } from 'vitest';

vi.mock('./config', () => ({
  env: {
    AUTH_SERVER_URL: 'http://localhost:3001',
    PORTAL_SESSION_SECRET: 'test-secret-minimum-32-chars-long!!',
    PORTAL_SESSION_TTL: 900,
  },
}));

import type { PortalSessionPayload } from './session-cookie';
import {
  clearSessionCookieHeader,
  readSessionCookie,
  SESSION_COOKIE_NAME,
  setSessionCookieHeader,
  signSession,
  verifySession,
} from './session-cookie';

const samplePayload: PortalSessionPayload = {
  accessToken: 'access-token-value',
  refreshToken: 'refresh-token-value',
  expiresAt: Date.now() + 900_000,
};

describe('signSession / verifySession', () => {
  it('round-trips a payload correctly', () => {
    const signed = signSession(samplePayload);
    const result = verifySession(signed);
    expect(result).toEqual(samplePayload);
  });

  it('returns null for a tampered payload', () => {
    const signed = signSession(samplePayload);
    const parts = signed.split('.');
    const tampered = `${parts[0]}TAMPERED.${parts[1]}`;
    expect(verifySession(tampered)).toBeNull();
  });

  it('returns null for a tampered signature', () => {
    const signed = signSession(samplePayload);
    const lastDot = signed.lastIndexOf('.');
    const tampered = `${signed.slice(0, lastDot)}.INVALIDSIGNATURE`;
    expect(verifySession(tampered)).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(verifySession('')).toBeNull();
  });

  it('returns null for a value with no separator', () => {
    expect(verifySession('nodot')).toBeNull();
  });

  it('returns null for a value with only a leading separator', () => {
    expect(verifySession('.abc')).toBeNull();
  });
});

describe('setSessionCookieHeader', () => {
  it('includes the cookie name and required attributes', () => {
    const header = setSessionCookieHeader(samplePayload);
    expect(header).toContain(`${SESSION_COOKIE_NAME}=`);
    expect(header).toContain('HttpOnly');
    expect(header).toContain('SameSite=Lax');
    expect(header).toContain('Path=/');
    expect(header).toContain('Max-Age=900');
  });

  // The `__Host-` prefix mandates `Secure`; browsers reject the cookie
  // without it (RFC 6265bis §4.1.3.2). Emit it unconditionally.
  it('always includes Secure regardless of NODE_ENV', () => {
    const original = process.env['NODE_ENV'];
    for (const envValue of ['test', 'development', 'production']) {
      process.env['NODE_ENV'] = envValue;
      const header = setSessionCookieHeader(samplePayload);
      expect(header).toContain('Secure');
    }
    process.env['NODE_ENV'] = original;
  });
});

describe('clearSessionCookieHeader', () => {
  it('sets Max-Age=0 and clears the cookie value', () => {
    const header = clearSessionCookieHeader();
    expect(header).toContain(`${SESSION_COOKIE_NAME}=`);
    expect(header).toContain('Max-Age=0');
    expect(header).toContain('HttpOnly');
  });

  it('always includes Secure on the clearing header', () => {
    const original = process.env['NODE_ENV'];
    process.env['NODE_ENV'] = 'test';
    expect(clearSessionCookieHeader()).toContain('Secure');
    process.env['NODE_ENV'] = original;
  });
});

describe('readSessionCookie', () => {
  it('returns null when cookieHeader is undefined', () => {
    expect(readSessionCookie(undefined)).toBeNull();
  });

  it('returns null when the named cookie is absent', () => {
    expect(readSessionCookie('other_cookie=value')).toBeNull();
  });

  it('returns null when the cookie value has been tampered', () => {
    const signed = signSession(samplePayload);
    const tampered = signed.slice(0, -5) + 'XXXXX';
    const header = `${SESSION_COOKIE_NAME}=${tampered}`;
    expect(readSessionCookie(header)).toBeNull();
  });

  it('round-trips through a cookie header string', () => {
    const value = signSession(samplePayload);
    const cookieHeader = `other=abc; ${SESSION_COOKIE_NAME}=${value}; extra=xyz`;
    expect(readSessionCookie(cookieHeader)).toEqual(samplePayload);
  });
});
