import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
  },
}));

import {
  clearSessionCookie,
  csrfTokensEqual,
  generateCsrfToken,
  readCookie,
  SESSION_COOKIE_NAME,
  setSessionCookie,
  signSessionId,
  verifySignedSessionId,
} from './session-cookie';

describe('session cookie helpers', () => {
  it('signs and verifies a session id round-trip', () => {
    const signed = signSessionId('abc-123');
    expect(verifySignedSessionId(signed)).toBe('abc-123');
  });

  it('rejects a tampered signature', () => {
    const signed = signSessionId('abc-123');
    const tampered = signed.slice(0, -4) + 'XXXX';
    expect(verifySignedSessionId(tampered)).toBeNull();
  });

  it('rejects missing/empty values without throwing', () => {
    expect(verifySignedSessionId(undefined)).toBeNull();
    expect(verifySignedSessionId('')).toBeNull();
    expect(verifySignedSessionId('no-separator')).toBeNull();
    expect(verifySignedSessionId('.onlysig')).toBeNull();
    expect(verifySignedSessionId('onlyid.')).toBeNull();
  });

  it('readCookie returns the correct cookie value', () => {
    const request = {
      headers: { cookie: 'foo=bar; __Host-qauth_session=signed; baz=qux' },
    } as never;
    expect(readCookie(request, SESSION_COOKIE_NAME)).toBe('signed');
    expect(readCookie(request, 'foo')).toBe('bar');
    expect(readCookie(request, 'missing')).toBeUndefined();
  });

  it('setSessionCookie emits __Host- with required attrs', () => {
    const headers: Record<string, string> = {};
    const reply = {
      header: (k: string, v: string) => {
        headers[k] = v;
        return reply;
      },
    } as never;
    setSessionCookie(reply, 'sid');
    const cookie = headers['Set-Cookie'];
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=`);
    expect(cookie).toContain('Path=/');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
  });

  it('clearSessionCookie emits Max-Age=0', () => {
    const headers: Record<string, string> = {};
    const reply = {
      header: (k: string, v: string) => {
        headers[k] = v;
        return reply;
      },
    } as never;
    clearSessionCookie(reply);
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
  });

  it('csrfTokensEqual is timing-safe and length-aware', () => {
    const t = generateCsrfToken();
    expect(csrfTokensEqual(t, t)).toBe(true);
    expect(csrfTokensEqual(t, t + 'x')).toBe(false);
    expect(csrfTokensEqual(undefined, t)).toBe(false);
    expect(csrfTokensEqual(t, undefined)).toBe(false);
  });
});
