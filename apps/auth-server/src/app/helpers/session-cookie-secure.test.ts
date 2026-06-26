import { afterEach, describe, expect, it, vi } from 'vitest';

/**
 * Companion to session-cookie.test.ts (#109). That file mocks
 * SESSION_COOKIE_SECURE=false to exercise the local-dev path; this file mocks
 * it true (the production default) and asserts the Secure attribute is emitted
 * on both set and clear. Kept in a separate module so the env mock does not
 * collide with the false-path tests.
 */
vi.mock('../../config/env', () => ({
  env: {
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: true,
  },
}));

function captureCookie(fn: (reply: never) => void): string {
  const headers: Record<string, string> = {};
  const reply = {
    header: (k: string, v: string) => {
      headers[k] = v;
      return reply;
    },
  } as never;
  fn(reply);
  return headers['Set-Cookie'];
}

afterEach(() => {
  vi.resetModules();
});

describe('session cookie Secure attribute (#109, production default)', () => {
  it('setSessionCookie emits Secure when SESSION_COOKIE_SECURE is true', async () => {
    const { setSessionCookie } = await import('./session-cookie');
    const cookie = captureCookie((reply) => setSessionCookie(reply, 'sid'));
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain('Path=/');
  });

  it('clearSessionCookie also emits Secure so the clear matches the set', async () => {
    const { clearSessionCookie } = await import('./session-cookie');
    const cookie = captureCookie((reply) => clearSessionCookie(reply));
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('Max-Age=0');
  });
});
