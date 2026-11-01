import { afterEach, describe, expect, it, vi } from 'vitest';

/**
 * Companion to session-cookie.test.ts (#109). That file mocks
 * SESSION_COOKIE_SECURE=false to exercise the local-dev path; this file mocks
 * it true (the production default) and asserts the Secure attribute is emitted
 * on every set and clear of the signed cookies. Kept in a separate module so
 * the env mock does not collide with the false-path tests.
 */
vi.mock('../../config/env', () => ({
  env: {
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: true,
  },
}));

import { createFakeCookieSigner } from '../../testing/cookie-keys';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';

async function captureCookie(fn: (reply: never) => void | Promise<void>): Promise<string> {
  const headers: Record<string, string> = {};
  const reply = {
    header: (k: string, v: string) => {
      headers[k] = v;
      return reply;
    },
  } as never;
  await fn(reply);
  return headers['Set-Cookie'];
}

afterEach(() => {
  vi.resetModules();
});

describe('session cookie Secure attribute (#109, production default)', () => {
  it('setSessionCookie emits Secure when SESSION_COOKIE_SECURE is true', async () => {
    const { setSessionCookie } = await import('./session-cookie');
    const fastify = { signer: createFakeCookieSigner() };
    const cookie = await captureCookie((reply) =>
      setSessionCookie(fastify, reply, {
        sid: 'sid',
        realmId: REALM,
        expiresAt: Date.now() + 3_600_000,
      })
    );
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain('Path=/');
    expect(cookie).not.toMatch(/Domain=/i);
  });

  it('a client-scoped development override drops Secure, and only that', async () => {
    const { sessionCookieHeader } = await import('./session-cookie');
    const header = await sessionCookieHeader(
      { signer: createFakeCookieSigner() },
      { sid: 'sid', realmId: REALM, expiresAt: Date.now() + 3_600_000 },
      false
    );
    expect(header).not.toContain('Secure');
    expect(header).toContain('HttpOnly');
  });

  it('clearSessionCookie also emits Secure so the clear matches the set', async () => {
    const { clearSessionCookie } = await import('./session-cookie');
    const cookie = await captureCookie((reply) => clearSessionCookie(reply));
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('Max-Age=0');
  });

  it('the login-CSRF and wallet-flow cookies emit Secure on set and clear', async () => {
    const { clearLoginCsrfCookie, clearWalletFlowCookie, setLoginCsrfCookie, setWalletFlowCookie } =
      await import('./session-cookie');
    const fastify = { signer: createFakeCookieSigner() };
    const cookies = [
      await captureCookie((reply) => setLoginCsrfCookie(fastify, reply, REALM, 'token')),
      await captureCookie((reply) => clearLoginCsrfCookie(reply)),
      await captureCookie((reply) =>
        setWalletFlowCookie(fastify, reply, REALM, [
          { handle: 'h', binder: 'b', expiresAt: Date.now() + 60_000 },
        ])
      ),
      await captureCookie((reply) => clearWalletFlowCookie(reply)),
    ];
    for (const cookie of cookies) expect(cookie).toContain('Secure');
  });
});
