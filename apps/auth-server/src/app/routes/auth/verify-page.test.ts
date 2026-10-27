import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../config/env', async () => {
  const { EMAIL_VERIFICATION_TEST_ENV } = await import('../../../testing/email-verification-env');
  return { env: { ...EMAIL_VERIFICATION_TEST_ENV } };
});

import {
  buildEmailVerificationApp,
  type EmailVerificationStubs,
  hiddenField,
} from '../../../testing/email-verification-app';
import { LOGIN_CSRF_COOKIE_NAME } from '../../helpers/session-cookie';

/**
 * GET /auth/verify — the page the verification mail links to (42c4d1e4 left
 * the link with no route). Opening it must change nothing: a mail gateway's
 * link scanner or a prefetch fetches it too.
 */
describe('GET /auth/verify (the emailed link)', () => {
  const TOKEN = '0123456789abcdef'.repeat(4);
  let app: FastifyInstance;
  let stubs: EmailVerificationStubs;

  beforeEach(async () => {
    ({ app, stubs } = await buildEmailVerificationApp());
  });

  afterEach(async () => {
    await app.close();
  });

  function expectNothingTouched() {
    expect(stubs.hashToken).not.toHaveBeenCalled();
    expect(stubs.findByTokenHash).not.toHaveBeenCalled();
    expect(stubs.findCredentialById).not.toHaveBeenCalled();
    expect(stubs.verifyPassword).not.toHaveBeenCalled();
    expect(stubs.transaction).not.toHaveBeenCalled();
    expect(stubs.markUsed).not.toHaveBeenCalled();
    expect(stubs.setEmailVerified).not.toHaveBeenCalled();
    expect(stubs.redis.incr).not.toHaveBeenCalled();
  }

  it('renders the password form with the token in a hidden field, and verifies nothing', async () => {
    const res = await app.inject({ method: 'GET', url: `/auth/verify?token=${TOKEN}` });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('text/html; charset=utf-8');
    expect(res.body).toContain('<form method="post" action="/ui/verify">');
    expect(hiddenField(res.body, 'token')).toBe(TOKEN);
    expect(res.body).toContain('<input type="password" name="password"');
    // No script at all: the form works without JavaScript.
    expect(res.body).not.toContain('<script');
    expectNothingTouched();
  });

  it('carries the headers that keep the token on this page', async () => {
    const res = await app.inject({ method: 'GET', url: `/auth/verify?token=${TOKEN}` });

    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    const csp = res.headers['content-security-policy'] as string;
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("form-action 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("'unsafe-inline'");
    // The page's one inline <style> carries this response's nonce.
    const nonce = /style-src [^;]*'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(res.body).toContain(`<style nonce="${nonce}">`);
  });

  it('sets the signed login-CSRF cookie and puts its token in the form', async () => {
    const res = await app.inject({ method: 'GET', url: `/auth/verify?token=${TOKEN}` });

    const setCookie = [res.headers['set-cookie'] ?? []].flat();
    const cookie = setCookie.find((value) => value.startsWith(`${LOGIN_CSRF_COOKIE_NAME}=`));
    expect(cookie).toBeDefined();
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
    const csrf = hiddenField(res.body, 'csrf_token');
    expect(csrf).toBeTruthy();
    expect(cookie?.split(';', 1)[0]).toMatch(new RegExp(`^${LOGIN_CSRF_COOKIE_NAME}=${csrf}\\.`));
  });

  it('keeps a valid login-CSRF cookie the browser already has', async () => {
    const first = await app.inject({ method: 'GET', url: `/auth/verify?token=${TOKEN}` });
    const cookie = [first.headers['set-cookie'] ?? []].flat()[0]?.split(';', 1)[0] ?? '';

    const again = await app.inject({
      method: 'GET',
      url: `/auth/verify?token=${TOKEN}`,
      headers: { cookie },
    });

    expect(again.headers['set-cookie']).toBeUndefined();
    expect(hiddenField(again.body, 'csrf_token')).toBe(hiddenField(first.body, 'csrf_token'));
  });

  it('accepts the token in either hex case, as POST /auth/verify does', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/auth/verify?token=${TOKEN.toUpperCase()}`,
    });

    expect(res.statusCode).toBe(200);
    expect(hiddenField(res.body, 'token')).toBe(TOKEN.toUpperCase());
  });

  it.each([
    ['no token', '/auth/verify'],
    ['an empty token', '/auth/verify?token='],
    ['a truncated token', `/auth/verify?token=${TOKEN.slice(0, 40)}`],
    ['a token with a non-hex character', `/auth/verify?token=${TOKEN.slice(0, 63)}g`],
  ])('answers %s with the incomplete-link page, no form and no 500', async (_case, url) => {
    const res = await app.inject({ method: 'GET', url });

    expect(res.statusCode).toBe(400);
    expect(res.headers['content-type']).toBe('text/html; charset=utf-8');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.body).toContain('This link is incomplete');
    expect(res.body).not.toContain('<form');
    expect(res.headers['set-cookie']).toBeUndefined();
    expectNothingTouched();
  });

  it('never echoes a hostile token value back into the page', async () => {
    const hostile = '"><script>alert(1)</script>';
    const res = await app.inject({
      method: 'GET',
      url: `/auth/verify?token=${encodeURIComponent(hostile)}`,
    });

    expect(res.statusCode).toBe(400);
    expect(res.body).not.toContain('<script');
    expect(res.body).not.toContain('alert(1)');
    expectNothingTouched();
  });

  it('answers HEAD (what some link scanners send) without touching anything', async () => {
    const res = await app.inject({ method: 'HEAD', url: `/auth/verify?token=${TOKEN}` });

    expect(res.statusCode).toBe(200);
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expectNothingTouched();
  });
});
