import Fastify, {
  type FastifyInstance,
  type LightMyRequestResponse,
  type RouteOptions,
} from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../config/env', async () => {
  const { EMAIL_VERIFICATION_TEST_ENV } = await import('../../../testing/email-verification-env');
  return { env: { ...EMAIL_VERIFICATION_TEST_ENV } };
});

import {
  buildEmailVerificationApp,
  cookieHeader,
  type EmailVerificationStubs,
  hiddenField,
  passwordCredentialFixture,
} from '../../../testing/email-verification-app';
import { hashEmail } from '../../helpers/auth-events';
import { LOGIN_CSRF_COOKIE_NAME } from '../../helpers/session-cookie';
import { VERIFY_FORM_ERRORS } from '../../helpers/verify-email-page';
import verifyApiRoute from '../auth/verify';
import verifyPageRoute from '../auth/verify-page';
import uiVerifyRoute from './verify';

/**
 * POST /ui/verify — the form of the emailed link's page. It verifies through
 * the same function as POST /auth/verify, and answers each outcome with the
 * status that route answers, so the page tells a caller no more than the JSON
 * API does.
 */
describe('POST /ui/verify (the form of the emailed link)', () => {
  const TOKEN = '0123456789abcdef'.repeat(4);
  const PASSWORD = 'registrant-password';
  let app: FastifyInstance;
  let stubs: EmailVerificationStubs;

  beforeEach(async () => {
    ({ app, stubs } = await buildEmailVerificationApp());
  });

  afterEach(async () => {
    await app.close();
  });

  /** Open the mailed link, as a browser does: the page, its CSRF field and cookie. */
  async function openLink(): Promise<{ csrf: string; cookie: string }> {
    const page = await app.inject({ method: 'GET', url: `/auth/verify?token=${TOKEN}` });
    expect(page.statusCode).toBe(200);
    return {
      csrf: hiddenField(page.body, 'csrf_token') ?? '',
      cookie: cookieHeader(page.headers['set-cookie']),
    };
  }

  /** Submit the page's form. */
  async function submitForm(
    fields: { password?: string; token?: string; csrf?: string } = {},
    options: { cookie?: string; ip?: string } = {}
  ): Promise<LightMyRequestResponse> {
    const opened = await openLink();
    return app.inject({
      method: 'POST',
      url: '/ui/verify',
      remoteAddress: options.ip,
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: options.cookie ?? opened.cookie,
      },
      payload: new URLSearchParams({
        token: fields.token ?? TOKEN,
        password: fields.password ?? PASSWORD,
        csrf_token: fields.csrf ?? opened.csrf,
      }).toString(),
    });
  }

  /** The same request to the JSON API. */
  function postJson(
    body: { token?: string; password?: string } = {},
    options: { ip?: string } = {}
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'POST',
      url: '/auth/verify',
      remoteAddress: options.ip,
      payload: { token: body.token ?? TOKEN, password: body.password ?? PASSWORD },
    });
  }

  function expectPageHeaders(res: LightMyRequestResponse) {
    expect(res.headers['content-type']).toBe('text/html; charset=utf-8');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['content-security-policy']).toMatch(/style-src [^;]*'nonce-/);
  }

  it('verifies with the right password and says so, as POST /auth/verify answers 200', async () => {
    const res = await submitForm();

    expect(res.statusCode).toBe(200);
    expectPageHeaders(res);
    expect(res.body).toContain('Email address verified');
    expect(res.body).toContain('<strong>user@example.com</strong> is verified.');
    expect(stubs.hashToken).toHaveBeenCalledWith(TOKEN);
    expect(stubs.verifyPassword).toHaveBeenCalledWith('hash', PASSWORD);
    expect(stubs.markUsed).toHaveBeenCalledOnce();
    expect(stubs.setEmailVerified).toHaveBeenCalledWith('cred-1', expect.anything());
    expect(stubs.setVerified).toHaveBeenCalledWith(
      'user-1',
      'self_reported',
      'email',
      true,
      expect.anything()
    );

    stubs.markUsed.mockClear();
    const json = await postJson();
    expect(json.statusCode).toBe(res.statusCode);
    expect(json.json()).toEqual({
      message: 'Email verified successfully',
      email: 'user@example.com',
    });
  });

  it('keeps the form after a wrong password, consumes nothing, and answers 401 as the API does', async () => {
    stubs.verifyPassword.mockResolvedValue(false);

    const res = await submitForm({ password: 'mailbox-owner-guess' });

    expect(res.statusCode).toBe(401);
    expectPageHeaders(res);
    expect(res.body).toContain(VERIFY_FORM_ERRORS.wrongPassword);
    // The form is there again, with the token, so the registrant can retry.
    expect(hiddenField(res.body, 'token')).toBe(TOKEN);
    expect(hiddenField(res.body, 'csrf_token')).toBeTruthy();
    expect(stubs.transaction).not.toHaveBeenCalled();
    expect(stubs.markUsed).not.toHaveBeenCalled();
    expect(stubs.setEmailVerified).not.toHaveBeenCalled();

    const json = await postJson({ password: 'mailbox-owner-guess' });
    expect(json.statusCode).toBe(res.statusCode);
  });

  it('answers an unknown, expired or used token with one page, 400 as the API does', async () => {
    stubs.findByTokenHash.mockResolvedValue(undefined);

    const res = await submitForm();

    expect(res.statusCode).toBe(400);
    expectPageHeaders(res);
    expect(res.body).toContain('This link is no longer valid');
    expect(res.body).not.toContain('<form');
    expect(stubs.verifyPassword).not.toHaveBeenCalled();

    const json = await postJson();
    expect(json.statusCode).toBe(res.statusCode);
  });

  it('answers a disabled account exactly as an unknown token', async () => {
    stubs.findByTokenHash.mockResolvedValue(undefined);
    const unknown = await submitForm();
    stubs.findByTokenHash.mockResolvedValue({
      id: 'token-1',
      credentialId: 'cred-1',
      userId: 'user-1',
    });
    stubs.findUserById.mockResolvedValue({ id: 'user-1', enabled: false });
    const disabled = await submitForm();

    const masked = (res: LightMyRequestResponse) => res.body.replace(/ nonce="[^"]*"/g, '');
    expect(disabled.statusCode).toBe(unknown.statusCode);
    expect(masked(disabled)).toBe(masked(unknown));
    expect(stubs.verifyPassword).not.toHaveBeenCalled();
  });

  it('answers an address already verified with 409, as the API does', async () => {
    stubs.findCredentialById.mockResolvedValue(
      passwordCredentialFixture({ credentialData: { password_hash: 'hash', email_verified: true } })
    );

    const res = await submitForm();

    expect(res.statusCode).toBe(409);
    expectPageHeaders(res);
    expect(res.body).toContain('Email address already verified');
    expect(stubs.markUsed).not.toHaveBeenCalled();

    const json = await postJson();
    expect(json.statusCode).toBe(res.statusCode);
  });

  it('shares the failed-login lockout: 429 with Retry-After, as the API does', async () => {
    const emailId = `email:${hashEmail('user@example.com')}`;
    stubs.redis._store.set(`failed-login:lockout:realm-1:${emailId}`, '1');
    stubs.redis._ttls.set(`failed-login:lockout:realm-1:${emailId}`, 300);

    const res = await submitForm();

    expect(res.statusCode).toBe(429);
    expect(res.headers['retry-after']).toBe('300');
    expectPageHeaders(res);
    expect(res.body).toContain(VERIFY_FORM_ERRORS.lockedOut);
    expect(hiddenField(res.body, 'token')).toBe(TOKEN);
    expect(stubs.verifyPassword).not.toHaveBeenCalled();

    const json = await postJson();
    expect(json.statusCode).toBe(res.statusCode);
    expect(json.headers['retry-after']).toBe('300');
  });

  it('counts wrong passwords from the form and the API on one account', async () => {
    stubs.verifyPassword.mockResolvedValue(false);

    for (let i = 0; i < 3; i++) {
      expect(
        (await submitForm({ password: 'wrong' }, { ip: `198.51.100.${i + 1}` })).statusCode
      ).toBe(401);
    }
    for (let i = 3; i < 5; i++) {
      expect(
        (await postJson({ password: 'wrong' }, { ip: `198.51.100.${i + 1}` })).statusCode
      ).toBe(401);
    }
    // Five wrong passwords, through either door: the account is locked.
    const locked = await submitForm({}, { ip: '198.51.100.9' });
    expect(locked.statusCode).toBe(429);
    expect(stubs.verifyPassword).toHaveBeenCalledTimes(5);
  });

  describe('CSRF (signed double-submit, as /ui/login)', () => {
    it('refuses a post with no login-CSRF cookie before any lookup, with a fresh token', async () => {
      const res = await submitForm({}, { cookie: '' });

      expect(res.statusCode).toBe(403);
      expectPageHeaders(res);
      expect(res.body).toContain(VERIFY_FORM_ERRORS.sessionExpired);
      expect(hiddenField(res.body, 'token')).toBe(TOKEN);
      const fresh = hiddenField(res.body, 'csrf_token');
      expect(cookieHeader(res.headers['set-cookie'])).toMatch(
        new RegExp(`^${LOGIN_CSRF_COOKIE_NAME}=${fresh}\\.`)
      );
      expect(stubs.hashToken).not.toHaveBeenCalled();
      expect(stubs.findByTokenHash).not.toHaveBeenCalled();
      expect(stubs.verifyPassword).not.toHaveBeenCalled();
      expect(stubs.redis.incr).not.toHaveBeenCalled();
    });

    it('refuses a field that does not match the cookie', async () => {
      const res = await submitForm({ csrf: 'not-the-cookie-token' });

      expect(res.statusCode).toBe(403);
      expect(stubs.findByTokenHash).not.toHaveBeenCalled();
      expect(stubs.markUsed).not.toHaveBeenCalled();
    });

    it('refuses a cookie whose signature does not verify', async () => {
      const { csrf } = await openLink();
      const res = await submitForm(
        { csrf },
        { cookie: `${LOGIN_CSRF_COOKIE_NAME}=${csrf}.forged-signature` }
      );

      expect(res.statusCode).toBe(403);
      expect(stubs.findByTokenHash).not.toHaveBeenCalled();
    });
  });

  it('refuses a malformed token or an empty password at the schema, as the API does', async () => {
    const opened = await openLink();
    for (const fields of [
      { token: 'not-hex', password: PASSWORD },
      { token: TOKEN, password: '' },
    ]) {
      const form = await app.inject({
        method: 'POST',
        url: '/ui/verify',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          cookie: opened.cookie,
        },
        payload: new URLSearchParams({ ...fields, csrf_token: opened.csrf }).toString(),
      });
      const json = await postJson(fields);

      expect(form.statusCode).toBe(400);
      expect(json.statusCode).toBe(form.statusCode);
    }
    expect(stubs.findByTokenHash).not.toHaveBeenCalled();
  });

  it('is a browser route with the rate limit of POST /auth/verify; the link page is a browser route too', async () => {
    const seen = new Map<string, RouteOptions>();
    const probe = Fastify({ logger: false });
    probe.setValidatorCompiler(validatorCompiler);
    probe.setSerializerCompiler(serializerCompiler);
    probe.addHook('onRoute', (route) => {
      seen.set(`${String(route.method)} ${route.url}`, route);
    });
    await probe.register(verifyApiRoute, { prefix: '/auth' });
    await probe.register(verifyPageRoute, { prefix: '/auth' });
    await probe.register(uiVerifyRoute, { prefix: '/ui' });
    await probe.ready();

    const form = seen.get('POST /ui/verify')?.config;
    const api = seen.get('POST /auth/verify')?.config;
    expect(form?.surface).toBe('browser');
    expect(form?.rateLimit).toEqual(api?.rateLimit);
    expect(form?.rateLimit).toMatchObject({ max: 10, timeWindow: 900_000 });
    expect(seen.get('GET /auth/verify')?.config?.surface).toBe('browser');
    expect(api?.surface).toBe('api');
    await probe.close();
  });
});
