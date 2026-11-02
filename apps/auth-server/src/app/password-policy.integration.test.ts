import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE ONE PASSWORD POLICY, AND ITS NORMALISATION MARKER, ON REAL CONTAINERS
 * (#634, ADR-017 Decision 8).
 *
 * `POST /auth/register` checks a new password against the realm's policy and
 * answers a refusal with its reasons; it hashes the password in NFC and
 * records the marker, so either spelling of the same text signs in. A
 * credential stored before the policy has no marker, and every verifier (the
 * password sign-in and the email verification) checks it on the password as
 * typed, so existing passwords keep working.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

/** A password as composed (U+00E9) and as decomposed (e + U+0301): one text, two spellings. */
const COMPOSED = 'café-terrace-at-night';
const DECOMPOSED = 'café-terrace-at-night';

describe('the one password policy (real containers, #634)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let accounts = 0;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      // Several accounts register and sign in from one address.
      REGISTRATION_RATE_LIMIT: '100',
      LOGIN_RATE_LIMIT: '100',
    });
    await resetE2eState(booted.app);
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
    delete process.env['REGISTRATION_RATE_LIMIT'];
    delete process.env['LOGIN_RATE_LIMIT'];
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  function app(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  function address(): string {
    accounts += 1;
    return `policy-${accounts}-${Date.now()}@example.com`;
  }

  async function passwordCredential(email: string) {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      realm.id,
      'password',
      email
    );
    if (!credential) throw new Error(`no password credential for ${email}`);
    return credential;
  }

  function login(email: string, password: string) {
    return app().inject({ method: 'POST', url: '/auth/login', payload: { email, password } });
  }

  /**
   * Register `email` and hand back the verification token its mail carried,
   * without verifying the account.
   */
  async function registerUnverified(email: string, password: string): Promise<string> {
    const emailService = app().emailService;
    const original = emailService.sendVerificationEmail;
    const tokens: string[] = [];
    emailService.sendVerificationEmail = async (realmId, to, token, link, options) => {
      if (to === email) tokens.push(token);
      return original.call(emailService, realmId, to, token, link, options);
    };
    try {
      const response = await app().inject({
        method: 'POST',
        url: '/auth/register',
        payload: { email, password },
      });
      expect(response.statusCode, response.body).toBe(202);
      const deadline = Date.now() + 5_000;
      while (tokens.length === 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    } finally {
      emailService.sendVerificationEmail = original;
    }
    const token = tokens.at(-1);
    if (token === undefined) throw new Error(`registration of ${email} sent no verification mail`);
    return token;
  }

  /** Replace the credential's data with what a release before #634 stored: no marker, hashed as typed. */
  async function storeWithoutMarker(email: string, typed: string, emailVerified: boolean) {
    const credential = await passwordCredential(email);
    await app().repositories.userCredentials.updateCredentialData(credential.id, {
      password_hash: await app().passwordHasher.hashPassword(typed),
      email_verified: emailVerified,
    });
  }

  describe('POST /auth/register', () => {
    it('answers a refused password with a weak_password problem carrying its reasons (acceptance criterion)', async () => {
      const response = await app().inject({
        method: 'POST',
        url: '/auth/register',
        payload: { email: address(), password: 'Kx9#mQ2$vL7!pR' },
      });

      expect(response.statusCode).toBe(422);
      expect(response.headers['content-type']).toMatch(/^application\/problem\+json(?:;|$)/);
      expect(response.json()).toMatchObject({
        status: 422,
        code: 'weak_password',
        reasons: ['too_short'],
        errors: [{ pointer: '/password', message: 'Password must be at least 15 characters' }],
      });
    });

    it('lists every reason found, in the order checked', async () => {
      const response = await app().inject({
        method: 'POST',
        url: '/auth/register',
        payload: { email: address(), password: 'password' },
      });

      expect(response.statusCode).toBe(422);
      expect(response.json()).toMatchObject({
        code: 'weak_password',
        reasons: ['too_short', 'blocklisted', 'too_weak'],
      });
    });

    it('refuses the address itself as the password, and accepts one that contains it', async () => {
      const email = address();
      const refused = await app().inject({
        method: 'POST',
        url: '/auth/register',
        payload: { email, password: email },
      });
      expect(refused.statusCode).toBe(422);
      expect(refused.json<{ reasons: string[] }>().reasons).toContain('blocklisted');

      const accepted = await app().inject({
        method: 'POST',
        url: '/auth/register',
        payload: { email, password: `${email} rides the night ferry 1987` },
      });
      expect(accepted.statusCode, accepted.body).toBe(202);
    });

    it('records the NFC marker, and either spelling of the password signs in', async () => {
      const email = address();
      await registerPasswordAccount(app(), email, DECOMPOSED);

      const credential = await passwordCredential(email);
      expect(credential.credentialData).toMatchObject({ password_normalization: 'nfc' });

      for (const password of [COMPOSED, DECOMPOSED]) {
        const response = await login(email, password);
        expect(response.statusCode, response.body).toBe(200);
      }
    });
  });

  describe('a credential without the marker, as stored before #634', () => {
    it('still signs in, verified on the password as typed (acceptance criterion)', async () => {
      const email = address();
      await registerPasswordAccount(app(), email, E2E_PASSWORD);
      await storeWithoutMarker(email, DECOMPOSED, true);

      const asTyped = await login(email, DECOMPOSED);
      expect(asTyped.statusCode, asTyped.body).toBe(200);
      // Not normalised: the other spelling is another password for it.
      const otherSpelling = await login(email, COMPOSED);
      expect(otherSpelling.statusCode).toBe(401);
    });

    it('still verifies the email address, then signs in', async () => {
      const email = address();
      const token = await registerUnverified(email, E2E_PASSWORD);
      await storeWithoutMarker(email, DECOMPOSED, false);

      const verified = await app().inject({
        method: 'POST',
        url: '/auth/verify',
        payload: { token, password: DECOMPOSED },
      });
      expect(verified.statusCode, verified.body).toBe(200);
      expect((await passwordCredential(email)).credentialData).toMatchObject({
        email_verified: true,
      });
      expect((await passwordCredential(email)).credentialData).not.toHaveProperty(
        'password_normalization'
      );

      const asTyped = await login(email, DECOMPOSED);
      expect(asTyped.statusCode, asTyped.body).toBe(200);
    });
  });
});
