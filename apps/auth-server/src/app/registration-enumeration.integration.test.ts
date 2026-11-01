import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  type E2eInfrastructure,
  extractCsrfToken,
  generateJwtPem,
  type PemKeyPair,
  REQUIRED_TEST_ENVIRONMENT,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * REGISTRATION DOES NOT REVEAL WHETHER AN ADDRESS HAS AN ACCOUNT
 * (ANT-2026-SPEMY9GU, `docs/security/threat-model.md`).
 *
 * The scanner's scenario against a real Postgres and Redis, on a deployment
 * with no setting changed: an ordinary user signs up and verifies, then an
 * anonymous caller registers that address and an unused one with the same
 * password, and tries to log in to both with it.
 *
 * Before the fix the first step answered `409` for the registered address and
 * `201` (with the new user's id) for the free one, and the login answered
 * `200` for the free one and `401` for the registered one (`403` vs `401` with
 * `REQUIRE_VERIFIED_ACCOUNT=true`). Each step now answers both the same way.
 * The unique-index duplicate path only exists against a real database, which
 * is why this is an integration suite.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const REALM = 'master';
/** Where the mailed links point: the default realm's issuer (#490). */
const MAIL_LINK = { baseUrl: REQUIRED_TEST_ENVIRONMENT['JWT_ISSUER'] };
const VICTIM = 'victim@example.test';
const VICTIM_PASSWORD = 'Victims-Own-Long-Passphrase-77!';
const FREE = 'nobody-here@example.test';
const ATTACKER_PASSWORD = 'Purple-Otter-Ladder-42!';

/**
 * Response headers that differ between ANY two requests: the request id, the
 * date, and the per-address rate-limit counters. Everything else must match,
 * except the CSP nonces, which are fresh on every response and are masked.
 */
const PER_REQUEST_HEADERS = new Set([
  'date',
  'x-request-id',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
  'retry-after',
]);

function stableHeaders(response: LightMyRequestResponse): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(response.headers)
      .filter(([name]) => !PER_REQUEST_HEADERS.has(name))
      .map(([name, value]) =>
        name === 'content-security-policy' && typeof value === 'string'
          ? [name, value.replace(/'nonce-[^']+'/g, "'nonce-*'")]
          : [name, value]
      )
  );
}

/**
 * A problem document without its `trace_id`, which is the request id and so
 * differs between any two requests (#513). Every other member must match.
 */
function stableProblem(response: LightMyRequestResponse): Record<string, unknown> {
  const { trace_id: traceId, ...rest } = response.json() as Record<string, unknown>;
  expect(traceId).toEqual(expect.any(String));
  return rest;
}

describe('registration does not reveal whether an address is registered (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  /** A deployment on the defaults this fix is about. */
  async function withDeployment<T>(body: (app: FastifyInstance) => Promise<T>): Promise<T> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    let booted: BootedAuthServer | undefined;
    try {
      booted = await bootAuthServer({
        ...baseEnvironment(infra, jwt),
        // Blank is unset (as docker-compose.yml forwards it): the DEFAULT gate,
        // whatever the shell running the suite exports.
        REQUIRE_VERIFIED_ACCOUNT: '',
        REQUIRE_EMAIL_VERIFIED: '',
        REGISTRATION_RATE_LIMIT: '100',
        // Five refused logins from one address arm the lockout by default; this
        // suite makes four on purpose before the victim's own sign-in.
        FAILED_LOGIN_MAX_ATTEMPTS: '100',
        METRICS_ENABLED: 'true',
      });
      await resetE2eState(booted.app);
      return await body(booted.app);
    } finally {
      await booted?.close();
    }
  }

  function register(app: FastifyInstance, email: string, password: string) {
    return app.inject({ method: 'POST', url: '/auth/register', payload: { email, password } });
  }

  function login(app: FastifyInstance, email: string, password: string) {
    return app.inject({ method: 'POST', url: '/auth/login', payload: { email, password } });
  }

  /** Sign in through the hosted login form; returns the response. */
  async function uiLogin(app: FastifyInstance, email: string, password: string) {
    const jar = new CookieJar();
    const page = await app.inject({ method: 'GET', url: '/ui/login' });
    jar.absorb(page.headers['set-cookie']);
    return app.inject({
      method: 'POST',
      url: '/ui/login',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: jar.header() as string,
      },
      payload: new URLSearchParams({
        email,
        password,
        csrf_token: extractCsrfToken(page.body),
      }).toString(),
    });
  }

  /** The victim signs up and verifies from the mailed link, as a person would. */
  async function victimSignsUp(app: FastifyInstance): Promise<void> {
    const sent = vi.spyOn(app.emailService, 'sendVerificationEmail');
    try {
      expect((await register(app, VICTIM, VICTIM_PASSWORD)).statusCode).toBe(202);
      await vi.waitFor(() =>
        expect(sent).toHaveBeenCalledWith(expect.any(String), VICTIM, expect.any(String), MAIL_LINK)
      );
      const token = sent.mock.calls.at(-1)?.[2];
      const verified = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: { token, password: VICTIM_PASSWORD },
      });
      expect(verified.statusCode).toBe(200);
    } finally {
      sent.mockRestore();
    }
    // Time passes: the per-address mail interval the sign-up claimed runs out.
    await app.redis.flushdb();
  }

  it('answers a registered and a free address identically, at registration and at login', async () => {
    await withDeployment(async (app) => {
      await victimSignsUp(app);
      const notices = vi.spyOn(app.emailService, 'sendAccountExistsEmail');

      // Step 1: register both addresses with the attacker's password.
      const taken = await register(app, VICTIM, ATTACKER_PASSWORD);
      const free = await register(app, FREE, ATTACKER_PASSWORD);

      expect(taken.statusCode).toBe(202);
      expect(free.statusCode).toBe(taken.statusCode);
      expect(free.body).toBe(taken.body);
      expect(stableHeaders(free)).toEqual(stableHeaders(taken));
      expect(taken.json()).toEqual({
        message: 'Registration received. Check your inbox for an email with the next step.',
      });

      // Step 2: log in to both with the password just chosen. The free address
      // now has an unverified account with that password; the taken one has
      // the victim's account, for which it is wrong.
      const loginTaken = await login(app, VICTIM, ATTACKER_PASSWORD);
      const loginFree = await login(app, FREE, ATTACKER_PASSWORD);

      expect(loginTaken.statusCode).toBe(401);
      expect(loginTaken.json()).toMatchObject({ status: 401, code: 'invalid_credentials' });
      expect(loginFree.statusCode).toBe(loginTaken.statusCode);
      expect(stableProblem(loginFree)).toEqual(stableProblem(loginTaken));
      expect(stableHeaders(loginFree)).toEqual(stableHeaders(loginTaken));

      // The same through the hosted login page. The page echoes the typed
      // address back into the form, and carries this request's CSRF token.
      const masked = (response: LightMyRequestResponse, email: string) =>
        response.body
          .replaceAll(email, 'ADDRESS')
          .replace(/name="csrf_token" value="[^"]*"/, 'CSRF')
          .replace(/ nonce="[^"]*"/g, ' nonce="*"');
      const uiTaken = await uiLogin(app, VICTIM, ATTACKER_PASSWORD);
      const uiFree = await uiLogin(app, FREE, ATTACKER_PASSWORD);

      expect(uiTaken.statusCode).toBe(401);
      expect(uiFree.statusCode).toBe(uiTaken.statusCode);
      expect(masked(uiFree, FREE)).toBe(masked(uiTaken, VICTIM));

      // `/metrics` is unauthenticated: no label of its own for the refusal.
      const metrics = await app.inject({ method: 'GET', url: '/metrics' });
      expect(metrics.body).not.toContain('email_not_verified');

      // What did happen reaches only the mailbox, and the victim is unharmed.
      await vi.waitFor(() => expect(notices).toHaveBeenCalledWith(expect.any(String), VICTIM));
      expect((await login(app, VICTIM, VICTIM_PASSWORD)).statusCode).toBe(200);
      notices.mockRestore();
    });
  }, 120_000);

  it('sends an unverified account its verification link again, and creates nothing', async () => {
    await withDeployment(async (app) => {
      expect((await register(app, FREE, ATTACKER_PASSWORD)).statusCode).toBe(202);
      await app.redis.flushdb();
      const links = vi.spyOn(app.emailService, 'sendVerificationEmail');

      const again = await register(app, FREE, 'Another-Long-Passphrase-31!');

      expect(again.statusCode).toBe(202);
      await vi.waitFor(() =>
        expect(links).toHaveBeenCalledWith(expect.any(String), FREE, expect.any(String), MAIL_LINK)
      );
      const realm = await app.repositories.realms.findByName(REALM);
      if (!realm) throw new Error('no realm');
      const credential = await app.repositories.userCredentials.findByRealmProviderSub(
        realm.id,
        'password',
        FREE
      );
      expect(credential).toBeDefined();
      // Still the first registration's account, password unchanged: the new
      // link verifies only with the password chosen first.
      const token = links.mock.calls.at(-1)?.[2];
      const wrong = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: { token, password: 'Another-Long-Passphrase-31!' },
      });
      expect(wrong.statusCode).toBe(401);
      const right = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: { token, password: ATTACKER_PASSWORD },
      });
      expect(right.statusCode).toBe(200);
      links.mockRestore();
    });
  }, 120_000);
});
