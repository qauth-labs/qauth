import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  extractCsrfToken,
  generateJwtPem,
  type PemKeyPair,
  provisionRealmKeys,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE VERIFIED-ACCOUNT, PASSWORD AND BRUTE-FORCE POLICY COME FROM THE REALM
 * ROW (ADR-019 Decision 10, issue #528), end to end against real Postgres and
 * Redis.
 *
 * Two realms of one deployment differ: one refuses an unverified account's
 * password sign-in and the other lets it in, on `/auth/login` and on
 * `/ui/login`; one accepts a weak new password and the other refuses it; the
 * failed sign-ins of one never lock the same address in the other; and a
 * realm whose brute-force policy is off never locks. `REQUIRE_VERIFIED_ACCOUNT`,
 * `PASSWORD_MIN_SCORE` and the `FAILED_LOGIN_*` keys only seed a new realm: a
 * node that boots with other values applies the stored ones. A change of a
 * realm's policies reaches its next request without a restart.
 *
 * A policy change goes through the policy store, as the admin API's will, and
 * the test then drops the realm resolver's host cache, which stands in for its
 * cache time (30 s): the next request reads the row again.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

/** Keys this suite sets; the harness clears only its own prefixes between boots. */
const SUITE_KEYS = [
  'REGISTRATION_RATE_LIMIT',
  'VERIFICATION_RATE_LIMIT',
  'REQUIRE_VERIFIED_ACCOUNT',
  'PASSWORD_MIN_SCORE',
  'FAILED_LOGIN_TRACKING_ENABLED',
  'FAILED_LOGIN_MAX_ATTEMPTS',
] as const;

const HOST_A = 'auth.example.com';
const HOST_B = 'beta.example.com';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const WRONG_PASSWORD = 'Wrong-Password-For-This-Account-7!';
/** zxcvbn scores it 1: weak, below the seeded lowest score of 2. */
const SCORE_ONE_PASSWORD = 'monkey12345';
/** A source address of its own, for guesses whose lockout must not reach the suite's other sign-ins. */
const GUESSER = '198.51.100.7';

describe('account policies read from the realm row (#528, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  /** The suite's deployment: the policy keys unset, so every realm is seeded with the defaults. */
  function environment(overrides: Record<string, string> = {}): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    return {
      ...baseEnvironment(infra, jwt),
      // Sized for humans; a test registers several accounts from one address.
      REGISTRATION_RATE_LIMIT: '1000',
      VERIFICATION_RATE_LIMIT: '1000',
      ...overrides,
    };
  }

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    booted = await bootAuthServer(environment());
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
    for (const key of SUITE_KEYS) delete process.env[key];
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    // The boot step puts the default realm back, seeded from the environment.
    await resetE2eState(booted.app);
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  async function realmIdOf(app: FastifyInstance, name: string): Promise<string> {
    const realm = await app.repositories.realms.findByName(name);
    if (!realm) throw new Error(`no realm ${name}`);
    return realm.id;
  }

  /** A second realm on its own host, with its own keys (#491), seeded as the default realm was. */
  async function createBetaRealm(app: FastifyInstance): Promise<string> {
    const { realm } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'beta', issuer: `https://${HOST_B}`, enabled: true },
      HOST_B
    );
    await provisionRealmKeys(app, 'beta');
    return realm.id;
  }

  /**
   * Change a realm's policies through the policy store, at the counter it has
   * now, and drop the resolver's host cache so the next request reads the row.
   */
  async function updatePolicies(
    app: FastifyInstance,
    realmId: string,
    patch: Record<string, unknown>
  ): Promise<void> {
    const current = await app.policyStore.get(realmId);
    if (current === undefined) throw new Error(`no policies for realm ${realmId}`);
    expect(current.hasPolicies).toBe(true);
    await app.policyStore.update(realmId, patch, { expectedVersion: current.version });
    app.realmHostCache.clear();
  }

  /**
   * `POST /auth/register` at `host` of a new address, the account left
   * unverified. An accepted registration's verification mail goes out off the
   * request path: it is waited for, so no mail is still being sent when the
   * next test empties the database.
   */
  async function register(
    app: FastifyInstance,
    host: string,
    email: string,
    password = E2E_PASSWORD
  ): Promise<LightMyRequestResponse> {
    const emailService = app.emailService;
    const original = emailService.sendVerificationEmail;
    let sent = false;
    emailService.sendVerificationEmail = async (realmId, to, token, link, options) => {
      const result = await original.call(emailService, realmId, to, token, link, options);
      if (to === email) sent = true;
      return result;
    };
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host },
        payload: { email, password },
      });
      if (response.statusCode === 202) {
        const deadline = Date.now() + 5_000;
        while (!sent && Date.now() < deadline) {
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        expect(sent, `the verification mail to ${email}`).toBe(true);
      }
      return response;
    } finally {
      emailService.sendVerificationEmail = original;
    }
  }

  /** Register an account at `host` and leave it unverified. */
  async function registerUnverified(
    app: FastifyInstance,
    host: string,
    email: string
  ): Promise<void> {
    const response = await register(app, host, email);
    expect(response.statusCode, response.body).toBe(202);
  }

  /** `POST /auth/login` at `host`, from `remoteAddress` when given. */
  function apiLogin(
    app: FastifyInstance,
    host: string,
    email: string,
    password = E2E_PASSWORD,
    remoteAddress?: string
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'POST',
      url: '/auth/login',
      headers: { host },
      payload: { email, password },
      ...(remoteAddress === undefined ? {} : { remoteAddress }),
    });
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

  /** The `/ui/login` form at `host`, CSRF included, as a browser fills it in. */
  async function formLogin(
    app: FastifyInstance,
    host: string,
    email: string,
    password = E2E_PASSWORD
  ): Promise<LightMyRequestResponse> {
    const jar = new CookieJar();
    const page = await app.inject({ method: 'GET', url: '/ui/login', headers: { host } });
    expect(page.statusCode).toBe(200);
    jar.absorb(page.headers['set-cookie']);
    return app.inject({
      method: 'POST',
      url: '/ui/login',
      headers: { ...FORM, host, cookie: jar.header() as string },
      payload: new URLSearchParams({
        email,
        password,
        csrf_token: extractCsrfToken(page.body),
      }).toString(),
    });
  }

  /** The failed-login counters and lockouts Redis holds for a realm. */
  async function failedLoginKeys(app: FastifyInstance, realmId: string): Promise<string[]> {
    // `failed-login:<attempts|lockout>:<realm id>:<identifier>`
    return (await app.redis.keys('failed-login:*')).filter((key) => key.split(':')[2] === realmId);
  }

  it('starts every realm with the account policies the environment seeds: the defaults, as before #528', async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    const betaId = await createBetaRealm(app);

    for (const realmId of [defaultId, betaId]) {
      const { policies } = (await app.policyStore.get(realmId)) ?? {};
      expect(policies?.accounts).toEqual({ requireVerifiedAccount: true });
      expect(policies?.password).toEqual({ minScore: 2 });
      expect(policies?.bruteForce).toEqual({
        enabled: true,
        maxAttempts: 5,
        windowSeconds: 900,
        lockoutSeconds: 900,
      });
    }

    // Under those defaults an unverified account is refused like a wrong
    // password, and a score-1 password is refused at registration.
    await registerUnverified(app, HOST_A, 'fresh@example.com');
    expect((await apiLogin(app, HOST_A, 'fresh@example.com')).statusCode).toBe(401);
    expect((await register(app, HOST_A, 'weak@example.com', SCORE_ONE_PASSWORD)).statusCode).toBe(
      422
    );
  });

  it('refuses an unverified login in a realm that requires verified accounts and accepts it in one that does not', async () => {
    const app = server();
    const betaId = await createBetaRealm(app);
    await updatePolicies(app, betaId, { accounts: { requireVerifiedAccount: false } });
    await registerUnverified(app, HOST_A, 'unverified@example.com');
    await registerUnverified(app, HOST_B, 'unverified@example.com');

    // Realm A (the default, `requireVerifiedAccount: true`): the right
    // password of an unverified account is answered as a wrong one, on both
    // front doors.
    const refused = await apiLogin(app, HOST_A, 'unverified@example.com');
    const wrong = await apiLogin(app, HOST_A, 'unverified@example.com', WRONG_PASSWORD);
    expect(refused.statusCode).toBe(401);
    expect(stableProblem(refused)).toEqual(stableProblem(wrong));
    const refusedForm = await formLogin(app, HOST_A, 'unverified@example.com');
    expect(refusedForm.statusCode).toBe(401);
    expect(refusedForm.body).toContain('confirm your email address first');

    // Realm B (`requireVerifiedAccount: false`): the same account signs in.
    const accepted = await apiLogin(app, HOST_B, 'unverified@example.com');
    expect(accepted.statusCode, accepted.body).toBe(200);
    expect(accepted.json<{ access_token: string }>().access_token).toEqual(expect.any(String));
    const acceptedForm = await formLogin(app, HOST_B, 'unverified@example.com');
    expect(acceptedForm.statusCode, acceptedForm.body).toBe(302);
    // Its refusal of a wrong password does not name verification.
    const wrongForm = await formLogin(app, HOST_B, 'unverified@example.com', WRONG_PASSWORD);
    expect(wrongForm.statusCode).toBe(401);
    expect(wrongForm.body).toContain('Invalid email or password.');
    expect(wrongForm.body).not.toContain('confirm your email address');
  });

  it('applies a change of the verified-account gate to the next sign-in, without a restart', async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    await registerUnverified(app, HOST_A, 'later@example.com');
    expect((await apiLogin(app, HOST_A, 'later@example.com')).statusCode).toBe(401);

    await updatePolicies(app, defaultId, { accounts: { requireVerifiedAccount: false } });

    const accepted = await apiLogin(app, HOST_A, 'later@example.com');
    expect(accepted.statusCode, accepted.body).toBe(200);
  });

  it('accepts a weak password in a realm with minScore 1 and refuses it in a realm with minScore 3', async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    const betaId = await createBetaRealm(app);
    await updatePolicies(app, defaultId, { password: { minScore: 1 } });
    await updatePolicies(app, betaId, { password: { minScore: 3 } });

    const lenient = await register(app, HOST_A, 'weak@example.com', SCORE_ONE_PASSWORD);
    const strict = await register(app, HOST_B, 'weak@example.com', SCORE_ONE_PASSWORD);

    expect(lenient.statusCode, lenient.body).toBe(202);
    expect(strict.statusCode, strict.body).toBe(422);
    expect(
      await app.repositories.userCredentials.findByRealmProviderSub(
        defaultId,
        'password',
        'weak@example.com'
      )
    ).toBeDefined();
    expect(
      await app.repositories.userCredentials.findByRealmProviderSub(
        betaId,
        'password',
        'weak@example.com'
      )
    ).toBeUndefined();
    // A strong password still passes the strict realm.
    expect((await register(app, HOST_B, 'strong@example.com')).statusCode).toBe(202);
  });

  it('keeps the failed sign-ins of one realm from locking the same address in another', async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    const betaId = await createBetaRealm(app);
    // Two failures lock in either realm; the environment's seed is five.
    await updatePolicies(app, defaultId, { bruteForce: { maxAttempts: 2 } });
    await updatePolicies(app, betaId, { bruteForce: { maxAttempts: 2 } });
    await registerPasswordAccount(app, 'shared@example.com');
    await registerPasswordAccount(app, 'shared@example.com', E2E_PASSWORD, { host: HOST_B });

    // The realm's two failures, then the right password: refused, locked out.
    for (let attempt = 0; attempt < 2; attempt += 1) {
      expect((await apiLogin(app, HOST_A, 'shared@example.com', WRONG_PASSWORD)).statusCode).toBe(
        401
      );
    }
    const locked = await apiLogin(app, HOST_A, 'shared@example.com');
    expect(locked.statusCode).toBe(429);

    // The same address, from the same source, signs in at realm B, on both
    // front doors.
    const atB = await apiLogin(app, HOST_B, 'shared@example.com');
    expect(atB.statusCode, atB.body).toBe(200);
    expect((await formLogin(app, HOST_B, 'shared@example.com')).statusCode).toBe(302);

    expect(await failedLoginKeys(app, defaultId)).toEqual(
      expect.arrayContaining([expect.stringMatching(/^failed-login:lockout:/)])
    );
    expect(
      (await failedLoginKeys(app, betaId)).filter((key) => key.startsWith('failed-login:lockout:'))
    ).toEqual([]);
  });

  it('never locks in a realm whose brute-force policy is off', async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    const betaId = await createBetaRealm(app);
    // Both realms would lock after one failure; realm B's policy is off.
    await updatePolicies(app, defaultId, { bruteForce: { maxAttempts: 1 } });
    await updatePolicies(app, betaId, { bruteForce: { enabled: false, maxAttempts: 1 } });
    await registerPasswordAccount(app, 'guessed@example.com');
    await registerPasswordAccount(app, 'guessed@example.com', E2E_PASSWORD, { host: HOST_B });

    for (let attempt = 0; attempt < 10; attempt += 1) {
      expect((await apiLogin(app, HOST_B, 'guessed@example.com', WRONG_PASSWORD)).statusCode).toBe(
        401
      );
    }
    expect((await formLogin(app, HOST_B, 'guessed@example.com', WRONG_PASSWORD)).statusCode).toBe(
      401
    );
    const accepted = await apiLogin(app, HOST_B, 'guessed@example.com');
    expect(accepted.statusCode, accepted.body).toBe(200);
    expect(await failedLoginKeys(app, betaId)).toEqual([]);

    // Realm A, whose policy is on, locks after its one failure.
    expect((await apiLogin(app, HOST_A, 'guessed@example.com', WRONG_PASSWORD)).statusCode).toBe(
      401
    );
    expect((await apiLogin(app, HOST_A, 'guessed@example.com')).statusCode).toBe(429);
  });

  it('applies the stored policies on a node booted with other values, which seed only the realms it creates', async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    await registerUnverified(app, HOST_A, 'stored@example.com');

    // Another node of the deployment, booted with looser values, on the same
    // database, whose default realm already has its policies.
    const looser = {
      REQUIRE_VERIFIED_ACCOUNT: 'false',
      PASSWORD_MIN_SCORE: '0',
      FAILED_LOGIN_TRACKING_ENABLED: 'false',
      FAILED_LOGIN_MAX_ATTEMPTS: '9',
    };
    const other = await bootAuthServer(environment(looser));
    try {
      expect((await apiLogin(other.app, HOST_A, 'stored@example.com')).statusCode).toBe(401);
      expect(
        (await register(other.app, HOST_A, 'weak@example.com', SCORE_ONE_PASSWORD)).statusCode
      ).toBe(422);
      expect((await other.app.policyStore.get(defaultId))?.policies).toMatchObject({
        accounts: { requireVerifiedAccount: true },
        password: { minScore: 2 },
        bruteForce: { enabled: true, maxAttempts: 5 },
      });
      // Its environment turns the lockout off; the realm's stored policy locks
      // after five failures, and that node applies it. From an address of its
      // own, so the first node's sign-ins below are not counted with it.
      await registerPasswordAccount(other.app, 'locked@example.com');
      for (let attempt = 0; attempt < 5; attempt += 1) {
        expect(
          (await apiLogin(other.app, HOST_A, 'locked@example.com', WRONG_PASSWORD, GUESSER))
            .statusCode
        ).toBe(401);
      }
      expect(
        (await apiLogin(other.app, HOST_A, 'locked@example.com', E2E_PASSWORD, GUESSER)).statusCode
      ).toBe(429);

      // A realm that node creates gets its environment's values.
      const { realm: gamma } = await other.app.repositories.realms.createWithPrimaryHost(
        { name: 'gamma', issuer: 'https://gamma.example.com', enabled: true },
        'gamma.example.com'
      );
      expect((await other.app.policyStore.get(gamma.id))?.policies).toMatchObject({
        accounts: { requireVerifiedAccount: false },
        password: { minScore: 0 },
        bruteForce: { enabled: false, maxAttempts: 9 },
      });
    } finally {
      await other.close();
      for (const key of Object.keys(looser)) delete process.env[key];
    }

    // The first node, unchanged, applies the stored policies too.
    expect((await apiLogin(app, HOST_A, 'stored@example.com')).statusCode).toBe(401);
  });
});
