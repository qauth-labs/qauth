import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
import * as contract from '@qauth-labs/shared-account-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

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
 * THE ACCOUNT API'S SIGN-IN METHODS AND PASSWORD CHANGE (#1107; ADR-020 §3,
 * ADR-017 Decision 8, ADR-019 Decision 7), against a real Postgres and Redis,
 * one case per acceptance criterion:
 *
 * - `GET /sign-in-methods` answers for a password-only account, one with a
 *   passkey, one with an authenticator app, and a passkey-only one;
 * - a wrong current password answers `invalid_current_password` and counts
 *   on the account's failure ladder;
 * - a weak new password, and one on the breach list, answer `weak_password`;
 * - a stale sign-in gets the `insufficient_user_authentication` challenge, an
 *   act-chain token `delegated_token_refused`;
 * - after a change the account's other sessions and its refresh tokens end,
 *   and the session the token names keeps working.
 *
 * Tokens are minted as the code exchange mints the account API's (`auth_time`,
 * `amr`, `sid`), for the account console's backend.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ACCOUNT_AUDIENCE = contract.ACCOUNT_API_AUDIENCE;
const SIGN_IN_METHODS = `${contract.ACCOUNT_API_PREFIX}/sign-in-methods`;
const PASSWORD_CHANGE = `${contract.ACCOUNT_API_PREFIX}/password/change`;
const PASSWORD_CHANGED = 'urn:qauth:event:user.password_changed:v1-rc.0';
const REFUSED = 'urn:qauth:event:request.account_operation_refused:v1-rc.0';
/** The new password: long and unusual, so the realm's policy takes it. */
const NEW_PASSWORD = 'Copper-Heron-Lattice-Orchard-81';
/** A password the policy takes, which the deployment's breach list holds. */
const LISTED_PASSWORD = 'Tangerine-Quartz-Lantern-Orbit-58!';
/** The variables this suite sets beyond the harness's, removed when it ends. */
const SUITE_KEYS = [
  'REGISTRATION_RATE_LIMIT',
  'VERIFICATION_RATE_LIMIT',
  'BREACHED_PASSWORD_LIST_PATH',
  'BREACHED_PASSWORD_RANGE_URL',
];
/** A TOTP time step, in milliseconds. */
const STEP_MS = 30_000;

/**
 * The SHA-1 digest of {@link LISTED_PASSWORD}, as the breach list file holds
 * it: 40 uppercase hex characters, written out as a test vector.
 */
const LISTED_DIGEST = 'A0E0899D8318F7892920FE14CD72B00343B94BDB';

/** A passkey's `credential_data`, as an enrolment stores it. */
function passkeyData(n: number): Record<string, unknown> {
  return {
    public_key: 'pQECAyYgASFYIK_voW-Xypst',
    algorithm: -7,
    sign_count: 0,
    transports: ['internal'],
    backup_eligible: true,
    backed_up: true,
    aaguid: '00000000-0000-0000-0000-000000000000',
    rp_id: 'auth.example.com',
    user_handle: `dXNlci1oYW5kbGU${n}`,
    nickname: null,
    created_at: Date.now(),
    last_used_at: null,
    sign_counter_regressed_at: null,
  };
}

describe('the account API’s sign-in methods and password change (#1107, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let listDirectory: string | undefined;
  let dockerUp = false;
  let realmId = '';
  let accounts = 0;
  /** The engine mails, by address, in order. */
  const mails = new Map<string, string[]>();

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    // The server reads the operator's breach list at boot.
    listDirectory = await mkdtemp(join(tmpdir(), 'qauth-account-breach-list-'));
    const listPath = join(listDirectory, 'breached-passwords.txt');
    await writeFile(listPath, `${LISTED_DIGEST}\n`, 'utf8');
    // A value an earlier file in this worker set must not make the range
    // lookup configured.
    delete process.env['BREACHED_PASSWORD_RANGE_URL'];
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      // Each case registers its own accounts from one address.
      REGISTRATION_RATE_LIMIT: '10000',
      VERIFICATION_RATE_LIMIT: '10000',
      BREACHED_PASSWORD_LIST_PATH: listPath,
    });
    const { emailService } = booted.app;
    const original = emailService.sendEngineMail.bind(emailService);
    emailService.sendEngineMail = async (realm, to, mail: EngineMail, context) => {
      mails.set(to, [...(mails.get(to) ?? []), mail.template]);
      return original(realm, to, mail, context);
    };
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
    if (listDirectory !== undefined) await rm(listDirectory, { recursive: true, force: true });
    for (const key of SUITE_KEYS) delete process.env[key];
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || !booted) {
      ctx.skip();
      return;
    }
    await resetE2eState(booted.app);
    mails.clear();
    const realm = await booted.app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
  });

  function app(): FastifyInstance {
    if (!booted) throw new Error('server not booted');
    return booted.app;
  }

  async function query<Row extends Record<string, unknown>>(
    sql: string,
    params: unknown[]
  ): Promise<Row[]> {
    return (await app().dbPool.query<Row>(sql, params)).rows;
  }

  // ── Accounts ───────────────────────────────────────────────────────────

  /** A verified password account: its id and address. */
  async function passwordAccount(): Promise<{ userId: string; email: string }> {
    const email = `methods-${++accounts}-${randomUUID()}@example.com`;
    return { userId: await registerPasswordAccount(app(), email), email };
  }

  /** An account whose only credential is a passkey. */
  async function passkeyOnlyAccount(): Promise<string> {
    const created = await app().repositories.users.create(
      { realmId },
      {
        providerType: 'webauthn',
        externalSub: `cGFzc2tleS1vbmx5${++accounts}`,
        credentialData: passkeyData(accounts),
      }
    );
    return created.id;
  }

  async function bindPasskey(userId: string): Promise<void> {
    await app().repositories.userCredentials.create({
      userId,
      realmId,
      providerType: 'webauthn',
      externalSub: `cGFzc2tleS0${++accounts}`,
      credentialData: passkeyData(accounts),
    });
  }

  /** Bind an authenticator app as a set-up stores it: a secret sealed by the signer. */
  async function bindTotp(userId: string): Promise<void> {
    const { totpSecretContext } = await import('./helpers/totp-sign-in');
    const sealed = await app().signer.encrypt('api', {
      realmId,
      plaintext: new Uint8Array(randomBytes(20)),
      context: totpSecretContext(realmId, userId),
    });
    const bound = await app().repositories.userCredentials.upsertTotp({
      realmId,
      userId,
      credentialData: { secret: sealed, last_step: Math.floor(Date.now() / STEP_MS) - 2 },
      at: Date.now(),
    });
    expect(bound).toBeDefined();
  }

  /** A linked upstream identity of the account, as a link stores it. */
  async function bindUpstream(userId: string): Promise<void> {
    await app().repositories.userCredentials.create({
      userId,
      realmId,
      providerType: 'oidc_acme',
      externalSub: `upstream-${randomUUID()}`,
      credentialData: { kind: 'upstream', iss: 'https://idp.acme.example', verified: true },
    });
  }

  /** Issue a set of ten recovery codes, then use `used` of them. */
  async function issueRecoveryCodes(userId: string, used: number): Promise<void> {
    const codes = app().repositories.userRecoveryCodes;
    await codes.replaceSet({
      realmId,
      userId,
      codeHashes: Array.from({ length: 10 }, (_, i) => `hash-${i}-${randomUUID()}`),
      createdAt: Date.now(),
    });
    const unused = await codes.findUnused(realmId, userId);
    for (const code of unused.slice(0, used)) {
      await codes.markUsed({ realmId, userId, id: code.id, usedAt: Date.now() });
    }
  }

  /** A live browser session of the account, signed in with `amr`. */
  async function session(userId: string, amr: string[]): Promise<string> {
    const row = await app().repositories.sessions.create({
      realmId,
      userId,
      authTime: Date.now() - 1_000,
      amr,
      expiresAt: Date.now() + 3_600_000,
    });
    return row.id;
  }

  /** A refresh token of the account, at a client of the realm. */
  async function refreshToken(userId: string): Promise<string> {
    const [client] = await query<{ id: string }>(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
       VALUES ($1, $2, 'h', 'Relying party', '["https://rp.example/cb"]')
       RETURNING id::text AS id`,
      [realmId, `rp-${randomUUID()}`]
    );
    const row = await app().repositories.refreshTokens.create({
      tokenHash: randomBytes(32).toString('hex'),
      userId,
      oauthClientId: client?.id as string,
      familyCreatedAt: Date.now(),
      familySessionExpiresAt: null,
      authTime: Date.now() - 1_000,
      amr: ['pwd'],
      scopes: ['openid'],
      expiresAt: Date.now() + 600_000,
    });
    return row.id;
  }

  // ── Tokens and calls ───────────────────────────────────────────────────

  /** A sign-in `secondsAgo` old, as the token's `auth_time` keeps it: whole seconds, in ms. */
  function signedInAgo(secondsAgo: number): number {
    return (Math.floor(Date.now() / 1000) - secondsAgo) * 1000;
  }

  /** An account API token, as the code exchange mints it for the account console. */
  async function token(
    userId: string,
    claims: {
      authTime?: number;
      amr?: readonly string[];
      sid?: string;
      act?: { sub: string };
    } = {}
  ): Promise<string> {
    return app().jwtUtils.signAccessToken(
      { id: realmId },
      {
        sub: userId,
        clientId: 'account-console',
        aud: ACCOUNT_AUDIENCE,
        scope: 'qauth:account:read qauth:account:write',
        ...claims,
      }
    );
  }

  function read(bearer: string): Promise<LightMyRequestResponse> {
    return app().inject({
      method: 'GET',
      url: SIGN_IN_METHODS,
      headers: { authorization: `Bearer ${bearer}` },
    });
  }

  function change(bearer: string, body: unknown): Promise<LightMyRequestResponse> {
    return app().inject({
      method: 'POST',
      url: PASSWORD_CHANGE,
      headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' },
      payload: JSON.stringify(body),
    });
  }

  /** A fresh token with the password as the strongest factor, naming `sid` when given. */
  async function freshPasswordToken(userId: string, sid?: string): Promise<string> {
    return token(userId, {
      authTime: signedInAgo(5),
      amr: ['pwd'],
      ...(sid === undefined ? {} : { sid }),
    });
  }

  async function passwordHashOf(userId: string): Promise<string | undefined> {
    const [row] = await query<{ hash: string }>(
      "SELECT credential_data->>'password_hash' AS hash FROM user_credentials WHERE user_id = $1 AND provider_type = 'password'",
      [userId]
    );
    return row?.hash;
  }

  async function eventsOf(type: string, userId: string): Promise<Record<string, unknown>[]> {
    return query(
      'SELECT data, client_id FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
      [type, userId]
    );
  }

  /** The time a `changedAt` names, checked to lie between `from` and now. */
  function expectTimeBetween(value: unknown, from: number): void {
    expect(typeof value).toBe('string');
    const at = Date.parse(value as string);
    expect(at).toBeGreaterThanOrEqual(from - 1_000);
    expect(at).toBeLessThanOrEqual(Date.now());
  }

  // ── The read ───────────────────────────────────────────────────────────

  describe('GET /sign-in-methods', () => {
    it('answers for a password-only account, and takes an act-chain token', async () => {
      const before = Date.now();
      const { userId } = await passwordAccount();

      const response = await read(await token(userId));
      expect(response.statusCode, response.body).toBe(200);
      expect(response.headers['cache-control']).toBe('no-store');
      const body = response.json();
      expect(body).toEqual({
        password: { set: true, changedAt: expect.any(String) },
        passkeys: { count: 0 },
        totp: { enabled: false },
        recoveryCodes: { remaining: 0 },
        linkedAccounts: { count: 0 },
        hasContactAddress: true,
        freshAuthenticationFactor: 'pwd',
      });
      // The registration set the password.
      expectTimeBetween(body.password.changedAt, before);

      // A read takes a delegated token (ADR-019 Decision 7).
      const delegated = await read(await token(userId, { act: { sub: 'support-agent' } }));
      expect(delegated.statusCode, delegated.body).toBe(200);
      expect(delegated.json()).toEqual(body);
    });

    it('answers no set time for a password set before the server recorded one', async () => {
      const { userId } = await passwordAccount();
      // A credential as a release before #1107 wrote it; a later write to it
      // (here the address's verification) is no time the password was set.
      await query(
        "UPDATE user_credentials SET credential_data = credential_data - 'password_set_at', updated_at = $2 WHERE user_id = $1 AND provider_type = 'password'",
        [userId, Date.now()]
      );

      const response = await read(await token(userId));
      expect(response.statusCode, response.body).toBe(200);
      expect(response.json()).toMatchObject({ password: { set: true, changedAt: null } });
    });

    it('answers for an account with a passkey and a linked upstream account', async () => {
      const { userId } = await passwordAccount();
      await bindPasskey(userId);
      await bindUpstream(userId);

      const response = await read(await token(userId));
      expect(response.statusCode, response.body).toBe(200);
      expect(response.json()).toMatchObject({
        password: { set: true },
        passkeys: { count: 1 },
        totp: { enabled: false },
        recoveryCodes: { remaining: 0 },
        linkedAccounts: { count: 1 },
        hasContactAddress: true,
        freshAuthenticationFactor: 'pop',
      });
    });

    it('answers for an account with an authenticator app and its recovery codes', async () => {
      const { userId } = await passwordAccount();
      await bindTotp(userId);
      await issueRecoveryCodes(userId, 1);

      const response = await read(await token(userId));
      expect(response.statusCode, response.body).toBe(200);
      expect(response.json()).toMatchObject({
        password: { set: true },
        passkeys: { count: 0 },
        totp: { enabled: true },
        recoveryCodes: { remaining: 9 },
        linkedAccounts: { count: 0 },
        hasContactAddress: true,
        freshAuthenticationFactor: 'otp',
      });
    });

    it('answers for a passkey-only account: no password, no contact address', async () => {
      const userId = await passkeyOnlyAccount();

      const response = await read(await token(userId));
      expect(response.statusCode, response.body).toBe(200);
      expect(response.json()).toEqual({
        password: { set: false, changedAt: null },
        passkeys: { count: 1 },
        totp: { enabled: false },
        recoveryCodes: { remaining: 0 },
        linkedAccounts: { count: 0 },
        hasContactAddress: false,
        freshAuthenticationFactor: 'pop',
      });

      // Setting a first password is no account API operation.
      const set = await change(await token(userId, { authTime: signedInAgo(5), amr: ['pop'] }), {
        currentPassword: E2E_PASSWORD,
        newPassword: NEW_PASSWORD,
      });
      expect(set.statusCode, set.body).toBe(404);
      expect(set.json()).toMatchObject({ code: 'not_found' });
    });
  });

  // ── The change ─────────────────────────────────────────────────────────

  describe('POST /password/change', () => {
    it('refuses a wrong current password with invalid_current_password, counted on the ladder', async () => {
      const { userId } = await passwordAccount();
      const stored = await passwordHashOf(userId);

      const refused = await change(await freshPasswordToken(userId), {
        currentPassword: 'not-the-password-of-this-account',
        newPassword: NEW_PASSWORD,
      });
      expect(refused.statusCode, refused.body).toBe(400);
      expect(refused.headers['content-type']).toMatch(/^application\/problem\+json/);
      // Every account API answer, an error too, is kept out of caches.
      expect(refused.headers['cache-control']).toBe('no-store');
      expect(refused.json()).toMatchObject({
        code: 'invalid_current_password',
        type: 'https://docs.qauth.dev/reference/problem-types/#invalid-current-password',
        status: 400,
      });

      // The account's password ladder counted it, as a failed sign-in.
      const counters = await app().redis.keys('sign-in-ladder:*:password');
      expect(counters).toHaveLength(1);
      expect(await app().redis.hget(counters[0] as string, 'n')).toBe('1');
      // Nothing changed.
      expect(await passwordHashOf(userId)).toBe(stored);
      expect(await eventsOf(PASSWORD_CHANGED, userId)).toEqual([]);
    });

    it('refuses a weak new password and a listed one with weak_password and its reasons', async () => {
      const { userId, email } = await passwordAccount();
      const stored = await passwordHashOf(userId);
      const bearer = await freshPasswordToken(userId);

      // The policy's own reasons for it, as registration gives them.
      const weak = 'aaaaaaaaaaaaaaaa';
      const realm = await app().repositories.realms.findById(realmId);
      if (!realm) throw new Error('default realm missing');
      const { accountPoliciesOf } = await import('./helpers/account-policies');
      const policies = accountPoliciesOf(app(), realm);
      const checked = app()
        .passwordValidators.forPolicy({
          minLength: policies.passwordMinLength,
          minScore: policies.passwordMinScore,
        })
        .check(weak, { email, serviceName: policies.serviceName, realmName: realm.name });
      if (checked.valid) throw new Error('the weak password meets the policy');

      const tooWeak = await change(bearer, { currentPassword: E2E_PASSWORD, newPassword: weak });
      expect(tooWeak.statusCode, tooWeak.body).toBe(422);
      expect(tooWeak.json()).toMatchObject({ code: 'weak_password', reasons: checked.reasons });
      // The reasons alone: no prose field errors.
      expect(tooWeak.json()).not.toHaveProperty('errors');

      // A password on the realm's breach list, once the realm reads the list.
      const current = await app().policyStore.get(realmId);
      if (current === undefined) throw new Error('no policies for the default realm');
      await app().policyStore.update(
        realmId,
        { password: { breachListSource: 'local' } },
        { expectedVersion: current.version }
      );
      app().realmHostCache.clear();
      const listed = await change(bearer, {
        currentPassword: E2E_PASSWORD,
        newPassword: LISTED_PASSWORD,
      });
      expect(listed.statusCode, listed.body).toBe(422);
      expect(listed.json()).toMatchObject({ code: 'weak_password', reasons: ['breached'] });

      expect(await passwordHashOf(userId)).toBe(stored);
      expect(await eventsOf(PASSWORD_CHANGED, userId)).toEqual([]);
    });

    it('challenges a stale sign-in and refuses an act-chain token', async () => {
      const { userId } = await passwordAccount();

      const stale = await change(
        await token(userId, { authTime: signedInAgo(301), amr: ['pwd'] }),
        { currentPassword: E2E_PASSWORD, newPassword: NEW_PASSWORD }
      );
      expect(stale.statusCode, stale.body).toBe(401);
      expect(stale.headers['www-authenticate']).toBe(
        'Bearer error="insufficient_user_authentication", max_age="300"'
      );
      expect(stale.json()).toMatchObject({
        code: 'insufficient_user_authentication',
        max_age: 300,
      });

      const delegated = await change(
        await token(userId, {
          authTime: signedInAgo(5),
          amr: ['pwd'],
          act: { sub: 'support-agent' },
        }),
        { currentPassword: E2E_PASSWORD, newPassword: NEW_PASSWORD }
      );
      expect(delegated.statusCode, delegated.body).toBe(403);
      expect(delegated.json()).toMatchObject({ code: 'delegated_token_refused' });

      expect(
        (
          await query<{ data: Record<string, unknown> }>(
            'SELECT data FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
            [REFUSED, userId]
          )
        ).map((row) => row.data)
      ).toEqual([
        { operation: 'account.password.change', reason: 'authentication_too_old', maxAge: 300 },
        { operation: 'account.password.change', reason: 'delegated_token' },
      ]);
      expect(await eventsOf(PASSWORD_CHANGED, userId)).toEqual([]);
    });

    it("changes it: the other sessions and the refresh tokens end, the token's own session keeps working", async () => {
      const { userId, email } = await passwordAccount();
      const own = await session(userId, ['pwd']);
      const other = await session(userId, ['pwd']);
      const refresh = await refreshToken(userId);
      const bearer = await freshPasswordToken(userId, own);
      const before = Date.now();

      const changed = await change(bearer, {
        currentPassword: E2E_PASSWORD,
        newPassword: NEW_PASSWORD,
      });
      expect(changed.statusCode, changed.body).toBe(204);
      expect(changed.body).toBe('');
      expect(changed.headers['cache-control']).toBe('no-store');

      // The new password is the account's.
      const hash = await passwordHashOf(userId);
      if (hash === undefined) throw new Error('the password is gone');
      expect(await app().passwordHasher.verifyPassword(hash, NEW_PASSWORD)).toBe(true);
      // The other session ended; the token's own did not.
      const sessions = await query<{
        id: string;
        revoked_at: string | null;
        revoked_reason: string | null;
      }>('SELECT id::text AS id, revoked_at, revoked_reason FROM sessions WHERE user_id = $1', [
        userId,
      ]);
      expect(sessions.find((row) => row.id === own)).toMatchObject({ revoked_at: null });
      expect(sessions.find((row) => row.id === other)).toMatchObject({
        revoked_at: expect.anything(),
        revoked_reason: 'reset',
      });
      // As the session store reads them: the own session lives, the other is gone.
      expect(await app().sessionService.get({ realmId, sid: own })).not.toBeNull();
      expect(await app().sessionService.get({ realmId, sid: other })).toBeNull();
      // Every refresh token ended.
      expect(
        await query('SELECT revoked, revoked_reason FROM refresh_tokens WHERE id = $1::uuid', [
          refresh,
        ])
      ).toEqual([{ revoked: true, revoked_reason: 'password_changed' }]);
      // Recorded as the hosted page records it, naming the client it came through.
      expect(await eventsOf(PASSWORD_CHANGED, userId)).toEqual([
        { data: {}, client_id: 'account-console' },
      ]);
      await vi.waitFor(() => expect(mails.get(email) ?? []).toContain('password_changed'), {
        timeout: 5_000,
        interval: 20,
      });

      // The token's own session keeps working: the read answers, with the new time.
      const after = await read(bearer);
      expect(after.statusCode, after.body).toBe(200);
      expectTimeBetween(after.json().password.changedAt, before);
      // The old password is no longer the current one.
      const again = await change(await freshPasswordToken(userId, own), {
        currentPassword: E2E_PASSWORD,
        newPassword: 'Willow-Anvil-Meadow-Sextant-26#',
      });
      expect(again.statusCode, again.body).toBe(400);
      expect(again.json()).toMatchObject({ code: 'invalid_current_password' });
    });

    it('refuses a body the contract does not describe before checking any password', async () => {
      const { userId } = await passwordAccount();
      const bearer = await freshPasswordToken(userId);

      for (const body of [
        { currentPassword: E2E_PASSWORD },
        { currentPassword: E2E_PASSWORD, newPassword: NEW_PASSWORD, extra: true },
        { currentPassword: '', newPassword: NEW_PASSWORD },
        { currentPassword: E2E_PASSWORD, newPassword: 'x'.repeat(257) },
      ]) {
        const refused = await change(bearer, body);
        expect(refused.statusCode, refused.body).toBe(400);
        expect(refused.json()).toMatchObject({ code: 'validation_error' });
      }
      expect(await app().redis.keys('sign-in-ladder:*:password')).toEqual([]);
    });
  });
});
