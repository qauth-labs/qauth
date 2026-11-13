import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
import * as accountContract from '@qauth-labs/shared-account-contract';
import { type ProofOfWorkParams, solveProofOfWork } from '@qauth-labs/shared-interaction-client';
import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  decodeJwtClaims,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import type { BackgroundTasks } from './helpers/background-tasks';
import type { InteractionEngines } from './helpers/interaction-engines';

/**
 * THE RECOVERY CODES ON THE HOSTED PAGES (#649; ADR-017 Decisions 7 and 8,
 * ADR-018 §3; `graphs/flows/core/recovery-code`), end to end against real
 * Postgres and Redis, with INTERACTION_UI_ENABLED on.
 *
 * The account is a password account with a passkey bound: no step of the
 * passkey is served yet, so after the password the downgrade rule offers the
 * `recovery_code` step alone. It proves the issue's integration criteria:
 *
 * - A code stands in for the passkey once, adds no `amr` value (the sign-in
 *   the engine finishes with proves `pwd` alone), and is refused after; its
 *   use is recorded and mailed.
 * - Regenerating a set invalidates every code of the old one and mails the
 *   user.
 * - The wrong codes are counted on the account, across transactions and IPs;
 *   a right password never clears the count; from 5 failures the bot
 *   challenge comes first and an attempt inside the wait gets `429`.
 * - At 100 wrong codes in a row the user is mailed and the security log
 *   records it, once a day.
 *
 * The three notices go out with no realm setting in their way: the registry
 * lets no realm switch them off (`realmMaySwitchOff: false`, its own test).
 * An MFA policy and the FiPA endpoint are not in this server yet: the
 * engine's tests prove a code never meets the policy and that FiPA answers
 * `redirect_to_web`.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
const CLIENT_ID = 'recovery-codes-notes-app';
const REDIRECT_URI = 'https://client.example.com/callback';
// `qauth:account:write`: the scope the guarded account operations need (#933),
// issued because the client lists the account API's audience.
const SCOPES = ['openid', 'email', 'qauth:account:write'];
const EMAIL = 'recovery-owner@example.test';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const RECOVERY_CODE = stepUrn('recovery_code');
const CAPTCHA = stepUrn('captcha');
const CONSENT = stepUrn('consent');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
/** An interaction id: 43 base64url characters. */
const INTERACTION_ID = /^[A-Za-z0-9_-]{43}$/;
/** Three end-user addresses in three /24 buckets. */
const IP_A = '203.0.113.10';
const IP_B = '198.51.100.20';
const IP_C = '192.0.2.30';
/** A code of the right form that no set holds. */
const WRONG = 'zzzz-zzzz-zzzz-zzzz';
const USED_EVENT = 'user.recovery_code_used';
const FAILED_EVENT = 'user.recovery_codes_failed';
/** The account API's audience, which the app lists for its console's calls (#663). */
const ACCOUNT_AUDIENCE = accountContract.ACCOUNT_API_AUDIENCE;
/**
 * The account operations the suite mounts behind the account API's guard
 * (#663), where no route serves them yet; the password change is served
 * (#1107) and called where it is.
 */
const GUARDED = ['account.passkeys.delete'] as const;
/** The guarded operations the suite calls: its probes, and the served password change. */
type Called = (typeof GUARDED)[number] | 'account.password.change';
const PASSKEY_ID = '00000000-0000-4000-8000-0000000000e1';

/** Where a guarded operation is called: its contract path, its parameter filled. */
function guardedUrl(id: Called): string {
  const { path } = accountContract.operationNamed(id);
  return `${accountContract.ACCOUNT_API_PREFIX}${path.replace(/\{[^}]+\}/g, PASSKEY_ID)}`;
}
/** The background tasks of the engines this suite builds: run now, failures dropped. */
const TASKS: BackgroundTasks = {
  run: (task) => {
    void Promise.resolve()
      .then(task)
      .catch(() => undefined);
  },
};

/** A mail the engine sent: its template and the count of codes it reports, if any. */
interface SentMail {
  readonly template: string;
  readonly unusedCodes?: number;
}

/** The step view the ceremony page reads. */
interface StepView {
  readonly step: string;
  readonly csrf: string;
  readonly alternatives?: readonly string[];
  readonly params?: Record<string, unknown>;
  readonly error?: string;
}

/** A sign-in in progress: its browser, its address and its interaction. */
interface SignIn {
  readonly jar: CookieJar;
  readonly ip: string;
  readonly id: string;
  readonly verifier: string;
}

describe('the recovery codes on the hosted pages (#649, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';
  let clientRowId = '';
  let engines: InteractionEngines | undefined;
  /** The engine mails, by address, in order. */
  const mails = new Map<string, SentMail[]>();

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer(
      {
        ...baseEnvironment(infra, await generateJwtPem()),
        INTERACTION_UI_ENABLED: 'true',
        // Each test registers its account through POST /auth/register.
        REGISTRATION_RATE_LIMIT: '10000',
      },
      {
        // The account operations a recovery code may and may not reach,
        // behind the account API's guard with the contract's rules (#663).
        // No route serves them yet; the guard is the app's own module.
        routes: async (scope) => {
          const { accountOperation } = await import('./helpers/account-operation-guard');
          for (const id of GUARDED) {
            const operation = accountContract.operationNamed(id);
            scope.route({
              method: operation.method.toUpperCase() as 'POST' | 'DELETE',
              url: `${accountContract.ACCOUNT_API_PREFIX}${operation.path.replace(/\{([^}]+)\}/g, ':$1')}`,
              preValidation: accountOperation({
                operationId: operation.id,
                operationClass: operation.class,
                permission: operation.permission,
                freshAuthentication: operation.freshAuthentication,
                actChain: operation.actChain,
              }).guard,
              config: { surface: 'api' },
              handler: async () => ({ ran: id }),
            });
          }
        },
      }
    );
    const { emailService } = booted.app;
    const original = emailService.sendEngineMail.bind(emailService);
    emailService.sendEngineMail = async (realm, to, mail: EngineMail, context) => {
      const unusedCodes =
        'unusedCodes' in mail && typeof mail.unusedCodes === 'number'
          ? mail.unusedCodes
          : undefined;
      mails.set(to, [
        ...(mails.get(to) ?? []),
        { template: mail.template, ...(unusedCodes === undefined ? {} : { unusedCodes }) },
      ]);
      return original(realm, to, mail, context);
    };
    // The account API's regeneration (ACC-02, #687) calls these. Imported
    // after the boot, as the harness imports the app: the module reads the
    // environment the boot sets, and shares the app's module instances.
    const { createInteractionEngines } = await import('./helpers/interaction-engines');
    engines = createInteractionEngines(booted.app, { tasks: TASKS });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  function recoveryCodes(): InteractionEngines['recoveryCodes'] {
    if (engines === undefined) throw new Error('engines not built');
    return engines.recoveryCodes;
  }

  async function query<Row extends Record<string, unknown>>(
    sql: string,
    params: unknown[] = []
  ): Promise<Row[]> {
    const { rows } = await server().dbPool.query<Row>(sql, params);
    return rows;
  }

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    const app = booted.app;
    await resetE2eState(app);
    mails.clear();
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
    const client = await app.repositories.oauthClients.create({
      realmId,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Recovery codes notes app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      // The account console's audience, issued only when a request names
      // it (#509): every other token's audience stays the client id.
      audience: [ACCOUNT_AUDIENCE],
      enabled: true,
      requirePkce: true,
      // A seeded client: its redirect URI receives authorization errors.
      provisionedByOperator: true,
    });
    clientRowId = client.id;
  }, 120_000);

  /**
   * The account: a password, a passkey bound and a set of recovery codes,
   * with the client's consent given. Returns its id and its codes as shown.
   */
  async function passkeyAccount(): Promise<{ userId: string; codes: readonly string[] }> {
    const userId = await registerPasswordAccount(server(), EMAIL);
    await server().repositories.userCredentials.create({
      userId,
      realmId,
      providerType: 'webauthn',
      externalSub: 'cmVjb3Zlcnktb3duZXI',
      credentialData: {
        public_key: 'pQECAyYgASFYIK_voW-Xypst',
        algorithm: -7,
        sign_count: 0,
        transports: ['internal'],
        backup_eligible: true,
        backed_up: true,
        aaguid: '00000000-0000-0000-0000-000000000000',
        rp_id: 'auth.example.com',
        user_handle: 'dXNlci1oYW5kbGU',
        nickname: null,
        created_at: Date.now(),
        last_used_at: null,
        sign_counter_regressed_at: null,
      },
    });
    await server().repositories.oauthConsents.upsertGrant(realmId, userId, clientRowId, SCOPES);
    const issued = await recoveryCodes().issue({ realmId, userId });
    if (issued === null) throw new Error('no set issued');
    const { codes } = issued;
    mails.clear();
    return { userId, codes };
  }

  /** The path of a redirect, without the realm origin. */
  function locationOf(response: LightMyRequestResponse): string {
    expect([302, 303], response.body).toContain(response.statusCode);
    const location = String(response.headers['location']);
    return location.startsWith(`${ORIGIN}/`) ? location.slice(ORIGIN.length) : location;
  }

  /** The step read, as the ceremony app's server makes it: the id alone, no cookie. */
  async function read(id: string): Promise<StepView> {
    const response = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}`,
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json();
  }

  /** Answer the current step with a form post from the ceremony page, from the sign-in's address. */
  async function answer(
    signIn: Pick<SignIn, 'jar' | 'ip' | 'id'>,
    type: string,
    fields: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    const { csrf } = await read(signIn.id);
    const response = await server().inject({
      method: 'POST',
      remoteAddress: signIn.ip,
      url: `${INTERACTION_API_PREFIX}/${signIn.id}/answer`,
      headers: { ...FORM, ...SAME_ORIGIN, cookie: signIn.jar.header() ?? '' },
      payload: new URLSearchParams({ type, csrf, ...fields }).toString(),
    });
    signIn.jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /**
   * A new sign-in from `ip`, answered up to the recovery-code step, for a code
   * bound to the RFC 8707 `resource` given.
   */
  async function atRecoveryCodeStep(ip: string, resource?: string): Promise<SignIn> {
    const jar = new CookieJar();
    const { verifier, challenge } = pkcePair();
    const authorized = await server().inject({
      method: 'GET',
      remoteAddress: ip,
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'recovery-state',
        ...(resource === undefined ? {} : { resource }),
      }).toString()}`,
    });
    jar.absorb(authorized.headers['set-cookie']);
    const path = locationOf(authorized);
    expect(path.startsWith(CEREMONY_PAGE_PREFIX), path).toBe(true);
    const id = path.slice(CEREMONY_PAGE_PREFIX.length);
    expect(id).toMatch(INTERACTION_ID);
    const signIn: SignIn = { jar, ip, id, verifier };

    const identified = await answer(signIn, IDENTIFIER, { login_hint: EMAIL });
    expect(identified.statusCode, identified.body).toBe(303);
    const signedIn = await answer(signIn, PASSWORD, { password: E2E_PASSWORD });
    expect(signedIn.statusCode, signedIn.body).toBe(303);
    // The passkey cannot be asked for here: the code is the one way on.
    const view = await read(id);
    expect(view.step).toBe(RECOVERY_CODE);
    expect(view.alternatives ?? []).toEqual([]);
    return signIn;
  }

  /**
   * The bot challenge an account past its free failures meets before its
   * next code is read: the answer brings the challenge, which is solved.
   */
  async function throughChallenge(signIn: SignIn): Promise<void> {
    const challenged = await answer(signIn, RECOVERY_CODE, { recovery_code: WRONG });
    expect(challenged.statusCode, challenged.body).toBe(303);
    const offered = await read(signIn.id);
    expect(offered.step).toBe(CAPTCHA);
    const solution = await solveProofOfWork(
      offered.params?.[CAPTCHA] as unknown as ProofOfWorkParams
    );
    const passed = await answer(signIn, CAPTCHA, { captcha_token: solution });
    expect(passed.statusCode, passed.body).toBe(303);
    expect((await read(signIn.id)).step).toBe(RECOVERY_CODE);
  }

  /** The code a finished interaction's redirect carries, through consent if asked. */
  async function codeOf(signIn: SignIn, response: LightMyRequestResponse): Promise<string> {
    let location = String(response.headers['location']);
    if (!location.startsWith(REDIRECT_URI)) {
      const path = locationOf(response);
      const consentId = path.slice(CEREMONY_PAGE_PREFIX.length);
      expect((await read(consentId)).step).toBe(CONSENT);
      const allowed = await answer({ ...signIn, id: consentId }, CONSENT, { decision: 'allow' });
      expect(allowed.statusCode, allowed.body).toBe(303);
      location = String(allowed.headers['location']);
    }
    const callback = new URL(location);
    expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
    const code = callback.searchParams.get('code');
    if (code === null) throw new Error(`no code at ${location}`);
    return code;
  }

  async function exchange(code: string, verifier: string): Promise<LightMyRequestResponse> {
    return server().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
      }).toString(),
    });
  }

  async function eventsOf(type: string, userId: string): Promise<Record<string, unknown>[]> {
    const rows = await query<{ data: Record<string, unknown> }>(
      'SELECT data FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
      [`urn:qauth:event:${type}:v1-rc.0`, userId]
    );
    return rows.map((row) => row.data);
  }

  /** The recovery-code counter of the account's failure ladder (`ladderAccountCounterKey`). */
  function counterKey(userId: string): string {
    return `sign-in-ladder:{${realmId}:user:${userId}}:recovery_code`;
  }

  /** The account's count of wrong codes in a row, or `null` with none. */
  async function failures(userId: string): Promise<string | null> {
    return server().redis.hget(counterKey(userId), 'n');
  }

  /** The templates mailed to `to` once `count` of `template` went out. */
  async function mailedWith(to: string, template: string, count: number): Promise<string[]> {
    const deadline = performance.now() + 5_000;
    const sent = () => (mails.get(to) ?? []).filter((mail) => mail.template === template);
    while (sent().length < count && performance.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(sent()).toHaveLength(count);
    return (mails.get(to) ?? []).map((mail) => mail.template);
  }

  it('signs in with a code in place of the passkey, once, adding no amr value', async () => {
    const { userId, codes } = await passkeyAccount();
    const first = codes[0] as string;

    // The set is stored as ten salted hashes, never as the codes.
    const stored = await query<{ code_hash: string; used_at: string | null }>(
      'SELECT code_hash, used_at FROM user_recovery_codes WHERE user_id = $1',
      [userId]
    );
    expect(stored).toHaveLength(10);
    for (const row of stored) expect(row.code_hash).toMatch(/^\$argon2id\$/);
    const rows = JSON.stringify(stored);
    for (const code of codes) expect(rows).not.toContain(code.replaceAll('-', ''));

    const signIn = await atRecoveryCodeStep(IP_A);
    // The hosted page asks for it.
    const page = await server().inject({ method: 'GET', url: `/ui/recovery-code/${signIn.id}` });
    expect(page.statusCode, page.body).toBe(200);
    expect(page.headers['cache-control']).toBe('no-store');
    expect(page.body).toContain('name="recovery_code"');

    // The decision the answer route makes of the engine's result: the
    // sign-in it finishes with, and the `amr` the interaction carries on.
    const decided = vi.spyOn(await import('./helpers/interaction-engines'), 'decisionOf');
    // Typed in capitals with spaces: the same code.
    const done = await answer(signIn, RECOVERY_CODE, {
      recovery_code: first.toUpperCase().replaceAll('-', ' '),
    });
    expect(done.statusCode, done.body).toBe(303);
    // The sign-in proved the password alone: no value for the code, and
    // never mfa. The session it starts says it took a code (#663), where the
    // account API's fresh-authentication guard reads it.
    expect(decided.mock.results.map((result) => result.value)).toEqual([
      {
        kind: 'authenticated',
        signIn: expect.objectContaining({ userId, amr: ['pwd'], recoveryCodeUsed: true }),
      },
    ]);
    expect(
      await query<{ recovery_code_used: boolean; amr: string[] }>(
        'SELECT recovery_code_used, amr FROM sessions WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1',
        [userId]
      )
    ).toEqual([{ recovery_code_used: true, amr: ['pwd'] }]);
    const tokens = await exchange(await codeOf(signIn, done), signIn.verifier);
    expect(tokens.statusCode, tokens.body).toBe(200);
    expect(decodeJwtClaims((tokens.json() as { id_token: string }).id_token)['sub']).toBe(userId);

    // Its use is recorded with the take, and the user is told what is left.
    expect(await eventsOf(USED_EVENT, userId)).toEqual([{ remaining: 9 }]);
    await mailedWith(EMAIL, 'recovery_code_used', 1);
    expect((mails.get(EMAIL) ?? []).find((mail) => mail.template === 'recovery_code_used')).toEqual(
      { template: 'recovery_code_used', unusedCodes: 9 }
    );
    expect(
      await query('SELECT 1 FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NOT NULL', [
        userId,
      ])
    ).toHaveLength(1);

    // The same code again, in a new sign-in: refused.
    const again = await atRecoveryCodeStep(IP_B);
    const refused = await answer(again, RECOVERY_CODE, { recovery_code: first });
    expect(refused.statusCode, refused.body).toBe(303);
    expect(await read(again.id)).toMatchObject({
      step: RECOVERY_CODE,
      error: 'invalid_credentials',
    });
    const refusedPage = await server().inject({
      method: 'GET',
      url: `/ui/recovery-code/${again.id}`,
    });
    expect(refusedPage.body).toContain('That code did not work');
    expect(await eventsOf(USED_EVENT, userId)).toHaveLength(1);
    expect(await failures(userId)).toBe('1');
  });

  it('takes the code to the account API, through sid: a rebind passes, nothing else does (#663)', async () => {
    const { userId, codes } = await passkeyAccount();
    await server().repositories.oauthConsents.upsertGrant(realmId, userId, clientRowId, SCOPES, [
      ACCOUNT_AUDIENCE,
    ]);
    const signIn = await atRecoveryCodeStep(IP_A, ACCOUNT_AUDIENCE);
    const done = await answer(signIn, RECOVERY_CODE, { recovery_code: codes[0] as string });
    expect(done.statusCode, done.body).toBe(303);
    const tokens = await exchange(await codeOf(signIn, done), signIn.verifier);
    expect(tokens.statusCode, tokens.body).toBe(200);

    // The account API's token names the session the sign-in started, which
    // records the code; its `amr` holds the password alone.
    const accessToken = (tokens.json() as { access_token: string }).access_token;
    const [session] = await query<{ id: string }>(
      'SELECT id FROM sessions WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1',
      [userId]
    );
    expect(decodeJwtClaims(accessToken)).toMatchObject({
      aud: ACCOUNT_AUDIENCE,
      sub: userId,
      amr: ['pwd'],
      sid: session?.id,
      // The account scope, issued to a client that lists the audience (#933).
      scope: SCOPES.join(' '),
    });

    const call = (id: Called) =>
      server().inject({
        method: accountContract.operationNamed(id).method.toUpperCase() as 'POST' | 'DELETE',
        url: guardedUrl(id),
        headers: { authorization: `Bearer ${accessToken}` },
      });
    // Removing the lost passkey, one half of the rebind, takes the code.
    const rebind = await call('account.passkeys.delete');
    expect(rebind.statusCode, rebind.body).toBe(200);
    // Changing the password does not: it needs the passkey itself. The
    // served route's guard refuses it before reading the body.
    const change = await call('account.password.change');
    expect(change.statusCode, change.body).toBe(401);
    expect(change.headers['www-authenticate']).toBe(
      'Bearer error="insufficient_user_authentication", max_age="0"'
    );
    expect(await eventsOf('request.account_operation_refused', userId)).toEqual([
      {
        operation: 'account.password.change',
        reason: 'strongest_factor_missing',
        requiredFactor: 'pop',
        maxAge: 0,
      },
    ]);
  });

  it('invalidates every code of the old set when the set is regenerated, and tells the user', async () => {
    const { userId, codes: old } = await passkeyAccount();

    const { codes: fresh } = await recoveryCodes().regenerate({ realmId, userId });

    expect(fresh).toHaveLength(10);
    expect(fresh.filter((code) => old.includes(code))).toEqual([]);
    expect(await mailedWith(EMAIL, 'recovery_codes_regenerated', 1)).toEqual([
      'recovery_codes_regenerated',
    ]);
    expect(
      await query('SELECT 1 FROM user_recovery_codes WHERE user_id = $1', [userId])
    ).toHaveLength(10);
    // Every code of the old set is refused against what is stored now.
    const redeemed = await Promise.all(
      old.map((code) => recoveryCodes().redeem({ realmId, userId, clientId: CLIENT_ID, code }))
    );
    expect(redeemed).toEqual(old.map(() => ({ kind: 'refused' })));

    // And at sign-in: an old code is refused, a new one is taken.
    const signIn = await atRecoveryCodeStep(IP_A);
    const refused = await answer(signIn, RECOVERY_CODE, { recovery_code: old[0] as string });
    expect(refused.statusCode, refused.body).toBe(303);
    expect(await read(signIn.id)).toMatchObject({ error: 'invalid_credentials' });
    const done = await answer(signIn, RECOVERY_CODE, { recovery_code: fresh[0] as string });
    expect(done.statusCode, done.body).toBe(303);
    await codeOf(signIn, done);
    expect(await eventsOf(USED_EVENT, userId)).toEqual([{ remaining: 9 }]);
  });

  it('counts wrong codes on the account across transactions and IPs, and a right password never clears the count', async () => {
    const { userId, codes } = await passkeyAccount();
    const right = codes[0] as string;
    // One instant for the whole run, moved by hand: the wait the 5th wrong
    // code sets (one second) neither passes nor is missed by chance.
    let now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);

    // Transaction A, from one address: three wrong codes.
    const a = await atRecoveryCodeStep(IP_A);
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const refused = await answer(a, RECOVERY_CODE, { recovery_code: WRONG });
      expect(refused.statusCode, refused.body).toBe(303);
      expect(await read(a.id)).toMatchObject({ step: RECOVERY_CODE, error: 'invalid_credentials' });
    }
    expect(await failures(userId)).toBe('3');

    // Transaction B, from another address: the right password leaves the
    // count, and two more wrong codes make it 5.
    const b = await atRecoveryCodeStep(IP_B);
    expect(await failures(userId)).toBe('3');
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      const refused = await answer(b, RECOVERY_CODE, { recovery_code: WRONG });
      expect(refused.statusCode, refused.body).toBe(303);
    }
    expect(await failures(userId)).toBe('5');

    // Transaction C, a third address: the right password again leaves the
    // count. The account is past its free failures, so the bot challenge
    // comes before the next code is read (PRO-12).
    const c = await atRecoveryCodeStep(IP_C);
    expect(await failures(userId)).toBe('5');
    await throughChallenge(c);
    expect(await failures(userId)).toBe('5');

    // Inside the wait the right code is refused, neither checked nor counted:
    // no address is exempt.
    const waited = await answer(c, RECOVERY_CODE, { recovery_code: right });
    expect(waited.statusCode, waited.body).toBe(429);
    expect(waited.headers['retry-after']).toBe('1');
    expect(await failures(userId)).toBe('5');
    expect(await eventsOf(USED_EVENT, userId)).toEqual([]);

    // After it the right code is taken, and the count is gone.
    now += 2_000;
    const done = await answer(c, RECOVERY_CODE, { recovery_code: right });
    expect(done.statusCode, done.body).toBe(303);
    await codeOf(c, done);
    expect(await failures(userId)).toBeNull();
    expect(await eventsOf(USED_EVENT, userId)).toEqual([{ remaining: 9 }]);
  });

  it('tells the user and records it at 100 wrong codes in a row, once a day', async () => {
    const { userId } = await passkeyAccount();
    const key = counterKey(userId);
    // 99 wrong codes counted before, the last wait over.
    await server().redis.hset(key, {
      n: '99',
      until: String(Date.now() - 1_000),
      run: 'seeded-run',
    });

    const signIn = await atRecoveryCodeStep(IP_A);
    await throughChallenge(signIn);
    const hundredth = await answer(signIn, RECOVERY_CODE, { recovery_code: WRONG });
    expect(hundredth.statusCode, hundredth.body).toBe(303);
    expect(await read(signIn.id)).toMatchObject({ error: 'invalid_credentials' });
    expect(await failures(userId)).toBe('100');
    expect(await mailedWith(EMAIL, 'recovery_codes_failed', 1)).toEqual(['recovery_codes_failed']);
    expect(await eventsOf(FAILED_EVENT, userId)).toEqual([{}]);

    // The 101st, its wait skipped: the day's notice is told already.
    await server().redis.hset(key, 'until', String(Date.now() - 1_000));
    await throughChallenge(signIn);
    await server().redis.hset(key, 'until', String(Date.now() - 1_000));
    const next = await answer(signIn, RECOVERY_CODE, { recovery_code: WRONG });
    expect(next.statusCode, next.body).toBe(303);
    expect(await failures(userId)).toBe('101');
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect((mails.get(EMAIL) ?? []).map((mail) => mail.template)).toEqual([
      'recovery_codes_failed',
    ]);
    expect(await eventsOf(FAILED_EVENT, userId)).toEqual([{}]);
  });
});
