import { createHmac, randomBytes } from 'node:crypto';

import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
import {
  base32Encode,
  type MfaPolicyReader,
  type TotpCredentials,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
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
 * TOTP AS A SECOND FACTOR ON THE HOSTED PAGES (#653; ADR-017 Decisions 7
 * and 8, ADR-020 §3; `graphs/flows/core/totp`), end to end against real
 * Postgres and Redis, with INTERACTION_UI_ENABLED on and an MFA policy each
 * test sets (the boot's test option: no policy is stored yet).
 *
 * The authenticator app is this file's own RFC 6238 code generator (SHA-1,
 * six digits, 30 seconds) over a secret sealed by the server's signer, as a
 * binding stores it. It proves the issue's integration criteria:
 *
 * - Under an MFA policy, an account with no second factor gets the
 *   `totp_setup` step and no code is mailed for it; the secret is bound only
 *   after a first valid code (and, for a password-only account, the mailbox
 *   proved by a mailed code), and the sign-in completes with
 *   `amr: ["pwd","otp","mfa"]` after the recovery set.
 * - An unclaimed account never binds one: the sign-in verifies its address
 *   first, and a binding that finds the account unclaimed is refused.
 * - Wrong codes are counted on the account across transactions, clients and
 *   IPs, verified no more often than the ladder allows (an early attempt is
 *   `429`, neither checked nor counted), and a right password never clears
 *   the count; the "wrong second factor" notice goes once a day.
 * - At 100 wrong codes in a row the TOTP is disabled only while the hosted
 *   pages are on and the account keeps an unused recovery code; the
 *   pages-off case runs on the server's own TOTP port, since no transport
 *   reaches a TOTP step with them off.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
const CLIENT_A = 'totp-notes-app';
const CLIENT_B = 'totp-tasks-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const EMAIL = 'totp-owner@example.test';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const TOTP = stepUrn('totp');
const TOTP_SETUP = stepUrn('totp_setup');
const EMAIL_CODE = stepUrn('email_code');
const RECOVERY_CODE = stepUrn('recovery_code');
const RECOVERY_CODES = stepUrn('recovery_codes');
const CAPTCHA = stepUrn('captcha');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
/** An interaction id: 43 base64url characters. */
const INTERACTION_ID = /^[A-Za-z0-9_-]{43}$/;
/** Three end-user addresses in three /24 buckets. */
const IP_A = '203.0.113.10';
const IP_B = '198.51.100.20';
const IP_C = '192.0.2.30';
const STEP_MS = 30_000;
/** No second factor required: the boot's policy until a test sets another. */
const POLICY_OFF = Object.freeze({ realm: 'off', client: 'off' }) as Awaited<
  ReturnType<MfaPolicyReader['read']>
>;
const POLICY_REQUIRED = Object.freeze({ realm: 'required', client: 'off' }) as Awaited<
  ReturnType<MfaPolicyReader['read']>
>;
/** The background tasks of the ports this suite builds: run now, failures dropped. */
const TASKS: BackgroundTasks = {
  run: (task) => {
    void Promise.resolve()
      .then(task)
      .catch(() => undefined);
  },
};

/** A mail the engine sent: its template and its code, if any. */
interface SentMail {
  readonly template: string;
  readonly code?: string;
}

/** The step view the ceremony page reads. */
interface StepView {
  readonly step: string;
  readonly csrf: string;
  readonly alternatives?: readonly string[];
  readonly params?: Record<string, Record<string, unknown>>;
  readonly error?: string;
}

/** A sign-in in progress: its browser, its address and its interaction. */
interface SignIn {
  readonly jar: CookieJar;
  readonly ip: string;
  readonly id: string;
}

/** RFC 4648 §6 base32, unpadded, as the set-up page shows the secret. */
function base32Decode(text: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const character of text) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error(`not base32: ${character}`);
    value = ((value << 5) | index) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** The authenticator app: the RFC 6238 code of `secret` at `at`, `offset` steps away. */
function codeAt(secret: Buffer, at: number, offset = 0): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / STEP_MS) + offset));
  const mac = createHmac('sha1', secret).update(counter).digest();
  const at4 = mac.readUInt8(19) & 0x0f;
  return String((mac.readUInt32BE(at4) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

/** A six-digit code no step of the window at `at` accepts. */
function wrongCodeAt(secret: Buffer, at: number): string {
  const valid = new Set([-1, 0, 1].map((offset) => codeAt(secret, at, offset)));
  for (const candidate of ['000000', '111111', '222222', '333333']) {
    if (!valid.has(candidate)) return candidate;
  }
  throw new Error('no wrong code');
}

describe('TOTP as a second factor on the hosted pages (#653, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';
  let clientRows: Record<string, string> = {};
  let engines: InteractionEngines | undefined;
  /** The MFA policy every round reads. */
  let policy = POLICY_OFF;
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
      { mfaPolicy: { read: async () => policy } }
    );
    const { emailService } = booted.app;
    const original = emailService.sendEngineMail.bind(emailService);
    emailService.sendEngineMail = async (realm, to, mail: EngineMail, context) => {
      const code = 'code' in mail && typeof mail.code === 'string' ? mail.code : undefined;
      mails.set(to, [
        ...(mails.get(to) ?? []),
        { template: mail.template, ...(code === undefined ? {} : { code }) },
      ]);
      return original(realm, to, mail, context);
    };
    // Imported after the boot, as the harness imports the app: the modules
    // read the environment the boot sets, and share the app's instances.
    const { createInteractionEngines } = await import('./helpers/interaction-engines');
    engines = createInteractionEngines(booted.app, { tasks: TASKS });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    policy = POLICY_OFF;
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
    clientRows = {};
    for (const clientId of [CLIENT_A, CLIENT_B]) {
      const client = await app.repositories.oauthClients.create({
        realmId,
        clientId,
        clientSecretHash: 'unused-public-client',
        tokenEndpointAuthMethod: 'none',
        name: `TOTP ${clientId}`,
        redirectUris: [REDIRECT_URI],
        scopes: SCOPES,
        grantTypes: ['authorization_code', 'refresh_token'],
        enabled: true,
        requirePkce: true,
        // A seeded client: its redirect URI receives authorization errors.
        provisionedByOperator: true,
      });
      clientRows[clientId] = client.id;
    }
  }, 120_000);

  /** A verified password account that consented to both clients. */
  async function passwordAccount(email = EMAIL): Promise<string> {
    const userId = await registerPasswordAccount(server(), email);
    for (const row of Object.values(clientRows)) {
      await server().repositories.oauthConsents.upsertGrant(realmId, userId, row, SCOPES);
    }
    return userId;
  }

  /** A password account whose address nobody verified: registered, never verified. */
  async function unclaimedAccount(email: string): Promise<string> {
    const registered = await server().inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(registered.statusCode, registered.body).toBe(202);
    const credential = await server().repositories.userCredentials.findByRealmProviderSub(
      realmId,
      'password',
      email
    );
    if (credential === undefined) throw new Error('no registered account');
    return credential.userId;
  }

  /**
   * Bind a TOTP to the account as a set-up stores it: a 160-bit secret
   * sealed by the signer under the account's context, its last step two
   * behind now. With `recovery`, a confirmed recovery set beside it.
   */
  async function bindTotp(
    userId: string,
    options: { readonly recovery: boolean } = { recovery: true }
  ): Promise<Buffer> {
    const secret = randomBytes(20);
    const { totpSecretContext } = await import('./helpers/totp-sign-in');
    const sealed = await server().signer.encrypt('api', {
      realmId,
      plaintext: new Uint8Array(secret),
      context: totpSecretContext(realmId, userId),
    });
    const bound = await server().repositories.userCredentials.upsertTotp({
      realmId,
      userId,
      credentialData: { secret: sealed, last_step: Math.floor(Date.now() / STEP_MS) - 2 },
      at: Date.now(),
    });
    expect(bound).toBeDefined();
    if (options.recovery) {
      const issued = await recoveryCodes().issue({ realmId, userId });
      if (issued === null) throw new Error('no set issued');
      expect(await recoveryCodes().confirm({ realmId, userId, setId: issued.setId })).toBe(true);
    }
    mails.clear();
    return secret;
  }

  /** The server's own TOTP port, as the engines build it, with the hosted pages as given. */
  async function totpPort(hostedPages: boolean): Promise<TotpCredentials> {
    const { createEngineMailer } = await import('./helpers/engine-mail');
    const { createServerLadderParts } = await import('./helpers/password-attempts');
    const { createServerTotp } = await import('./helpers/totp-sign-in');
    const mailer = createEngineMailer(server(), TASKS);
    return createServerTotp(server(), {
      mailer,
      realmOf: async (id) => {
        const realm = await server().repositories.realms.findById(id);
        if (realm === undefined) throw new Error('no realm');
        return realm;
      },
      recoveryCodes: recoveryCodes(),
      ladder: createServerLadderParts(server(), mailer.passwordDisabledNotices).ladder,
      hostedPages,
      passkeys: false,
    });
  }

  /** The account's TOTP row: its stored data and its disabled mark. */
  async function totpRow(
    userId: string
  ): Promise<{ credential_data: Record<string, unknown>; disabled_at: unknown } | undefined> {
    const rows = await query<{ credential_data: Record<string, unknown>; disabled_at: unknown }>(
      `SELECT credential_data, disabled_at FROM user_credentials
        WHERE realm_id = $1 AND user_id = $2 AND provider_type = 'totp'`,
      [realmId, userId]
    );
    return rows[0];
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
    signIn: SignIn,
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

  /** A new sign-in of `email` for `clientId` from `ip`, answered through the password. */
  async function afterPassword(ip: string, clientId = CLIENT_A, email = EMAIL): Promise<SignIn> {
    const jar = new CookieJar();
    const { challenge } = pkcePair();
    const authorized = await server().inject({
      method: 'GET',
      remoteAddress: ip,
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'totp-state',
      }).toString()}`,
    });
    jar.absorb(authorized.headers['set-cookie']);
    const path = locationOf(authorized);
    expect(path.startsWith(CEREMONY_PAGE_PREFIX), path).toBe(true);
    const id = path.slice(CEREMONY_PAGE_PREFIX.length);
    expect(id).toMatch(INTERACTION_ID);
    const signIn: SignIn = { jar, ip, id };

    const identified = await answer(signIn, IDENTIFIER, { login_hint: email });
    expect(identified.statusCode, identified.body).toBe(303);
    const signedIn = await answer(signIn, PASSWORD, { password: E2E_PASSWORD });
    expect(signedIn.statusCode, signedIn.body).toBe(303);
    return signIn;
  }

  /** A new sign-in at the TOTP step, after a right password. */
  async function atTotpStep(ip: string, clientId = CLIENT_A): Promise<SignIn> {
    const signIn = await afterPassword(ip, clientId);
    expect((await read(signIn.id)).step).toBe(TOTP);
    return signIn;
  }

  /**
   * The bot challenge an account past its free failures meets before its
   * next code is read: the answer brings the challenge, which is solved.
   */
  async function throughChallenge(signIn: SignIn, code: string): Promise<void> {
    const challenged = await answer(signIn, TOTP, { otp: code });
    expect(challenged.statusCode, challenged.body).toBe(303);
    const offered = await read(signIn.id);
    expect(offered.step).toBe(CAPTCHA);
    const solution = await solveProofOfWork(
      offered.params?.[CAPTCHA] as unknown as ProofOfWorkParams
    );
    const passed = await answer(signIn, CAPTCHA, { captcha_token: solution });
    expect(passed.statusCode, passed.body).toBe(303);
    expect((await read(signIn.id)).step).toBe(TOTP);
  }

  /** The TOTP counter of the account's failure ladder (`ladderAccountCounterKey`). */
  function counterKey(userId: string): string {
    return `sign-in-ladder:{${realmId}:user:${userId}}:totp`;
  }

  /** The account's count of wrong codes in a row, or `null` with none. */
  async function failures(userId: string): Promise<string | null> {
    return server().redis.hget(counterKey(userId), 'n');
  }

  /** The mails of `template` sent to `to`, once `count` of them went out. */
  async function mailedWith(to: string, template: string, count: number): Promise<SentMail[]> {
    const deadline = performance.now() + 5_000;
    const sent = () => (mails.get(to) ?? []).filter((mail) => mail.template === template);
    while (sent().length < count && performance.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(sent()).toHaveLength(count);
    return sent();
  }

  /** The secret the set-up page shows, as text: the browser holding the flow cookie reads it. */
  /** The keys of every string value in Redis that holds `text`. */
  async function redisHolds(text: string): Promise<string[]> {
    const redis = server().redis;
    const holding: string[] = [];
    for (const key of await redis.keys('*')) {
      if ((await redis.type(key)) !== 'string') continue;
      if ((await redis.get(key))?.includes(text) === true) holding.push(key);
    }
    return holding;
  }

  async function shownSecret(signIn: SignIn): Promise<Buffer> {
    const page = await server().inject({
      method: 'GET',
      url: `/ui/totp-setup/${signIn.id}`,
      headers: { 'sec-fetch-site': 'same-origin', cookie: signIn.jar.header() ?? '' },
    });
    expect(page.statusCode, page.body).toBe(200);
    expect(page.headers['cache-control']).toBe('no-store');
    expect(page.body).toContain('<svg');
    const shown = /<code class="secret">([A-Z2-7 ]+)<\/code>/.exec(page.body)?.[1];
    if (shown === undefined) throw new Error('the set-up page shows no secret');
    return base32Decode(shown.replaceAll(' ', ''));
  }

  it('signs in with a password then a code, amr pwd/otp/mfa, and a code works once', async () => {
    // One instant for the test: a step boundary cannot fall between a code
    // and its check.
    const now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const userId = await passwordAccount();
    const secret = await bindTotp(userId);

    const signIn = await atTotpStep(IP_A);
    // The hosted page asks for it.
    const page = await server().inject({ method: 'GET', url: `/ui/totp/${signIn.id}` });
    expect(page.statusCode, page.body).toBe(200);
    expect(page.headers['cache-control']).toBe('no-store');
    expect(page.body).toContain('name="otp"');

    // A code of the previous step: inside the tolerance.
    const code = codeAt(secret, now, -1);
    const decided = vi.spyOn(await import('./helpers/interaction-engines'), 'decisionOf');
    const done = await answer(signIn, TOTP, { otp: code });
    expect(done.statusCode, done.body).toBe(303);
    expect(decided.mock.results.map((result) => result.value)).toEqual([
      {
        kind: 'authenticated',
        signIn: expect.objectContaining({ userId, amr: ['pwd', 'otp', 'mfa'] }),
      },
    ]);
    // The step it matched is the last one accepted now.
    expect((await totpRow(userId))?.credential_data['last_step']).toBe(
      Math.floor(now / STEP_MS) - 1
    );

    // The same code again, in a new sign-in: refused, and counted.
    const again = await atTotpStep(IP_B);
    const refused = await answer(again, TOTP, { otp: code });
    expect(refused.statusCode, refused.body).toBe(303);
    expect(await read(again.id)).toMatchObject({ step: TOTP, error: 'invalid_credentials' });
    const refusedPage = await server().inject({ method: 'GET', url: `/ui/totp/${again.id}` });
    expect(refusedPage.body).toContain('That code did not work');
    expect(await failures(userId)).toBe('1');
  });

  it('counts wrong codes on the account across transactions, clients and IPs, checks none early, and a right password never clears the count', async () => {
    // One instant for the whole run, moved by hand: the wait the 5th wrong
    // code sets (one second) neither passes nor is missed by chance.
    let now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const userId = await passwordAccount();
    const secret = await bindTotp(userId);
    const wrong = wrongCodeAt(secret, now);
    const lastStep = (await totpRow(userId))?.credential_data['last_step'];

    // Transaction A, client A, one address: three wrong codes.
    const a = await atTotpStep(IP_A, CLIENT_A);
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const refused = await answer(a, TOTP, { otp: wrong });
      expect(refused.statusCode, refused.body).toBe(303);
      expect(await read(a.id)).toMatchObject({ step: TOTP, error: 'invalid_credentials' });
    }
    expect(await failures(userId)).toBe('3');
    // A wrong code after a right password is told to the owner, once a day.
    await mailedWith(EMAIL, 'second_factor_failed', 1);

    // Transaction B, client B, another address: the right password leaves
    // the count, and two more wrong codes make it 5.
    const b = await atTotpStep(IP_B, CLIENT_B);
    expect(await failures(userId)).toBe('3');
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      const refused = await answer(b, TOTP, { otp: wrong });
      expect(refused.statusCode, refused.body).toBe(303);
    }
    expect(await failures(userId)).toBe('5');

    // Transaction C, a third address: the right password again leaves the
    // count. Past its free failures, the bot challenge comes before the next
    // code is read.
    const c = await atTotpStep(IP_C, CLIENT_A);
    expect(await failures(userId)).toBe('5');
    await throughChallenge(c, wrong);
    expect(await failures(userId)).toBe('5');

    // Inside the wait the right code is refused, neither checked nor
    // counted: no address is exempt, and the step it names stays unused.
    const at = now;
    const right = codeAt(secret, at);
    const waited = await answer(c, TOTP, { otp: right });
    expect(waited.statusCode, waited.body).toBe(429);
    expect(waited.headers['retry-after']).toBe('1');
    expect(await failures(userId)).toBe('5');
    expect((await totpRow(userId))?.credential_data['last_step']).toBe(lastStep);

    // After it the same right code is taken, and the count is gone.
    now += 2_000;
    const done = await answer(c, TOTP, { otp: right });
    expect(done.statusCode, done.body).toBe(303);
    expect(await failures(userId)).toBeNull();
    // The code names the step it was read at, which the wait may have left
    // behind by one: that step, within the tolerance, is the one taken.
    expect((await totpRow(userId))?.credential_data['last_step']).toBe(Math.floor(at / STEP_MS));
    // The day's notice went with the first wrong code: none since.
    expect((mails.get(EMAIL) ?? []).map((mail) => mail.template)).toEqual(['second_factor_failed']);
  });

  it('disables the TOTP at 100 wrong codes in a row only while the account keeps an unused recovery code', async () => {
    const now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    // No recovery code and no other second factor: the 100th disables nothing.
    const bare = await passwordAccount('totp-bare@example.test');
    const bareSecret = await bindTotp(bare, { recovery: false });
    await server().redis.hset(counterKey(bare), {
      n: '99',
      until: String(Date.now() - 1_000),
      run: 'seeded-run',
    });
    const first = await afterPassword(IP_A, CLIENT_A, 'totp-bare@example.test');
    expect((await read(first.id)).step).toBe(TOTP);
    await throughChallenge(first, wrongCodeAt(bareSecret, Date.now()));
    const notArmed = await answer(first, TOTP, { otp: wrongCodeAt(bareSecret, Date.now()) });
    expect(notArmed.statusCode, notArmed.body).toBe(303);
    expect(await failures(bare)).toBe('100');
    expect((await totpRow(bare))?.disabled_at).toBeNull();

    // With an unused recovery code: the 100th disables the TOTP, and the
    // owner is told.
    const userId = await passwordAccount();
    const secret = await bindTotp(userId);
    await server().redis.hset(counterKey(userId), {
      n: '99',
      until: String(Date.now() - 1_000),
      run: 'seeded-run',
    });
    const signIn = await atTotpStep(IP_B);
    await throughChallenge(signIn, wrongCodeAt(secret, Date.now()));
    const hundredth = await answer(signIn, TOTP, { otp: wrongCodeAt(secret, Date.now()) });
    expect(hundredth.statusCode, hundredth.body).toBe(303);
    expect(await failures(userId)).toBe('100');
    expect((await totpRow(userId))?.disabled_at).not.toBeNull();
    await mailedWith(EMAIL, 'second_factor_disabled', 1);

    // Disabled, it still counts as bound: after the password only a
    // recovery code is offered.
    const next = await afterPassword(IP_C);
    expect(await read(next.id)).toMatchObject({ step: RECOVERY_CODE });
    expect((await read(next.id)).alternatives ?? []).toEqual([]);
  });

  it('never disables the TOTP at the ceiling with the hosted pages off', async () => {
    const userId = await passwordAccount();
    await bindTotp(userId);

    await (await totpPort(false)).ceilingReached({ realmId, userId });
    expect((await totpRow(userId))?.disabled_at).toBeNull();

    // The same port with the pages on: the account keeps unused codes.
    await (await totpPort(true)).ceilingReached({ realmId, userId });
    expect((await totpRow(userId))?.disabled_at).not.toBeNull();
    await mailedWith(EMAIL, 'second_factor_disabled', 1);
  });

  it('asks an account with no second factor to set one up under an MFA policy, mails no code for it, and binds only after a first valid code', async () => {
    const now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const userId = await passwordAccount();
    mails.clear();
    policy = POLICY_REQUIRED;

    const signIn = await afterPassword(IP_A);
    const offered = await read(signIn.id);
    expect(offered.step).toBe(TOTP_SETUP);
    expect(offered.params?.[TOTP_SETUP]).toEqual({ algorithm: 'SHA1', digits: 6, period: 30 });
    // No code stands in for the factor: nothing was mailed.
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(mails.get(EMAIL) ?? []).toEqual([]);
    const secret = await shownSecret(signIn);
    expect(secret).toHaveLength(20);
    expect(await totpRow(userId)).toBeUndefined();
    // The page opened the held ciphertext for its read: Redis keeps the
    // secret nowhere, neither in the interaction record nor beside it.
    await expect(redisHolds(base32Encode(secret))).resolves.toEqual([]);

    // A wrong first code binds nothing.
    const refused = await answer(signIn, TOTP_SETUP, { otp: wrongCodeAt(secret, Date.now()) });
    expect(refused.statusCode, refused.body).toBe(303);
    expect(await read(signIn.id)).toMatchObject({
      step: TOTP_SETUP,
      error: 'invalid_credentials',
    });
    expect(await totpRow(userId)).toBeUndefined();
    // The same secret is shown again.
    expect((await shownSecret(signIn)).equals(secret)).toBe(true);

    // A valid one: the first second factor of a password-only account needs
    // its mailbox proved in this sign-in, by a mailed code.
    const valid = await answer(signIn, TOTP_SETUP, { otp: codeAt(secret, Date.now()) });
    expect(valid.statusCode, valid.body).toBe(303);
    const mailbox = await read(signIn.id);
    expect(mailbox.step).toBe(EMAIL_CODE);
    expect(await totpRow(userId)).toBeUndefined();
    const [mailed] = await mailedWith(EMAIL, 'code', 1);
    const proved = await answer(signIn, EMAIL_CODE, { otp: mailed?.code ?? '' });
    expect(proved.statusCode, proved.body).toBe(303);

    // Bound now, sealed: the stored secret is the signer's ciphertext.
    const row = await totpRow(userId);
    expect(row?.disabled_at).toBeNull();
    const stored = String(row?.credential_data['secret']);
    expect(stored).not.toContain(secret.toString('hex'));
    expect(stored).not.toContain(secret.toString('base64'));
    await mailedWith(EMAIL, 'totp_added', 1);

    // The first binding issues a recovery set; its confirmation completes
    // the sign-in, the first code standing for the TOTP's proof.
    expect((await read(signIn.id)).step).toBe(RECOVERY_CODES);
    const decided = vi.spyOn(await import('./helpers/interaction-engines'), 'decisionOf');
    const done = await answer(signIn, RECOVERY_CODES, { acknowledged: 'true' });
    expect(done.statusCode, done.body).toBe(303);
    expect(decided.mock.results.map((result) => result.value)).toEqual([
      {
        kind: 'authenticated',
        signIn: expect.objectContaining({ userId, amr: ['pwd', 'otp', 'mfa'] }),
      },
    ]);
  });

  it('never binds a TOTP to an unclaimed account', async () => {
    policy = POLICY_REQUIRED;
    const email = 'totp-unclaimed@example.test';
    const userId = await unclaimedAccount(email);
    mails.clear();

    // At sign-in its address is verified first: the set-up step is not
    // offered to an account nobody claimed.
    const signIn = await afterPassword(IP_A, CLIENT_A, email);
    const offered = await read(signIn.id);
    expect(offered.step).toBe(EMAIL_CODE);
    expect(offered.params?.[EMAIL_CODE]?.['purpose']).toBe('verify_account');
    expect(await totpRow(userId)).toBeUndefined();

    // A binding that finds the account unclaimed is refused, and stores nothing.
    const port = await totpPort(true);
    const started = await port.start({ realmId, userId, identifier: email });
    const binding = await port.bind({
      realmId,
      userId,
      clientId: CLIENT_A,
      sealed: started.sealed,
      step: Math.floor(Date.now() / STEP_MS),
    });
    expect(binding).toEqual({ kind: 'refused', reason: 'account_unclaimed' });
    expect(await totpRow(userId)).toBeUndefined();
  });
});
