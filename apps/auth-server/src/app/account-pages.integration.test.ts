import { createHmac, randomBytes, randomUUID } from 'node:crypto';

import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
import {
  createFixtureNetwork,
  type EgressTransport,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/fastify-plugin-ssf/src/testing/egress-network';
import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { createLocalJWKSet, type JSONWebKeySet, jwtVerify } from 'jose';
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
  registerPasswordAccount,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { type SoftPasskey, softPasskey,type SoftPasskeyCreation } from '../testing/soft-passkey';
import type { BackgroundTasks } from './helpers/background-tasks';
import type { InteractionEngines } from './helpers/interaction-engines';

/**
 * THE HOSTED ACCOUNT PAGES, `/ui/account` (#844; ADR-017 Decision 8, ADR-020
 * §3; `graphs/flows/account/*`), end to end against real Postgres and Redis,
 * with INTERACTION_UI_ENABLED and WEBAUTHN_ENABLED on. Every request is a
 * plain form post or a page load, as a browser without JavaScript sends it;
 * the passkeys are software authenticators, the authenticator app is the
 * RFC 6238 code computed here.
 *
 * It proves the issue's integration criteria:
 *
 * - every change is refused without a fresh authentication with the
 *   account's strongest factor, and made after one, the fresh sign-in
 *   through "Confirm it's you" included;
 * - a form post without the CSRF value, with another, or from another site
 *   is refused;
 * - a password change that breaks the password policy is refused with the
 *   policy's message;
 * - removing the account's last way to sign in is refused;
 * - sign out everywhere ends every session of the person, and each relying
 *   party with a back-channel logout URI receives a logout token (local
 *   HTTPS receivers behind the egress client's network edges, as the
 *   back-channel logout suite has them);
 * - a new set of recovery codes replaces the old one, whose codes no longer
 *   work;
 * - and the E2E run with no JavaScript: sign in, change the password, add a
 *   passkey and remove it, set up an authenticator app, sign out everywhere.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const network = vi.hoisted(() => ({ current: undefined as EgressTransport | undefined }));

vi.mock('../../../../libs/server/egress/src/lib/transport', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const current = (): EgressTransport => {
    if (network.current === undefined) throw new Error('no fixture network');
    return network.current;
  };
  return {
    ...actual,
    NODE_TRANSPORT: {
      resolveHost: (...args: Parameters<EgressTransport['resolveHost']>) =>
        current().resolveHost(...args),
      exchange: (...args: Parameters<EgressTransport['exchange']>) => current().exchange(...args),
    },
  };
});

const ORIGIN = 'https://auth.example.com';
const RP_ID = 'auth.example.com';
const ACCOUNT = '/ui/account';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as a browser sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const WEBAUTHN_GET = stepUrn('webauthn_get');
const WEBAUTHN_CREATE = stepUrn('webauthn_create');
const TOTP_SETUP = stepUrn('totp_setup');
const EMAIL_CODE = stepUrn('email_code');
const RECOVERY_CODES = stepUrn('recovery_codes');
const NEW_PASSWORD = 'Another-Correct-Horse-Battery-77!';
/** A sign-in older than the five minutes a change takes. */
const STALE_MS = 10 * 60_000;
const STEP_MS = 30_000;
const REFUSED_EVENT = 'request.account_operation_refused';
/** The page a change refused for want of a fresh sign-in answers with. */
const REAUTHENTICATE_FORM = `action="${ACCOUNT}/reauthenticate"`;
/** A public address the fixture DNS hands out; a local server stands for it. */
const RECEIVER_ADDRESS = '93.184.215.14';
const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
/** The background tasks of the engines this suite builds: run now, failures dropped. */
const TASKS: BackgroundTasks = {
  run: (task) => {
    void Promise.resolve()
      .then(task)
      .catch(() => undefined);
  },
};

/** The step view the ceremony page reads. */
interface StepView {
  readonly step: string;
  readonly csrf: string;
  readonly alternatives?: readonly string[];
  readonly params?: Record<string, Record<string, unknown>>;
  readonly error?: string;
}

/** A browser on the account pages: its cookies. */
interface Browser {
  readonly jar: CookieJar;
}

/** A browser in an interaction of the account page. */
interface Flow extends Browser {
  readonly id: string;
}

/** An account of the suite: its id and its sign-in address. */
interface Account {
  readonly userId: string;
  readonly email: string;
}

/** How a ceremony's sign-in is answered. */
interface SignInAnswers {
  /** Sign in with this passkey; otherwise with the address and `password`. */
  readonly passkey?: SoftPasskey;
  readonly password?: string;
  /** Collects the passkey a `webauthn_create` step bound. */
  readonly created?: (passkey: SoftPasskey) => void;
  /** Collects the secret a `totp_setup` step showed. */
  readonly totpSecret?: (secret: Buffer) => void;
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

/** The authenticator app: the RFC 6238 code of `secret` at `at`. */
function codeAt(secret: Buffer, at: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / STEP_MS)));
  const mac = createHmac('sha1', secret).update(counter).digest();
  const offset = mac.readUInt8(19) & 0x0f;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

/** Text as the pages escape it. */
function escaped(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** The CSRF value a page's forms carry. */
function csrfOf(body: string): string {
  const match = /name="csrf" value="([^"]+)"/.exec(body);
  if (match?.[1] === undefined) throw new Error('no csrf field on the page');
  return match[1];
}

/** The recovery codes a "new recovery codes" page shows, and the set to confirm. */
function codesOf(body: string): { readonly codes: string[]; readonly setId: string } {
  const codes = [...body.matchAll(/<li><code>([^<]+)<\/code><\/li>/g)].map((m) => m[1] as string);
  const setId = /name="set_id" value="([^"]+)"/.exec(body)?.[1];
  if (setId === undefined) throw new Error('no set_id on the page');
  return { codes, setId };
}

/** The creation options the "add a passkey" page hands the browser's ceremony. */
function creationOptionsOf(body: string): SoftPasskeyCreation & {
  readonly user: { readonly id: string };
} {
  const match = /data-options="([^"]*)"/.exec(body);
  if (match === null) throw new Error('no options on the page');
  return JSON.parse(
    (match[1] as string)
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
  );
}

describe('the hosted account pages (#844, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let net: FixtureNetwork | undefined;
  let receiver: FixtureServer;
  let dockerUp = false;
  let realmId = '';
  let engines: InteractionEngines | undefined;
  let signCookie: ((session: { sid: string; realmId: string }) => Promise<string>) | undefined;
  /** The engine mails, by address, in order. */
  const mails = new Map<string, { template: string; code?: string }[]>();
  /** The mailed codes a test answered already. */
  const usedCodes = new Set<string>();

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    net = await createFixtureNetwork();
    receiver = await net.serve(RECEIVER_ADDRESS, (_req, _body, res) => {
      res.writeHead(200);
      res.end();
    });
    network.current = net.transport;
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      INTERACTION_UI_ENABLED: 'true',
      WEBAUTHN_ENABLED: 'true',
      // Each test registers its accounts through POST /auth/register, and
      // drives dozens of page loads from one address.
      REGISTRATION_RATE_LIMIT: '10000',
      AUTHORIZE_RATE_LIMIT: '10000',
      AUTHORIZE_RATE_LIMIT_LENIENT: '10000',
    });
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
    const { signSessionCookie, SESSION_COOKIE_NAME } = await import('./helpers/session-cookie');
    const app = booted.app;
    signCookie = async (session) =>
      `${SESSION_COOKIE_NAME}=${await signSessionCookie(app, session)}`;
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await net?.close();
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp || booted === undefined || net === undefined) {
      ctx.skip();
      return;
    }
    net.dns.clear();
    net.dns.set('rp.egress.test', [RECEIVER_ADDRESS]);
    receiver.requests.length = 0;
    mails.clear();
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

  async function eventsOf(type: string, userId: string): Promise<Record<string, unknown>[]> {
    const rows = await query<{ data: Record<string, unknown> }>(
      'SELECT data FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
      [`urn:qauth:event:${type}:v1-rc.0`, userId]
    );
    return rows.map((row) => row.data);
  }

  async function credentialsOf(userId: string): Promise<{ id: string; provider_type: string }[]> {
    return query(
      'SELECT id::text AS id, provider_type FROM user_credentials WHERE user_id = $1 ORDER BY provider_type, id',
      [userId]
    );
  }

  // ── Accounts and sessions ──────────────────────────────────────────────

  /** A password account, with a passkey bound if one is given. */
  async function account(passkey?: SoftPasskey): Promise<Account> {
    const email = `account-${randomUUID()}@example.test`;
    const userId = await registerPasswordAccount(server(), email);
    if (passkey !== undefined) await bindPasskey(userId, passkey);
    return { userId, email };
  }

  async function bindPasskey(userId: string, passkey: SoftPasskey): Promise<string> {
    const row = await server().repositories.userCredentials.create({
      userId,
      realmId,
      providerType: 'webauthn',
      externalSub: passkey.credentialId,
      credentialData: passkey.credentialData,
    });
    return row.id;
  }

  /** Bind an authenticator app as a set-up stores it: a secret sealed by the signer. */
  async function bindTotp(userId: string): Promise<Buffer> {
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
    return secret;
  }

  /** A linked upstream identity of the account, as a link stores it. */
  async function bindUpstream(userId: string): Promise<string> {
    const row = await server().repositories.userCredentials.create({
      userId,
      realmId,
      providerType: 'acme-sso',
      externalSub: `upstream-${randomUUID()}`,
      credentialData: { kind: 'upstream', iss: 'https://idp.acme.example', verified: true },
    });
    return row.id;
  }

  /**
   * A browser signed in to the account `ageMs` ago with `amr`, as a sign-in
   * on the hosted pages leaves it: a session, and its cookie.
   */
  async function signedIn(
    who: Account,
    amr: readonly string[],
    options: { readonly ageMs?: number; readonly recoveryCodeUsed?: boolean } = {}
  ): Promise<Browser & { readonly sid: string }> {
    if (signCookie === undefined) throw new Error('server not booted');
    const session = await server().sessionService.create({
      realmId,
      userId: who.userId,
      authTime: Date.now() - (options.ageMs ?? 1_000),
      amr,
      ...(options.recoveryCodeUsed === true ? { recoveryCodeUsed: true } : {}),
      ipAddress: '192.0.2.10',
      userAgent: 'Browser/1',
    });
    const jar = new CookieJar();
    jar.absorb(await signCookie({ sid: session.sid, realmId }));
    return { jar, sid: session.sid };
  }

  // ── Pages and forms ────────────────────────────────────────────────────

  async function open(browser: Browser, path: string): Promise<LightMyRequestResponse> {
    const response = await server().inject({
      method: 'GET',
      url: path,
      headers: { cookie: browser.jar.header() ?? '' },
    });
    browser.jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** The overview, opened by a signed-in browser. */
  async function overview(browser: Browser): Promise<LightMyRequestResponse> {
    const response = await open(browser, ACCOUNT);
    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.body).not.toMatch(/<script\b/i);
    return response;
  }

  /** A form post to the account pages, as the browser sends it. */
  async function post(
    browser: Browser,
    path: string,
    fields: Record<string, string>,
    headers: Record<string, string> = SAME_ORIGIN
  ): Promise<LightMyRequestResponse> {
    const response = await server().inject({
      method: 'POST',
      url: path,
      headers: { ...FORM, ...headers, cookie: browser.jar.header() ?? '' },
      payload: new URLSearchParams(fields).toString(),
    });
    browser.jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** Submit one of the overview's forms: the CSRF value the page carries, and `fields`. */
  async function submit(
    browser: Browser,
    path: string,
    fields: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    const csrf = csrfOf((await overview(browser)).body);
    return post(browser, path, { csrf, ...fields });
  }

  /** The path of a redirect, without the realm origin. */
  function locationOf(response: LightMyRequestResponse): string {
    expect([302, 303], response.body).toContain(response.statusCode);
    const location = String(response.headers['location']);
    return location.startsWith(`${ORIGIN}/`) ? location.slice(ORIGIN.length) : location;
  }

  // ── The ceremonies ─────────────────────────────────────────────────────

  async function read(id: string): Promise<StepView> {
    const response = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}`,
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json();
  }

  async function answer(
    flow: Flow,
    type: string,
    fields: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    const { csrf } = await read(flow.id);
    const response = await server().inject({
      method: 'POST',
      url: `${INTERACTION_API_PREFIX}/${flow.id}/answer`,
      headers: { ...FORM, ...SAME_ORIGIN, cookie: flow.jar.header() ?? '' },
      payload: new URLSearchParams({ type, csrf, ...fields }).toString(),
    });
    flow.jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** A hosted step page of the interaction, opened by its browser. */
  async function stepPage(flow: Flow, path: string): Promise<string> {
    const response = await server().inject({
      method: 'GET',
      url: `/ui/${path}/${flow.id}`,
      headers: { cookie: flow.jar.header() ?? '', 'sec-fetch-site': 'same-origin' },
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    return response.body;
  }

  /** The newest code mailed to `to` that no answer used yet. */
  async function mailedCode(to: string): Promise<string> {
    let code: string | undefined;
    await vi.waitFor(
      () => {
        code = (mails.get(to) ?? [])
          .map((mail) => mail.code)
          .filter((value): value is string => value !== undefined && !usedCodes.has(value))
          .at(-1);
        expect(code).toBeDefined();
      },
      { timeout: 5_000, interval: 20 }
    );
    usedCodes.add(code as string);
    return code as string;
  }

  /**
   * Follow an account-page ceremony from the redirect that started it to the
   * account page it comes back to, answering each step as `answers` says:
   * the sign-in (passkey-first, or the address and password), the mailbox
   * code, a new passkey, an authenticator app, the new recovery codes.
   * Returns the path it came back to.
   */
  async function ceremony(
    browser: Browser,
    started: LightMyRequestResponse,
    who: Account,
    answers: SignInAnswers
  ): Promise<string> {
    const path = locationOf(started);
    expect(path.startsWith(CEREMONY_PAGE_PREFIX), path).toBe(true);
    const flow: Flow = { jar: browser.jar, id: path.slice(CEREMONY_PAGE_PREFIX.length) };
    for (let round = 0; round < 12; round += 1) {
      const view = await read(flow.id);
      let response: LightMyRequestResponse;
      if (view.step === WEBAUTHN_GET && answers.passkey !== undefined) {
        const request = view.params?.[WEBAUTHN_GET];
        if (request === undefined) throw new Error('the webauthn_get step carries no options');
        response = await answer(flow, WEBAUTHN_GET, {
          webauthn_response: answers.passkey.assert({
            challenge: String(request['challenge']),
            rpId: String(request['rpId']),
          }),
        });
      } else if (view.step === WEBAUTHN_GET || view.step === IDENTIFIER) {
        // "Try another way": the address, then the password.
        response = await answer(flow, IDENTIFIER, { login_hint: who.email });
      } else if (view.step === PASSWORD) {
        response = await answer(flow, PASSWORD, { password: answers.password ?? E2E_PASSWORD });
      } else if (view.step === EMAIL_CODE) {
        response = await answer(flow, EMAIL_CODE, { otp: await mailedCode(who.email) });
      } else if (view.step === WEBAUTHN_CREATE && answers.created === undefined) {
        // The optional passkey offer of a password-only account's sign-in,
        // which a ceremony that asked for none declines.
        expect(view.params?.[WEBAUTHN_CREATE]).toMatchObject({ optional: true });
        response = await answer(flow, WEBAUTHN_CREATE);
      } else if (view.step === WEBAUTHN_CREATE) {
        const options = creationOptionsOf(await stepPage(flow, 'passkey-enrolment'));
        const passkey = softPasskey(RP_ID, options.user.id);
        response = await answer(flow, WEBAUTHN_CREATE, {
          webauthn_response: passkey.create(options),
        });
        answers.created?.(passkey);
      } else if (view.step === TOTP_SETUP) {
        const shown = /<code class="secret">([A-Z2-7 ]+)<\/code>/.exec(
          await stepPage(flow, 'totp-setup')
        )?.[1];
        if (shown === undefined) throw new Error('the set-up page shows no secret');
        const secret = base32Decode(shown.replaceAll(' ', ''));
        response = await answer(flow, TOTP_SETUP, { otp: codeAt(secret, Date.now()) });
        answers.totpSecret?.(secret);
      } else if (view.step === RECOVERY_CODES) {
        response = await answer(flow, RECOVERY_CODES, { acknowledged: 'true' });
      } else {
        throw new Error(`no answer for the step ${view.step}`);
      }
      expect(response.statusCode, response.body).toBe(303);
      const next = locationOf(response);
      if (next.startsWith(ACCOUNT)) return next;
    }
    throw new Error('the ceremony never came back to the account page');
  }

  // ── The tests ──────────────────────────────────────────────────────────

  it('sends a browser with no session through a sign-in, and back to the page', async () => {
    const who = await account();
    const browser: Browser = { jar: new CookieJar() };
    const started = await open(browser, ACCOUNT);
    expect(started.statusCode, started.body).toBe(303);
    expect(await ceremony(browser, started, who, {})).toBe(ACCOUNT);
    const page = await overview(browser);
    expect(page.body).toContain(escaped(who.email));
    expect(csrfOf(page.body).length).toBeGreaterThan(20);
    expect(await eventsOf('user.signed_in', who.userId)).toEqual([{ method: 'password' }]);
  });

  it('refuses every change without a fresh sign-in with the strongest factor, and makes it after one (#663)', async () => {
    const passkey = softPasskey(RP_ID);
    const who = await account(passkey);
    await bindTotp(who.userId);
    const upstreamId = await bindUpstream(who.userId);
    const [passkeyRow] = await query<{ id: string }>(
      "SELECT id::text AS id FROM user_credentials WHERE user_id = $1 AND provider_type = 'webauthn'",
      [who.userId]
    );
    const passkeyId = passkeyRow?.id as string;

    /**
     * Each change that asks for a fresh sign-in, in an order that keeps the
     * passkey, the account's strongest factor, to the last; the answer of
     * the change made.
     */
    const changes: {
      readonly operation: string;
      readonly path: string;
      readonly fields?: Record<string, string>;
      readonly made: (response: LightMyRequestResponse) => void;
    }[] = [
      {
        operation: 'account.password.change',
        path: `${ACCOUNT}/password`,
        fields: { current_password: E2E_PASSWORD, new_password: NEW_PASSWORD },
        made: (response) => expect(locationOf(response)).toBe(`${ACCOUNT}?notice=password_changed`),
      },
      {
        operation: 'account.recoveryCodes.regenerate',
        path: `${ACCOUNT}/recovery-codes/regenerate`,
        made: (response) => {
          expect(response.statusCode, response.body).toBe(200);
          expect(codesOf(response.body).codes).toHaveLength(10);
        },
      },
      {
        operation: 'account.linkedAccounts.delete',
        path: `${ACCOUNT}/linked-accounts/${upstreamId}/unlink`,
        made: (response) => expect(locationOf(response)).toBe(`${ACCOUNT}?notice=unlinked`),
      },
      {
        operation: 'account.totp.delete',
        path: `${ACCOUNT}/totp/remove`,
        made: (response) => expect(locationOf(response)).toBe(`${ACCOUNT}?notice=totp_removed`),
      },
      {
        operation: 'account.passkeys.delete',
        path: `${ACCOUNT}/passkeys/${passkeyId}/remove`,
        made: (response) => expect(locationOf(response)).toBe(`${ACCOUNT}?notice=passkey_removed`),
      },
    ];

    for (const change of changes) {
      const before = await credentialsOf(who.userId);
      // Signed in with the passkey, but ten minutes ago; and a minute ago,
      // with the password alone. Both are refused, and both are recorded.
      for (const browser of [
        await signedIn(who, ['pop', 'mfa'], { ageMs: STALE_MS }),
        await signedIn(who, ['pwd']),
      ]) {
        const refused = await submit(browser, change.path, change.fields);
        expect(refused.statusCode, refused.body).toBe(403);
        expect(refused.body).toContain(REAUTHENTICATE_FORM);
        expect(refused.body).toContain('a passkey');
      }
      expect(await credentialsOf(who.userId)).toEqual(before);
      expect(
        (await eventsOf(REFUSED_EVENT, who.userId)).filter(
          (data) => data['operation'] === change.operation
        )
      ).toEqual([
        { operation: change.operation, reason: 'authentication_too_old', maxAge: 300 },
        {
          operation: change.operation,
          reason: 'strongest_factor_missing',
          requiredFactor: 'pop',
          maxAge: 0,
        },
      ]);
      // A minute ago, with the passkey: the change is made.
      const fresh = await signedIn(who, ['pop', 'mfa']);
      change.made(await submit(fresh, change.path, change.fields));
    }
    expect((await credentialsOf(who.userId)).map((row) => row.provider_type)).toEqual(['password']);
    expect(await eventsOf('user.password_changed', who.userId)).toEqual([{}]);
    expect(await eventsOf('user.credential_removed', who.userId)).toEqual([
      { type: 'totp', credentialId: expect.any(String) },
      { type: 'passkey', credentialId: passkeyId },
    ]);
    expect(await eventsOf('user.recovery_codes_regenerated', who.userId)).toEqual([{}]);
  });

  it('takes a recovery code in place of the lost factor for a removal, never for a password change', async () => {
    const who = await account(softPasskey(RP_ID));
    const [row] = await query<{ id: string }>(
      "SELECT id::text AS id FROM user_credentials WHERE user_id = $1 AND provider_type = 'webauthn'",
      [who.userId]
    );
    // The password, then a code for the passkey: the session says it took one.
    const rebind = await signedIn(who, ['pwd'], { recoveryCodeUsed: true });
    const change = await submit(rebind, `${ACCOUNT}/password`, {
      current_password: E2E_PASSWORD,
      new_password: NEW_PASSWORD,
    });
    expect(change.statusCode, change.body).toBe(403);
    const removed = await submit(rebind, `${ACCOUNT}/passkeys/${row?.id}/remove`);
    expect(locationOf(removed)).toBe(`${ACCOUNT}?notice=passkey_removed`);
  });

  it('makes a refused change after a fresh sign-in through "Confirm it’s you"', async () => {
    const who = await account();
    const browser = await signedIn(who, ['pwd'], { ageMs: STALE_MS });
    const form = await open(browser, `${ACCOUNT}/password`);
    expect(form.statusCode, form.body).toBe(200);
    const refused = await post(browser, `${ACCOUNT}/password`, {
      csrf: csrfOf(form.body),
      current_password: E2E_PASSWORD,
      new_password: NEW_PASSWORD,
    });
    expect(refused.statusCode, refused.body).toBe(403);
    expect(refused.body).toContain(`name="return_to" value="${ACCOUNT}/password"`);

    const started = await post(browser, `${ACCOUNT}/reauthenticate`, {
      csrf: csrfOf(refused.body),
      return_to: `${ACCOUNT}/password`,
    });
    expect(await ceremony(browser, started, who, {})).toBe(`${ACCOUNT}/password?notice=confirmed`);

    const again = await open(browser, `${ACCOUNT}/password`);
    expect(again.statusCode, again.body).toBe(200);
    const changed = await post(browser, `${ACCOUNT}/password`, {
      csrf: csrfOf(again.body),
      current_password: E2E_PASSWORD,
      new_password: NEW_PASSWORD,
    });
    expect(locationOf(changed)).toBe(`${ACCOUNT}?notice=password_changed`);
    expect(await eventsOf('user.password_changed', who.userId)).toEqual([{}]);
  });

  it('refuses a form post without the CSRF value, with another, or from another site', async () => {
    const who = await account();
    const browser = await signedIn(who, ['pwd']);
    const csrf = csrfOf((await overview(browser)).body);
    const someId = randomUUID();

    // Every form of the pages, without its value.
    for (const path of [
      `${ACCOUNT}/password`,
      `${ACCOUNT}/reauthenticate`,
      `${ACCOUNT}/passkeys/add`,
      `${ACCOUNT}/passkeys/${someId}/rename`,
      `${ACCOUNT}/passkeys/${someId}/remove`,
      `${ACCOUNT}/totp/setup`,
      `${ACCOUNT}/totp/remove`,
      `${ACCOUNT}/recovery-codes/regenerate`,
      `${ACCOUNT}/recovery-codes/confirm`,
      `${ACCOUNT}/sessions/${someId}/end`,
      `${ACCOUNT}/sessions/end-all`,
      `${ACCOUNT}/linked-accounts/link`,
      `${ACCOUNT}/linked-accounts/${someId}/unlink`,
    ]) {
      // A form with a field, so the body is a form and not an empty one.
      const refused = await post(browser, path, { unrelated: '1' });
      expect(refused.statusCode, `${path}: ${refused.body}`).toBe(403);
    }
    // Another value, or the right one from another site.
    for (const [fields, headers] of [
      [{ csrf: `${csrf}x` }, SAME_ORIGIN],
      [{ csrf }, { origin: ORIGIN, 'sec-fetch-site': 'cross-site' }],
      [{ csrf }, { origin: 'https://evil.example' }],
    ] as const) {
      const refused = await post(browser, `${ACCOUNT}/sessions/end-all`, fields, headers);
      expect(refused.statusCode, refused.body).toBe(403);
    }
    expect(await eventsOf('request.csrf_rejected', who.userId)).toEqual(
      Array.from({ length: 14 }, () => ({ form: 'account' }))
    );
    // Nothing was ended: the session still opens the page.
    await overview(browser);
    // With the value, from the page's own origin, the same post is made.
    const ended = await post(browser, `${ACCOUNT}/sessions/end-all`, { csrf });
    expect(ended.statusCode, ended.body).toBe(200);
  });

  it('refuses a new password that breaks the password policy with the policy’s message', async () => {
    const who = await account();
    const browser = await signedIn(who, ['pwd']);
    const [stored] = await query<{ hash: string }>(
      "SELECT credential_data->>'password_hash' AS hash FROM user_credentials WHERE user_id = $1 AND provider_type = 'password'",
      [who.userId]
    );

    // The policy's own message for it, as registration gives it.
    const weak = 'aaaaaaaaaaaaaaaa';
    const realm = await server().repositories.realms.findById(realmId);
    if (!realm) throw new Error('default realm missing');
    const { accountPoliciesOf } = await import('./helpers/account-policies');
    const policies = accountPoliciesOf(server(), realm);
    const checked = server()
      .passwordValidators.forPolicy({
        minLength: policies.passwordMinLength,
        minScore: policies.passwordMinScore,
      })
      .check(weak, { email: who.email, serviceName: policies.serviceName, realmName: realm.name });
    if (checked.valid) throw new Error('the weak password meets the policy');
    expect(checked.feedback.length).toBeGreaterThan(0);

    const refused = await submit(browser, `${ACCOUNT}/password`, {
      current_password: E2E_PASSWORD,
      new_password: weak,
    });
    expect(refused.statusCode, refused.body).toBe(400);
    for (const message of checked.feedback) expect(refused.body).toContain(escaped(message));
    // A wrong current password is refused as itself.
    const wrong = await submit(browser, `${ACCOUNT}/password`, {
      current_password: 'not-the-password',
      new_password: NEW_PASSWORD,
    });
    expect(wrong.statusCode, wrong.body).toBe(400);
    expect(wrong.body).toContain(escaped('That is not your current password.'));
    // The password is the one it was.
    expect(
      await query(
        "SELECT credential_data->>'password_hash' AS hash FROM user_credentials WHERE user_id = $1 AND provider_type = 'password'",
        [who.userId]
      )
    ).toEqual([stored]);
    expect(await eventsOf('user.password_changed', who.userId)).toEqual([]);

    // A new one that meets it: changed, every other session ended, this one kept.
    const other = await signedIn(who, ['pwd']);
    const changed = await submit(browser, `${ACCOUNT}/password`, {
      current_password: E2E_PASSWORD,
      new_password: NEW_PASSWORD,
    });
    expect(locationOf(changed)).toBe(`${ACCOUNT}?notice=password_changed`);
    await overview(browser);
    const gone = await open(other, ACCOUNT);
    expect(gone.statusCode, gone.body).toBe(303);
    expect(locationOf(gone).startsWith(CEREMONY_PAGE_PREFIX)).toBe(true);
    await vi.waitFor(
      () =>
        expect((mails.get(who.email) ?? []).map((mail) => mail.template)).toContain(
          'password_changed'
        ),
      { timeout: 5_000, interval: 20 }
    );
  });

  it('refuses to remove the account’s last way to sign in', async () => {
    // A passkey-only account: its passkey is the last way in.
    const passkey = softPasskey(RP_ID);
    const only = await account(passkey);
    await query("DELETE FROM user_credentials WHERE user_id = $1 AND provider_type = 'password'", [
      only.userId,
    ]);
    const [row] = await credentialsOf(only.userId);
    expect(row?.provider_type).toBe('webauthn');
    const browser = await signedIn(only, ['pop', 'mfa']);
    const refused = await submit(browser, `${ACCOUNT}/passkeys/${row?.id}/remove`);
    expect(refused.statusCode, refused.body).toBe(409);
    expect(refused.body).toContain('This is your last way to sign in');
    expect(await credentialsOf(only.userId)).toEqual([row]);

    // A passkey and an authenticator app: the app is no way in on its own.
    await bindTotp(only.userId);
    const withApp = await submit(browser, `${ACCOUNT}/passkeys/${row?.id}/remove`);
    expect(withApp.statusCode, withApp.body).toBe(409);
    expect(await eventsOf('user.credential_removed', only.userId)).toEqual([]);

    // The last linked account of an account with nothing else.
    const linked = await account();
    const upstreamId = await bindUpstream(linked.userId);
    await query("DELETE FROM user_credentials WHERE user_id = $1 AND provider_type = 'password'", [
      linked.userId,
    ]);
    const unlinked = await submit(
      await signedIn(linked, ['pwd']),
      `${ACCOUNT}/linked-accounts/${upstreamId}/unlink`
    );
    expect(unlinked.statusCode, unlinked.body).toBe(409);
    expect((await credentialsOf(linked.userId)).map((credential) => credential.id)).toEqual([
      upstreamId,
    ]);
  });

  /** A relying party of the realm, with a back-channel logout URI if one is given. */
  async function relyingParty(uri: string | null): Promise<{ id: string; clientId: string }> {
    const clientId = `rp-${randomUUID()}`;
    const [row] = await query<{ id: string }>(
      `INSERT INTO oauth_clients
         (realm_id, client_id, client_secret_hash, name, redirect_uris,
          backchannel_logout_uri, backchannel_logout_uri_source,
          backchannel_logout_session_required)
       VALUES ($1, $2, 'h', 'Relying party', '["https://rp.example/cb"]', $3, $4, true)
       RETURNING id::text AS id`,
      [realmId, clientId, uri, uri === null ? null : 'client']
    );
    return { id: row?.id as string, clientId };
  }

  /** The session served `clients`, as the code mint records it. */
  async function served(sid: string, clients: readonly { id: string }[]): Promise<void> {
    for (const client of clients) {
      await query('INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2)', [
        sid,
        client.id,
      ]);
    }
  }

  /** The `sid` of every logout token `server` received for `audience`, each verified. */
  async function logoutTokenSids(audience: string): Promise<string[]> {
    const discovery = await server().inject({
      method: 'GET',
      url: '/.well-known/openid-configuration',
    });
    const { jwks_uri: jwksUri } = discovery.json<{ jwks_uri: string }>();
    const jwks = await server().inject({ method: 'GET', url: new URL(jwksUri).pathname });
    const keys = createLocalJWKSet(jwks.json<JSONWebKeySet>());
    const sids: string[] = [];
    for (const request of receiver.requests) {
      const token = new URLSearchParams(request.body.toString('utf8')).get('logout_token');
      const { payload } = await jwtVerify(token as string, keys, {
        issuer: ORIGIN,
        audience,
        typ: 'logout+jwt',
      });
      expect(payload['events']).toEqual({ [BACKCHANNEL_LOGOUT_EVENT]: {} });
      sids.push(String(payload['sid']));
    }
    return sids.sort();
  }

  it('signs one session out, then every session, and each relying party with a back-channel logout URI is sent a logout token', async () => {
    const rp = await relyingParty('https://rp.egress.test/backchannel');
    const silent = await relyingParty(null);
    // The first fan-out that sees a destination starts at the horizon: the
    // sessions end only once the back-channel logout position exists.
    await vi.waitFor(
      async () =>
        expect(
          await query(
            `SELECT 1 FROM event_delivery_positions
              WHERE realm_id = $1 AND destination_kind = 'backchannel_logout'`,
            [realmId]
          )
        ).toHaveLength(1),
      { timeout: 15_000, interval: 100 }
    );
    const who = await account();
    const browser = await signedIn(who, ['pwd']);
    const laptop = await signedIn(who, ['pwd']);
    const phone = await signedIn(who, ['pwd']);
    await served(browser.sid, [rp]);
    await served(laptop.sid, [rp, silent]);
    await served(phone.sid, [rp]);
    const page = await overview(browser);
    expect(page.body).toContain(`action="${ACCOUNT}/sessions/${laptop.sid}/end"`);
    expect(page.body).toContain(`action="${ACCOUNT}/sessions/${phone.sid}/end"`);
    expect(page.body).toContain('Sign out of this browser');

    // One session: the laptop's.
    const one = await submit(browser, `${ACCOUNT}/sessions/${laptop.sid}/end`);
    expect(locationOf(one)).toBe(`${ACCOUNT}?notice=session_ended`);
    await vi.waitFor(() => expect(receiver.requests).toHaveLength(1), {
      timeout: 20_000,
      interval: 200,
    });
    expect(await logoutTokenSids(rp.clientId)).toEqual([laptop.sid]);
    expect((await open(laptop, ACCOUNT)).statusCode).toBe(303);

    // Every session: this browser's and the phone's.
    const everywhere = await submit(browser, `${ACCOUNT}/sessions/end-all`);
    expect(everywhere.statusCode, everywhere.body).toBe(200);
    expect(String(everywhere.headers['set-cookie'])).toContain('__Host-qauth_session=;');
    expect(
      await query('SELECT 1 FROM sessions WHERE user_id = $1 AND revoked_at IS NULL', [who.userId])
    ).toEqual([]);
    await vi.waitFor(() => expect(receiver.requests).toHaveLength(3), {
      timeout: 20_000,
      interval: 200,
    });
    expect(await logoutTokenSids(rp.clientId)).toEqual([laptop.sid, browser.sid, phone.sid].sort());
    // The relying party without a URI is sent nothing; nor is any one twice.
    await new Promise((resolve) => setTimeout(resolve, 2_000));
    expect(receiver.requests).toHaveLength(3);
    for (const other of [browser, phone]) {
      const reopened = await open(other, ACCOUNT);
      expect(reopened.statusCode, reopened.body).toBe(303);
      expect(locationOf(reopened).startsWith(CEREMONY_PAGE_PREFIX)).toBe(true);
    }
    expect(await eventsOf('user.signed_out', who.userId)).toEqual([{ sid: laptop.sid }, {}]);
  });

  it('replaces the recovery codes with a new set, shown once, and an old code no longer works', async () => {
    const who = await account(softPasskey(RP_ID));
    const browser = await signedIn(who, ['pop', 'mfa']);

    const first = await submit(browser, `${ACCOUNT}/recovery-codes/regenerate`);
    expect(first.statusCode, first.body).toBe(200);
    expect(first.headers['cache-control']).toBe('no-store');
    const old = codesOf(first.body);
    expect(old.codes).toHaveLength(10);
    const saved = await post(browser, `${ACCOUNT}/recovery-codes/confirm`, {
      csrf: csrfOf(first.body),
      set_id: old.setId,
    });
    expect(locationOf(saved)).toBe(`${ACCOUNT}?notice=recovery_codes_saved`);

    const second = await submit(browser, `${ACCOUNT}/recovery-codes/regenerate`);
    expect(second.statusCode, second.body).toBe(200);
    const fresh = codesOf(second.body);
    expect(fresh.codes).toHaveLength(10);
    expect(fresh.codes.filter((code) => old.codes.includes(code))).toEqual([]);
    // The set is stored as hashes, never as the codes.
    const stored = JSON.stringify(
      await query('SELECT code_hash FROM user_recovery_codes WHERE user_id = $1', [who.userId])
    );
    for (const code of fresh.codes) expect(stored).not.toContain(code.replaceAll('-', ''));
    // The old set's page is out of date: its confirmation says so.
    const stale = await post(browser, `${ACCOUNT}/recovery-codes/confirm`, {
      csrf: csrfOf(second.body),
      set_id: old.setId,
    });
    expect(locationOf(stale)).toBe(`${ACCOUNT}?notice=recovery_codes_replaced`);

    // Every old code is refused where a sign-in redeems it; a new one is taken.
    const redeem = (code: string) =>
      recoveryCodes().redeem({
        realmId,
        userId: who.userId,
        clientId: 'urn:qauth:account-pages',
        code,
      });
    for (const code of old.codes) expect(await redeem(code)).toEqual({ kind: 'refused' });
    expect(await redeem(fresh.codes[0] as string)).toEqual({ kind: 'redeemed' });
    expect(await eventsOf('user.recovery_codes_regenerated', who.userId)).toEqual([{}, {}]);

    // An account with no second factor has nothing for a set to stand in for.
    const plain = await account();
    const refused = await submit(
      await signedIn(plain, ['pwd']),
      `${ACCOUNT}/recovery-codes/regenerate`
    );
    expect(refused.statusCode, refused.body).toBe(409);
  });

  it('end to end with no JavaScript: change the password, add and remove a passkey, set up an authenticator app, sign out everywhere', async () => {
    const who = await account();
    const browser: Browser = { jar: new CookieJar() };

    // Signed in through the hosted pages, back on the account page.
    expect(await ceremony(browser, await open(browser, ACCOUNT), who, {})).toBe(ACCOUNT);

    // The password, under the minutes the sign-in left.
    const form = await open(browser, `${ACCOUNT}/password`);
    expect(form.statusCode, form.body).toBe(200);
    const changed = await post(browser, `${ACCOUNT}/password`, {
      csrf: csrfOf(form.body),
      current_password: E2E_PASSWORD,
      new_password: NEW_PASSWORD,
    });
    expect(locationOf(changed)).toBe(`${ACCOUNT}?notice=password_changed`);

    // A passkey: a fresh sign-in with the new password, the mailbox code of
    // the account's first factor beyond it, the passkey, the recovery codes.
    let added: SoftPasskey | undefined;
    const addition = await submit(browser, `${ACCOUNT}/passkeys/add`);
    expect(
      await ceremony(browser, addition, who, {
        password: NEW_PASSWORD,
        created: (passkey) => {
          added = passkey;
        },
      })
    ).toBe(`${ACCOUNT}?notice=passkey`);
    if (added === undefined) throw new Error('no passkey was created');
    const passkeys = await query<{ id: string }>(
      "SELECT id::text AS id FROM user_credentials WHERE user_id = $1 AND provider_type = 'webauthn' AND external_sub = $2",
      [who.userId, added.credentialId]
    );
    expect(passkeys).toHaveLength(1);
    const passkeyId = passkeys[0]?.id as string;
    expect((await overview(browser)).body).toContain(
      `action="${ACCOUNT}/passkeys/${passkeyId}/remove"`
    );

    // Its removal asks for the passkey itself: "Confirm it's you" with it.
    const refused = await submit(browser, `${ACCOUNT}/passkeys/${passkeyId}/remove`);
    expect(refused.statusCode, refused.body).toBe(403);
    const confirming = await post(browser, `${ACCOUNT}/reauthenticate`, {
      csrf: csrfOf(refused.body),
      return_to: ACCOUNT,
    });
    expect(await ceremony(browser, confirming, who, { passkey: added })).toBe(
      `${ACCOUNT}?notice=confirmed`
    );
    const removed = await submit(browser, `${ACCOUNT}/passkeys/${passkeyId}/remove`);
    expect(locationOf(removed)).toBe(`${ACCOUNT}?notice=passkey_removed`);

    // An authenticator app: a fresh sign-in, the app's first code, and the
    // mailbox again: each binding proves it in its own sign-in.
    let secret: Buffer | undefined;
    const setup = await submit(browser, `${ACCOUNT}/totp/setup`);
    expect(
      await ceremony(browser, setup, who, {
        password: NEW_PASSWORD,
        totpSecret: (shown) => {
          secret = shown;
        },
      })
    ).toBe(`${ACCOUNT}?notice=totp`);
    expect(secret).toHaveLength(20);
    expect((await credentialsOf(who.userId)).map((row) => row.provider_type)).toEqual([
      'password',
      'totp',
    ]);
    expect(await eventsOf('user.credential_added', who.userId)).toEqual([
      { type: 'passkey', credentialId: passkeyId },
      { type: 'totp', credentialId: expect.any(String) },
    ]);

    // Sign out everywhere: this browser too.
    const everywhere = await submit(browser, `${ACCOUNT}/sessions/end-all`);
    expect(everywhere.statusCode, everywhere.body).toBe(200);
    expect(
      await query('SELECT 1 FROM sessions WHERE user_id = $1 AND revoked_at IS NULL', [who.userId])
    ).toEqual([]);
    const after = await open(browser, ACCOUNT);
    expect(after.statusCode, after.body).toBe(303);
    expect(locationOf(after).startsWith(CEREMONY_PAGE_PREFIX)).toBe(true);
  });
});
