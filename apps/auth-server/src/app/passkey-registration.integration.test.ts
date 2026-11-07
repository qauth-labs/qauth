import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  decodeJwtClaims,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  pkcePair,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { type SoftPasskey, softPasskey, type SoftPasskeyCreation } from '../testing/soft-passkey';

/**
 * PASSKEY-ONLY ACCOUNTS ON THE HOSTED PAGES (#655; ADR-017 Decision 8 and
 * phase F2b, `graphs/flows/core/passkey-sign-up`), end to end against real
 * Postgres and Redis, booted with `WEBAUTHN_ENABLED=true` and
 * INTERACTION_UI_ENABLED on.
 *
 * The passkey is a software authenticator (`testing/soft-passkey.ts`) whose
 * registrations and assertions the server's own WebAuthn verifier checks. It
 * proves the issue's criteria:
 *
 * - `WEBAUTHN_ENABLED=true` boots, and a registration offers a passkey first.
 * - A registration by passkey creates a user and a `webauthn` credential, with
 *   no email attribute and no password, recorded as a passkey registration.
 * - No code is issued before the recovery codes are confirmed.
 * - The account signs in with its passkey, under a realm that requires a
 *   verified account.
 * - A recovery code recovers a lost passkey on the hosted pages: it finds the
 *   account by itself, binds a new passkey, and the new passkey signs in.
 * - No mail is attempted at any of it: the notices are the security log.
 * - The realm's and the client's sign-up rules apply (PRO-16).
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
const RP_ID = 'auth.example.com';
const CLIENT_ID = 'passkey-registration-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const IDENTIFIER = stepUrn('identifier');
const EMAIL_CODE = stepUrn('email_code');
const WEBAUTHN_GET = stepUrn('webauthn_get');
const WEBAUTHN_CREATE = stepUrn('webauthn_create');
const RECOVERY_CODE = stepUrn('recovery_code');
const RECOVERY_CODES = stepUrn('recovery_codes');
const NEW_PASSWORD = stepUrn('new_password');
const CONSENT = stepUrn('consent');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
const IP = '203.0.113.20';
/** An address of the registration that takes the address instead. */
const ADDRESS = 'address-person@example.test';
/** The browser session's cookie. */
const SESSION_COOKIE = '__Host-qauth_session';

/** The step view the ceremony page reads. */
interface StepView {
  readonly step: string;
  readonly csrf: string;
  readonly alternatives?: readonly string[];
  readonly params?: Record<string, Record<string, unknown>>;
  readonly error?: string;
}

/** An interaction in progress: its browser, its id and its PKCE verifier. */
interface Flow {
  readonly jar: CookieJar;
  readonly id: string;
  readonly verifier: string;
}

/** A passkey-only account the suite registered. */
interface Registered {
  readonly userId: string;
  readonly passkey: SoftPasskey;
  readonly codes: readonly string[];
}

describe('passkey-only accounts on the hosted pages (#655, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';
  let clientRowId = '';
  /** Every mail the server attempted, by method. */
  const attempted: string[] = [];
  /** The codes the attempted mails carried, in order. */
  const mailedCodes: string[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    // The switch itself, as an operator sets it: no test option turns the
    // passkey steps on.
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      INTERACTION_UI_ENABLED: 'true',
      WEBAUTHN_ENABLED: 'true',
      // Each test starts a few registrations from one IP.
      REGISTRATION_RATE_LIMIT: '10000',
    });
    // Every send the mail service offers is recorded, whatever its template.
    const service = booted.app.emailService as unknown as Record<string, unknown>;
    for (const name of ['sendEngineMail', 'sendVerificationEmail', 'sendAccountExistsEmail']) {
      const original = service[name];
      if (typeof original !== 'function') continue;
      service[name] = async (...args: unknown[]) => {
        attempted.push(name);
        for (const arg of args) {
          const code = (arg as { code?: unknown } | null)?.code;
          if (typeof code === 'string') mailedCodes.push(code);
        }
        return (original as (...inner: unknown[]) => unknown).apply(service, args);
      };
    }
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  async function query<Row extends Record<string, unknown>>(
    sql: string,
    params: unknown[] = []
  ): Promise<Row[]> {
    const { rows } = await server().dbPool.query<Row>(sql, params);
    return rows;
  }

  /**
   * The realm's account policies, as an operator sets them: through the
   * policy store at the counter it has now, the host cache dropped so the
   * next request reads the row.
   */
  async function realmAccounts(accounts: {
    readonly allowSignUp?: boolean;
    readonly requireVerifiedAccount?: boolean;
  }): Promise<void> {
    const current = await server().policyStore.get(realmId);
    if (current === undefined) throw new Error(`no policies for realm ${realmId}`);
    await server().policyStore.update(realmId, { accounts }, { expectedVersion: current.version });
    server().realmHostCache.clear();
  }

  /** The client's operator-set flow list (#640), as the seed manifest writes it. */
  async function clientFlows(flows: string[] | null): Promise<void> {
    await query('UPDATE oauth_clients SET hosted_flows = $2::jsonb WHERE id = $1', [
      clientRowId,
      flows === null ? null : JSON.stringify(flows),
    ]);
  }

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    const app = booted.app;
    await resetE2eState(app);
    attempted.length = 0;
    mailedCodes.length = 0;
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
    const client = await app.repositories.oauthClients.create({
      realmId,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Passkey registration app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code'],
      enabled: true,
      requirePkce: true,
      // A seeded client: its redirect URI receives authorization errors.
      provisionedByOperator: true,
    });
    clientRowId = client.id;
    await realmAccounts({ allowSignUp: true, requireVerifiedAccount: true });
    await clientFlows(['register']);
  }, 120_000);

  /** `/oauth/authorize` for the client from a new browser: `prompt=create` when `register`. */
  async function authorize(register: boolean): Promise<LightMyRequestResponse & { flow?: Flow }> {
    const jar = new CookieJar();
    const { verifier, challenge } = pkcePair();
    const response = await server().inject({
      method: 'GET',
      remoteAddress: IP,
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'passkey-registration-state',
        ...(register ? { prompt: 'create' } : {}),
      }).toString()}`,
    });
    jar.absorb(response.headers['set-cookie']);
    const location = String(response.headers['location'] ?? '');
    const path = location.startsWith(`${ORIGIN}/`) ? location.slice(ORIGIN.length) : location;
    if (!path.startsWith(CEREMONY_PAGE_PREFIX)) return response;
    return Object.assign(response, {
      flow: { jar, id: path.slice(CEREMONY_PAGE_PREFIX.length), verifier },
    });
  }

  /** A new interaction, which must start at a ceremony page. */
  async function start(register: boolean): Promise<Flow> {
    const response = await authorize(register);
    expect(response.flow, String(response.headers['location'])).toBeDefined();
    return response.flow as Flow;
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

  /** The current step's personal data, for the browser whose flow cookie binds it. */
  async function personal(flow: Flow): Promise<Record<string, Record<string, unknown>>> {
    const response = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${flow.id}/personal`,
      headers: { cookie: flow.jar.header() ?? '' },
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json<{ data: Record<string, Record<string, unknown>> }>().data;
  }

  /** Answer with a form post from the ceremony page. */
  async function answer(
    flow: Flow,
    type: string,
    fields: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    const { csrf } = await read(flow.id);
    const response = await server().inject({
      method: 'POST',
      remoteAddress: IP,
      url: `${INTERACTION_API_PREFIX}/${flow.id}/answer`,
      headers: { ...FORM, ...SAME_ORIGIN, cookie: flow.jar.header() ?? '' },
      payload: new URLSearchParams({ type, csrf, ...fields }).toString(),
    });
    flow.jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** A hosted `/ui` page of the interaction, opened by its browser. */
  async function page(flow: Flow, path: string): Promise<LightMyRequestResponse> {
    const response = await server().inject({
      method: 'GET',
      url: `/ui/${path}/${flow.id}`,
      headers: { cookie: flow.jar.header() ?? '', 'sec-fetch-site': 'same-origin' },
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    return response;
  }

  /** The creation options the "add a passkey" page hands the browser's ceremony. */
  function creationOptionsOf(body: string): SoftPasskeyCreation & {
    readonly user: { readonly id: string; readonly name: string };
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

  /** The code a finished interaction's redirect carries, through its consent. */
  async function codeOf(flow: Flow, response: LightMyRequestResponse): Promise<string> {
    let location = String(response.headers['location']);
    if (!location.startsWith(REDIRECT_URI)) {
      const consentId = locationOf(response).slice(CEREMONY_PAGE_PREFIX.length);
      expect((await read(consentId)).step).toBe(CONSENT);
      const allowed = await answer({ ...flow, id: consentId }, CONSENT, { decision: 'allow' });
      expect(allowed.statusCode, allowed.body).toBe(303);
      location = String(allowed.headers['location']);
    }
    const callback = new URL(location);
    expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
    const code = callback.searchParams.get('code');
    if (code === null) throw new Error(`no code at ${location}`);
    return code;
  }

  /** The ID token's claims for a finished interaction. */
  async function idTokenOf(
    flow: Flow,
    response: LightMyRequestResponse
  ): Promise<Record<string, unknown>> {
    const code = await codeOf(flow, response);
    const exchanged = await server().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: flow.verifier,
      }).toString(),
    });
    expect(exchanged.statusCode, exchanged.body).toBe(200);
    return decodeJwtClaims(exchanged.json<{ id_token: string }>().id_token);
  }

  async function eventsOf(type: string, userId: string): Promise<Record<string, unknown>[]> {
    const rows = await query<{ data: Record<string, unknown> }>(
      'SELECT data FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
      [`urn:qauth:event:${type}:v1-rc.0`, userId]
    );
    return rows.map((row) => row.data);
  }

  async function userCount(): Promise<number> {
    const [row] = await query<{ count: string }>('SELECT count(*) AS count FROM users');
    return Number(row?.count ?? 0);
  }

  /** The mails attempted, once a send started off the request path had its time. */
  async function mailsAttempted(): Promise<readonly string[]> {
    await new Promise((resolve) => setTimeout(resolve, 300));
    return [...attempted];
  }

  /**
   * A registration by passkey up to the account and its recovery set, on the
   * hosted pages: the "create your account with a passkey" page's options,
   * the software authenticator's answer, then the set shown. Returns the
   * flow at its `recovery_codes` step.
   */
  async function registerUpToCodes(): Promise<Registered & { readonly flow: Flow }> {
    const flow = await start(true);
    const created = await page(flow, 'passkey-enrolment');
    expect(created.body).toContain('Create your account with a passkey');
    const options = creationOptionsOf(created.body);
    const passkey = softPasskey(RP_ID, options.user.id);
    const usersBefore = await userCount();

    const answered = await answer(flow, WEBAUTHN_CREATE, {
      webauthn_response: passkey.create(options),
    });
    expect(answered.statusCode, answered.body).toBe(303);
    expect(String(answered.headers['location'])).not.toContain(REDIRECT_URI);
    expect(await userCount()).toBe(usersBefore + 1);

    const [credential] = await query<{ user_id: string }>(
      "SELECT user_id FROM user_credentials WHERE provider_type = 'webauthn' AND external_sub = $1",
      [passkey.credentialId]
    );
    const userId = credential?.user_id as string;
    expect((await read(flow.id)).step).toBe(RECOVERY_CODES);
    const shown = (await personal(flow))[RECOVERY_CODES] as { codes?: unknown } | undefined;
    const codes = shown?.codes as string[];
    expect(codes).toHaveLength(10);
    return { flow, userId, passkey, codes };
  }

  /** A registered passkey-only account, its codes confirmed and its first code issued. */
  async function registered(): Promise<Registered> {
    const { flow, ...account } = await registerUpToCodes();
    const confirmed = await answer(flow, RECOVERY_CODES, { acknowledged: 'true' });
    expect(confirmed.statusCode, confirmed.body).toBe(303);
    await codeOf(flow, confirmed);
    attempted.length = 0;
    return account;
  }

  it('boots with WEBAUTHN_ENABLED=true and offers a passkey first at a registration', async () => {
    expect(server().passkeySignIn).toBe(true);
    const usersBefore = await userCount();
    const flow = await start(true);

    const first = await read(flow.id);
    expect(first.step).toBe(WEBAUTHN_CREATE);
    expect(first.alternatives).toEqual([IDENTIFIER]);
    expect(first.params?.[WEBAUTHN_CREATE]).toMatchObject({
      optional: false,
      options: {
        rp: { id: RP_ID },
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      },
    });
    // The page links the address step beside the passkey.
    const shown = await page(flow, 'passkey-enrolment');
    expect(shown.body).toContain('Use an email address instead');
    // Nobody exists before the ceremony.
    expect(await userCount()).toBe(usersBefore);

    // The address registration is still beside it: its code is mailed, and
    // the code leads on to the new password.
    const identified = await answer(flow, IDENTIFIER, { login_hint: ADDRESS });
    expect(identified.statusCode, identified.body).toBe(303);
    expect((await read(flow.id)).step).toBe(EMAIL_CODE);
    const deadline = performance.now() + 5_000;
    while (mailedCodes.length === 0 && performance.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const coded = await answer(flow, EMAIL_CODE, { otp: mailedCodes[0] as string });
    expect(coded.statusCode, coded.body).toBe(303);
    expect((await read(flow.id)).step).toBe(NEW_PASSWORD);
  });

  it('creates the account with its passkey and no address, and issues no code before the codes are confirmed', async () => {
    const { flow, userId, passkey, codes } = await registerUpToCodes();

    // A user and a webauthn credential: no password, no email attribute.
    expect(
      await query('SELECT provider_type, external_sub FROM user_credentials WHERE user_id = $1', [
        userId,
      ])
    ).toEqual([{ provider_type: 'webauthn', external_sub: passkey.credentialId }]);
    expect(
      await query('SELECT attr_key FROM user_attributes WHERE user_id = $1', [userId])
    ).toEqual([]);
    expect(await eventsOf('user.registered', userId)).toEqual([{ method: 'passkey' }]);
    expect(await eventsOf('user.signed_in', userId)).toEqual([]);

    // The set is stored with a lookup digest per code, never as the codes.
    const stored = await query<{ code_hash: string; lookup_digest: string | null }>(
      'SELECT code_hash, lookup_digest FROM user_recovery_codes WHERE user_id = $1',
      [userId]
    );
    expect(stored).toHaveLength(10);
    for (const row of stored) expect(row.lookup_digest).toMatch(/^argon2id\$/);
    const rows = JSON.stringify(stored);
    for (const code of codes) expect(rows).not.toContain(code.replaceAll('-', ''));

    // The hosted page shows the set; no code exists while it is unconfirmed.
    await page(flow, 'recovery-codes');
    expect(await query('SELECT 1 FROM authorization_codes WHERE user_id = $1', [userId])).toEqual(
      []
    );

    const confirmed = await answer(flow, RECOVERY_CODES, { acknowledged: 'true' });
    expect(confirmed.statusCode, confirmed.body).toBe(303);
    const claims = await idTokenOf(flow, confirmed);
    expect(claims['sub']).toBe(userId);
    // A registration is no sign-in (ADR-017 Decision 10), and there is no address.
    expect(claims).not.toHaveProperty('amr');
    expect(claims).not.toHaveProperty('auth_time');
    expect(claims).not.toHaveProperty('email');

    expect(await mailsAttempted()).toEqual([]);
  });

  it('refuses a passkey the user did not verify, and creates nobody', async () => {
    const flow = await start(true);
    const options = creationOptionsOf((await page(flow, 'passkey-enrolment')).body);
    const usersBefore = await userCount();

    const refused = await answer(flow, WEBAUTHN_CREATE, {
      webauthn_response: softPasskey(RP_ID, options.user.id).create(options, {
        userVerified: false,
      }),
    });
    expect(refused.statusCode, refused.body).toBe(303);
    const again = await read(flow.id);
    expect(again.step).toBe(WEBAUTHN_CREATE);
    expect(again.error).toBe('invalid_credentials');
    expect(await userCount()).toBe(usersBefore);
  });

  it('signs in with its passkey, under a realm that requires a verified account', async () => {
    const { userId, passkey } = await registered();
    const flow = await start(false);

    const first = await read(flow.id);
    expect(first.step).toBe(WEBAUTHN_GET);
    // "Try another way": a recovery code beside the first steps, for every account.
    expect(first.alternatives).toEqual(expect.arrayContaining([IDENTIFIER, RECOVERY_CODE]));
    const request = first.params?.[WEBAUTHN_GET] as { challenge: string; rpId: string };
    const signedIn = await answer(flow, WEBAUTHN_GET, {
      webauthn_response: passkey.assert(request),
    });
    expect(signedIn.statusCode, signedIn.body).toBe(303);

    const claims = await idTokenOf(flow, signedIn);
    expect(claims['sub']).toBe(userId);
    expect(claims['amr']).toEqual(['pop', 'mfa']);
    expect(await eventsOf('user.signed_in', userId)).toEqual([
      expect.objectContaining({ method: 'passkey' }),
    ]);
    expect(await mailsAttempted()).toEqual([]);
  });

  it('recovers a lost passkey with a recovery code on the hosted pages, then signs in with the new one', async () => {
    const { userId, codes, passkey: lost } = await registered();
    /** The passkeys bound to the account, as its events record them. */
    const passkeysBound = async () =>
      (await eventsOf('user.sign_in_step_passed', userId)).filter(
        (data) => data['step'] === WEBAUTHN_CREATE
      ).length;
    const boundBefore = await passkeysBound();
    const flow = await start(false);

    // The hosted page asks for the code offered beside the first steps.
    const asked = await page(flow, 'recovery-code');
    expect(asked.body).toContain('name="recovery_code"');
    const redeemed = await answer(flow, RECOVERY_CODE, { recovery_code: codes[0] as string });
    expect(redeemed.statusCode, redeemed.body).toBe(303);
    // A code alone never signs in: a new passkey is owed, and no session exists.
    expect(String(redeemed.headers['location'])).not.toContain(REDIRECT_URI);
    expect(flow.jar.header() ?? '').not.toContain(SESSION_COOKIE);
    const owed = await read(flow.id);
    expect(owed.step).toBe(WEBAUTHN_CREATE);
    expect(owed.alternatives ?? []).toEqual([]);
    expect(owed.params?.[WEBAUTHN_CREATE]).toMatchObject({ optional: false });

    const rebind = await page(flow, 'passkey-enrolment');
    expect(rebind.body).toContain('Add a new passkey');
    expect(rebind.body).not.toContain('Not now');
    const options = creationOptionsOf(rebind.body);
    const replacement = softPasskey(RP_ID, options.user.id);
    const bound = await answer(flow, WEBAUTHN_CREATE, {
      webauthn_response: replacement.create(options),
    });
    expect(bound.statusCode, bound.body).toBe(303);
    expect(
      await query(
        "SELECT 1 FROM user_credentials WHERE user_id = $1 AND provider_type = 'webauthn' AND external_sub = $2",
        [userId, replacement.credentialId]
      )
    ).toHaveLength(1);
    // The account has no address, so nothing is mailed: its events record
    // the rebind, as its webauthn_create step passed (the security log's
    // own `credential_added` entry comes with passkey management, #686).
    expect(await passkeysBound()).toBe(boundBefore + 1);

    // The new passkey proves the account: its assertion signs in.
    const proof = await read(flow.id);
    expect(proof.step).toBe(WEBAUTHN_GET);
    const request = proof.params?.[WEBAUTHN_GET] as { challenge: string; rpId: string };
    const signedIn = await answer(flow, WEBAUTHN_GET, {
      webauthn_response: replacement.assert(request),
    });
    expect(signedIn.statusCode, signedIn.body).toBe(303);
    const claims = await idTokenOf(flow, signedIn);
    expect(claims['sub']).toBe(userId);
    expect(claims['amr']).toEqual(['pop', 'mfa']);

    // The code is spent, the others kept; the notice is in the security log,
    // and nothing was mailed.
    expect(
      await query('SELECT 1 FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NOT NULL', [
        userId,
      ])
    ).toHaveLength(1);
    expect(await eventsOf('user.recovery_code_used', userId)).toEqual([{ remaining: 9 }]);
    expect(await mailsAttempted()).toEqual([]);

    // The new passkey took the lost one's place: the lost one is disabled,
    // and signs in no more.
    const [old] = await query<{ disabled_at: string | null }>(
      "SELECT disabled_at FROM user_credentials WHERE provider_type = 'webauthn' AND external_sub = $1",
      [lost.credentialId]
    );
    expect(old?.disabled_at).not.toBeNull();
    const thief = await start(false);
    const offered = (await read(thief.id)).params?.[WEBAUTHN_GET] as {
      challenge: string;
      rpId: string;
    };
    const refused = await answer(thief, WEBAUTHN_GET, { webauthn_response: lost.assert(offered) });
    expect(refused.statusCode, refused.body).toBe(303);
    expect(String(refused.headers['location'])).not.toContain(REDIRECT_URI);
    const again = await read(thief.id);
    expect(again.step).toBe(WEBAUTHN_GET);
    expect(again.error).toBe('invalid_credentials');
  });

  it('refuses a wrong code before any first factor the same way, naming nobody', async () => {
    await registered();
    const flow = await start(false);

    const refused = await answer(flow, RECOVERY_CODE, { recovery_code: 'aaaa-bbbb-cccc-dddd' });
    expect(refused.statusCode, refused.body).toBe(303);
    const again = await read(flow.id);
    expect(again.step).toBe(RECOVERY_CODE);
    expect(again.error).toBe('invalid_credentials');
    expect(await mailsAttempted()).toEqual([]);
  });

  describe('who may register (PRO-16)', () => {
    /** A refusal at the client's redirect URI, with no interaction. */
    function expectRefused(response: LightMyRequestResponse, error: string): void {
      expect(response.statusCode, response.body).toBe(302);
      const location = new URL(String(response.headers['location']));
      expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
      expect(location.searchParams.get('error')).toBe(error);
    }

    it('offers no registration while the realm does not allow sign-up', async () => {
      await realmAccounts({ allowSignUp: false });
      expectRefused(await authorize(true), 'invalid_request');
      // A sign-in offers no passkey creation in its place.
      const first = await read((await start(false)).id);
      expect([first.step, ...(first.alternatives ?? [])]).not.toContain(WEBAUTHN_CREATE);
    });

    it('refuses the passkey of a registration the realm stopped allowing after it started', async () => {
      const flow = await start(true);
      const options = creationOptionsOf((await page(flow, 'passkey-enrolment')).body);
      const passkey = softPasskey(RP_ID, options.user.id);
      const usersBefore = await userCount();
      await realmAccounts({ allowSignUp: false });

      const refused = await answer(flow, WEBAUTHN_CREATE, {
        webauthn_response: passkey.create(options),
      });
      expect(refused.statusCode, refused.body).toBeLessThan(500);
      expect(String(refused.headers['location'] ?? '')).not.toContain('code=');
      expect(await userCount()).toBe(usersBefore);
      expect(
        await query('SELECT 1 FROM user_credentials WHERE external_sub = $1', [
          passkey.credentialId,
        ])
      ).toEqual([]);
    });

    it('offers no registration to a client whose flows do not name register', async () => {
      await clientFlows(null);
      expectRefused(await authorize(true), 'unauthorized_client');
      await clientFlows([]);
      expectRefused(await authorize(true), 'unauthorized_client');
    });
  });
});
