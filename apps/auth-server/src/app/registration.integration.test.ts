import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
import { SIGN_IN_MIN_RESPONSE_TIME_MS } from '@qauth-labs/fastify-plugin-sign-in-engine';
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
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * REGISTRATION INSIDE THE ENGINE, STARTED BY `prompt=create` (#640; ADR-017
 * Decisions 3, 8 and 10; OpenID Connect Prompt Create 1.0;
 * `graphs/flows/core/sign-up`), end to end against real Postgres and Redis,
 * with INTERACTION_UI_ENABLED on.
 *
 * It proves the issue's integration criteria:
 *
 * - `prompt=create` is refused while the realm or the client does not allow
 *   registration, and without the `openid` scope (`invalid_request`).
 * - The first answer is the same for a new address and an existing one, in
 *   body and in timing: the 8-digit `email_code` step.
 * - No account exists before the code and the new password both passed.
 * - The account has a verified password credential and a verified email
 *   attribute.
 * - The code a registration ends in carries no `amr` and no `auth_time`.
 * - A disabled account's address gets no mail, and nothing of the account
 *   changes.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
const CLIENT_ID = 'registration-notes-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const NEW_EMAIL = 'new-person@example.test';
const EXISTING_EMAIL = 'existing-person@example.test';
const DISABLED_EMAIL = 'disabled-person@example.test';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const EMAIL_CODE = stepUrn('email_code');
const NEW_PASSWORD = stepUrn('new_password');
const CONSENT = stepUrn('consent');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
/** An interaction id: 43 base64url characters. */
const INTERACTION_ID = /^[A-Za-z0-9_-]{43}$/;
/** The new account's password: long and unusual, so the realm's policy takes it. */
const NEW_PASSWORD_VALUE = 'Quiet-Lantern-Orbit-Meadow-73';

/** A mail the engine sent: its template and its code, if it carries one. */
interface SentMail {
  readonly template: string;
  readonly code?: string;
}

describe('registration through prompt=create (#640, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';
  let clientRowId = '';
  /** The engine mails, by address, in order. */
  const mails = new Map<string, SentMail[]>();

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      INTERACTION_UI_ENABLED: 'true',
      // Each test starts a few registrations from one IP; the start cap is
      // sized for people.
      REGISTRATION_RATE_LIMIT: '10000',
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
   * Whether the realm allows sign-up, as an operator sets it: its
   * `accounts.allowSignUp`, through the policy store at the counter it has
   * now, the resolver's host cache dropped so the next request reads the row.
   */
  async function realmAllowsSignUp(allowed: boolean): Promise<void> {
    const current = await server().policyStore.get(realmId);
    if (current === undefined) throw new Error(`no policies for realm ${realmId}`);
    await server().policyStore.update(
      realmId,
      { accounts: { allowSignUp: allowed } },
      { expectedVersion: current.version }
    );
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
    mails.clear();
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
    const client = await app.repositories.oauthClients.create({
      realmId,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Registration notes app',
      redirectUris: [REDIRECT_URI],
      scopes: ['openid', 'email'],
      grantTypes: ['authorization_code'],
      enabled: true,
      requirePkce: true,
      // A seeded client: its redirect URI receives authorization errors.
      provisionedByOperator: true,
    });
    clientRowId = client.id;
    await realmAllowsSignUp(true);
    await clientFlows(['register']);
  }, 120_000);

  /** `/oauth/authorize` with `prompt=create` for the client, from the browser holding `jar`. */
  async function authorize(
    jar: CookieJar,
    extra: Record<string, string> = {},
    challenge = pkcePair().challenge
  ): Promise<LightMyRequestResponse> {
    const response = await server().inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: 'openid email',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'registration-state',
        prompt: 'create',
        ...extra,
      }).toString()}`,
      headers: jar.header() === undefined ? {} : { cookie: jar.header() as string },
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** The interaction id of a redirect to a ceremony page. */
  function interactionIdOf(response: LightMyRequestResponse): string {
    expect([302, 303], response.body).toContain(response.statusCode);
    const location = String(response.headers['location']);
    const path = location.startsWith(`${ORIGIN}/`) ? location.slice(ORIGIN.length) : location;
    expect(path.startsWith(CEREMONY_PAGE_PREFIX), location).toBe(true);
    const id = path.slice(CEREMONY_PAGE_PREFIX.length);
    expect(id).toMatch(INTERACTION_ID);
    return id;
  }

  /** The step read, as the ceremony app's server makes it: the id alone, no cookie. */
  async function read(id: string): Promise<{
    step: string;
    csrf: string;
    revision: number;
    params?: Record<string, unknown>;
    error?: string;
  }> {
    const response = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}`,
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json();
  }

  /** Answer the current step with a form post from the ceremony page. */
  async function answer(
    jar: CookieJar,
    id: string,
    type: string,
    fields: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    const { csrf } = await read(id);
    const response = await server().inject({
      method: 'POST',
      url: `${INTERACTION_API_PREFIX}/${id}/answer`,
      headers: { ...FORM, ...SAME_ORIGIN, cookie: jar.header() ?? '' },
      payload: new URLSearchParams({ type, csrf, ...fields }).toString(),
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /**
   * Wait until `count` mails went to `to`, and return the last. The mail goes
   * out after the answer, off the request path.
   */
  async function mailed(to: string, count = 1): Promise<SentMail> {
    const deadline = performance.now() + 5_000;
    while ((mails.get(to)?.length ?? 0) < count && performance.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const sent = mails.get(to) ?? [];
    expect(sent).toHaveLength(count);
    return sent[count - 1] as SentMail;
  }

  /** How many password credentials hold `email`. */
  async function credentialsOf(email: string): Promise<number> {
    const [row] = await query<{ count: string }>(
      "SELECT count(*) AS count FROM user_credentials WHERE provider_type = 'password' AND external_sub = $1",
      [email]
    );
    return Number(row?.count ?? 0);
  }

  async function userCount(): Promise<number> {
    const [row] = await query<{ count: string }>('SELECT count(*) AS count FROM users');
    return Number(row?.count ?? 0);
  }

  /** A registration of {@link NEW_EMAIL}, answered up to the code it mailed. */
  async function atCode(jar: CookieJar, challenge?: string): Promise<{ id: string; code: string }> {
    const id = interactionIdOf(await authorize(jar, {}, challenge));
    expect((await read(id)).step).toBe(IDENTIFIER);
    const identified = await answer(jar, id, IDENTIFIER, { login_hint: NEW_EMAIL });
    expect(identified.statusCode, identified.body).toBe(303);
    const sent = await mailed(NEW_EMAIL);
    expect(sent.template).toBe('code');
    return { id, code: sent.code as string };
  }

  describe('who may register', () => {
    /** A refusal at the client's redirect URI, with state and iss, and no interaction. */
    function expectRefused(response: LightMyRequestResponse, error: string): void {
      expect(response.statusCode, response.body).toBe(302);
      const location = new URL(String(response.headers['location']));
      expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
      expect(location.searchParams.get('error')).toBe(error);
      expect(location.searchParams.get('state')).toBe('registration-state');
      expect(location.searchParams.get('iss')).toBe(ORIGIN);
    }

    it('refuses prompt=create while the realm does not allow sign-up', async () => {
      await realmAllowsSignUp(false);
      expectRefused(await authorize(new CookieJar()), 'invalid_request');
    });

    it('refuses prompt=create for a client whose flows do not name register', async () => {
      await clientFlows(null);
      expectRefused(await authorize(new CookieJar()), 'unauthorized_client');
      await clientFlows([]);
      expectRefused(await authorize(new CookieJar()), 'unauthorized_client');
    });

    it('refuses prompt=create without the openid scope with invalid_request', async () => {
      expectRefused(await authorize(new CookieJar(), { scope: 'email' }), 'invalid_request');
    });

    it('lists create in discovery only while the realm allows sign-up', async () => {
      const values = async () =>
        (
          (
            await server().inject({ method: 'GET', url: '/.well-known/openid-configuration' })
          ).json() as Record<string, unknown>
        )['prompt_values_supported'];
      expect(await values()).toEqual(['none', 'login', 'consent', 'create']);
      await realmAllowsSignUp(false);
      expect(await values()).toEqual(['none', 'login', 'consent']);
    });
  });

  it('answers a new address and an existing one alike, in body and in timing', async () => {
    await registerPasswordAccount(server(), EXISTING_EMAIL);
    mails.clear();

    /** The identifier answer for `email`: its response, its time and the step it leads to. */
    const firstAnswer = async (email: string) => {
      const jar = new CookieJar();
      const id = interactionIdOf(await authorize(jar));
      const startedAt = performance.now();
      const response = await answer(jar, id, IDENTIFIER, { login_hint: email });
      const elapsed = performance.now() - startedAt;
      const step = await read(id);
      return {
        elapsed,
        status: response.statusCode,
        // The location names the interaction's own ceremony page.
        location: String(response.headers['location']).replace(id, '<id>'),
        body: response.body.replaceAll(id, '<id>'),
        step: { step: step.step, params: step.params, error: step.error, revision: step.revision },
      };
    };

    const fresh = await firstAnswer(NEW_EMAIL);
    const existing = await firstAnswer(EXISTING_EMAIL);

    const { elapsed: freshElapsed, ...freshAnswer } = fresh;
    const { elapsed: existingElapsed, ...existingAnswer } = existing;
    expect(existingAnswer).toEqual(freshAnswer);
    expect(freshAnswer.status).toBe(303);
    expect(freshAnswer.step.step).toBe(EMAIL_CODE);
    expect(freshAnswer.step.params?.[EMAIL_CODE]).toEqual({
      purpose: 'verify_account',
      length: 8,
      expires_in: 600,
      resend_after: 60,
    });
    // The engine's floor holds both answers, so neither tells the address apart.
    expect(freshElapsed).toBeGreaterThanOrEqual(SIGN_IN_MIN_RESPONSE_TIME_MS - 5);
    expect(existingElapsed).toBeGreaterThanOrEqual(SIGN_IN_MIN_RESPONSE_TIME_MS - 5);
    expect(Math.abs(freshElapsed - existingElapsed)).toBeLessThan(250);

    // The new address gets its code; the existing one its code and the notice
    // that an account holds it.
    const toNew = await mailed(NEW_EMAIL);
    const toExisting = await mailed(EXISTING_EMAIL);
    expect(toNew.template).toBe('code');
    expect(toNew.code).toMatch(/^[0-9]{8}$/);
    expect(toExisting.template).toBe('account_exists');
    expect(toExisting.code).toMatch(/^[0-9]{8}$/);
  });

  it('creates the account only after the code and the new password, verified, and its code carries no amr or auth_time', async () => {
    const usersBefore = await userCount();
    const jar = new CookieJar();
    const pkce = pkcePair();
    const { id, code } = await atCode(jar, pkce.challenge);
    expect(await credentialsOf(NEW_EMAIL)).toBe(0);

    // A right code: the new password is asked for, and still no account.
    const coded = await answer(jar, id, EMAIL_CODE, { otp: code });
    expect(coded.statusCode, coded.body).toBe(303);
    const asked = await read(id);
    expect(asked.step).toBe(NEW_PASSWORD);
    expect(asked.params?.[NEW_PASSWORD]).toMatchObject({ purpose: 'register' });
    expect(await credentialsOf(NEW_EMAIL)).toBe(0);
    expect(await userCount()).toBe(usersBefore);

    // A password the policy refuses: the step again, and still no account.
    const weak = await answer(jar, id, NEW_PASSWORD, { new_password: 'password' });
    expect(weak.statusCode, weak.body).toBe(303);
    expect((await read(id)).step).toBe(NEW_PASSWORD);
    expect(await credentialsOf(NEW_EMAIL)).toBe(0);

    // A password the policy takes: the account, then the request goes on at
    // its consent, with no browser session.
    const registered = await answer(jar, id, NEW_PASSWORD, { new_password: NEW_PASSWORD_VALUE });
    expect(registered.statusCode, registered.body).toBe(303);
    expect(jar.header() ?? '').not.toContain('qauth_session');
    expect(await userCount()).toBe(usersBefore + 1);

    const [credential] = await query<{ user_id: string; credential_data: Record<string, unknown> }>(
      "SELECT user_id, credential_data FROM user_credentials WHERE provider_type = 'password' AND external_sub = $1",
      [NEW_EMAIL]
    );
    expect(credential?.credential_data).toMatchObject({ email_verified: true });
    const userId = credential?.user_id as string;
    const attributes = await query<{ attr_value: string; verified: boolean }>(
      "SELECT attr_value, verified FROM user_attributes WHERE user_id = $1 AND attr_key = 'email'",
      [userId]
    );
    expect(attributes).toEqual([{ attr_value: NEW_EMAIL, verified: true }]);
    const [registeredEvent] = await query<{ data: Record<string, unknown>; subject_id: string }>(
      "SELECT data, subject_id FROM events WHERE type = 'urn:qauth:event:user.registered:v1-rc.0'"
    );
    expect(registeredEvent).toMatchObject({ data: { method: 'password' }, subject_id: userId });
    const signedIn = await query(
      "SELECT 1 FROM events WHERE type = 'urn:qauth:event:user.signed_in:v1-rc.0'"
    );
    expect(signedIn).toHaveLength(0);

    // The consent, for the new account.
    const consentId = interactionIdOf(registered);
    expect((await read(consentId)).step).toBe(CONSENT);
    const allowed = await answer(jar, consentId, CONSENT, { decision: 'allow' });
    expect(allowed.statusCode, allowed.body).toBe(303);
    const callback = new URL(String(allowed.headers['location']));
    expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
    const authorizationCode = callback.searchParams.get('code') as string;
    expect(authorizationCode).toMatch(/.+/);

    const [stored] = await query<{ auth_time: unknown; session_id: unknown }>(
      'SELECT auth_time, session_id FROM authorization_codes WHERE user_id = $1',
      [userId]
    );
    expect(stored).toEqual({ auth_time: null, session_id: null });

    const token = await server().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code: authorizationCode,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    expect(token.statusCode, token.body).toBe(200);
    const idToken = decodeJwtClaims((token.json() as { id_token: string }).id_token);
    expect(idToken['sub']).toBe(userId);
    expect(idToken).not.toHaveProperty('auth_time');
    expect(idToken).not.toHaveProperty('amr');
    expect(idToken).not.toHaveProperty('sid');
  });

  it('helps the owner of an existing verified account sign in after the code, creating nothing', async () => {
    await registerPasswordAccount(server(), EXISTING_EMAIL);
    mails.clear();
    const usersBefore = await userCount();
    const jar = new CookieJar();
    const id = interactionIdOf(await authorize(jar));
    await answer(jar, id, IDENTIFIER, { login_hint: EXISTING_EMAIL });
    const sent = await mailed(EXISTING_EMAIL);

    const coded = await answer(jar, id, EMAIL_CODE, { otp: sent.code as string });
    expect(coded.statusCode, coded.body).toBe(303);
    expect((await read(id)).step).toBe(PASSWORD);
    const signedIn = await answer(jar, id, PASSWORD, { password: E2E_PASSWORD });
    expect(signedIn.statusCode, signedIn.body).toBe(303);
    expect(await userCount()).toBe(usersBefore);
    expect(await credentialsOf(EXISTING_EMAIL)).toBe(1);
  });

  it("mails a disabled account's address nothing and changes nothing of the account", async () => {
    const userId = await registerPasswordAccount(server(), DISABLED_EMAIL);
    await query('UPDATE users SET enabled = false WHERE id = $1', [userId]);
    mails.clear();
    const snapshot = async () => ({
      user: await query('SELECT * FROM users WHERE id = $1', [userId]),
      credentials: await query('SELECT * FROM user_credentials WHERE user_id = $1', [userId]),
      attributes: await query('SELECT * FROM user_attributes WHERE user_id = $1', [userId]),
    });
    const before = await snapshot();

    const disabled = new CookieJar();
    const id = interactionIdOf(await authorize(disabled));
    const answered = await answer(disabled, id, IDENTIFIER, { login_hint: DISABLED_EMAIL });
    // The ordinary answer: the code step, as for any address.
    expect(answered.statusCode, answered.body).toBe(303);
    expect((await read(id)).step).toBe(EMAIL_CODE);
    // A guess at the code is refused as any wrong code is.
    const guessed = await answer(disabled, id, EMAIL_CODE, { otp: '12345678' });
    expect(guessed.statusCode, guessed.body).toBe(303);
    expect(await read(id)).toMatchObject({ step: EMAIL_CODE, error: 'invalid_credentials' });

    // A registration of a new address after it: its mail goes out, so the
    // dispatch ran, and none went to the disabled account's address.
    await atCode(new CookieJar());
    expect(mails.get(DISABLED_EMAIL) ?? []).toEqual([]);
    expect(await snapshot()).toEqual(before);
  });
});
