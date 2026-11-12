import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
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
 * THE SWITCH BETWEEN A SIGN-IN AND A REGISTRATION (#1079; ADR-017 Decision 8,
 * ADR-019 Decision 6, ADR-020 §3; `graphs/flows/core/sign-in` and
 * `sign-up`), end to end against real Postgres and Redis, with
 * INTERACTION_UI_ENABLED on.
 *
 * It proves the issue's integration criteria:
 *
 * - A client whose `hosted_flows` name `register`, on a realm that allows
 *   sign-up, is offered the `register` path marker beside the sign-in's
 *   first step; answering it leads to the registration's first step, and the
 *   registration ends in a code for the same authorization request.
 * - With sign-up off, no `register` in `hosted_flows`, a `max_age` or
 *   `prompt=login`, the marker is not offered and an answer naming it is
 *   refused; so is one answered after the gate closed.
 * - From the registration's first step, the `sign_in` marker leads back to
 *   the sign-in, in the same interaction.
 * - The offer is the same for a known and an unknown identifier.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
const CLIENT_ID = 'switch-notes-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const STATE = 'switch-state';
const NEW_EMAIL = 'switching-person@example.test';
const EXISTING_EMAIL = 'switch-existing@example.test';
const UNKNOWN_EMAIL = 'switch-unknown@example.test';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const EMAIL_CODE = stepUrn('email_code');
const NEW_PASSWORD = stepUrn('new_password');
const CONSENT = stepUrn('consent');
const CAPTCHA = stepUrn('captcha');
const REGISTER = stepUrn('register');
const SIGN_IN = stepUrn('sign_in');
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

/** The step read, as the ceremony app's server makes it. */
interface StepRead {
  readonly step: string;
  readonly csrf: string;
  readonly revision: number;
  readonly alternatives?: readonly string[];
  readonly params?: Record<string, unknown>;
  readonly error?: string;
}

describe('the switch between a sign-in and a registration (#1079, real containers)', () => {
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
      // Each test registers its accounts through POST /auth/register, and
      // starts registrations from one IP; the caps are sized for people.
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
   * A group of the realm's policies, as an operator sets it: through the
   * policy store at the counter it has now, the resolver's host cache dropped
   * so the next request reads the row.
   */
  async function realmPolicies(update: Record<string, Record<string, unknown>>): Promise<void> {
    const current = await server().policyStore.get(realmId);
    if (current === undefined) throw new Error(`no policies for realm ${realmId}`);
    await server().policyStore.update(realmId, update, { expectedVersion: current.version });
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
      name: 'Switch notes app',
      redirectUris: [REDIRECT_URI],
      scopes: ['openid', 'email'],
      grantTypes: ['authorization_code'],
      enabled: true,
      requirePkce: true,
      // A seeded client: its redirect URI receives authorization errors.
      provisionedByOperator: true,
    });
    clientRowId = client.id;
    await realmPolicies({
      accounts: { allowSignUp: true },
      botChallenge: { requiredAtSignUp: false },
    });
    await clientFlows(['register']);
  }, 120_000);

  /** `/oauth/authorize` for the client, a sign-in, from the browser holding `jar`. */
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
        state: STATE,
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
  async function read(id: string): Promise<StepRead> {
    const response = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}`,
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json();
  }

  /** What a step read shows the person, without the values each read renews. */
  function shown(step: StepRead) {
    return {
      step: step.step,
      alternatives: step.alternatives ?? [],
      params: step.params,
      error: step.error,
    };
  }

  /** Answer the current step with a form post from the ceremony page. */
  async function answer(
    jar: CookieJar,
    id: string,
    type: string,
    fields: Record<string, string> = {}
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

  /** The refusal of an answer: the generic `invalid_answer` problem, and the step unchanged. */
  async function expectRefused(
    response: LightMyRequestResponse,
    id: string,
    before: StepRead
  ): Promise<void> {
    expect(response.statusCode, response.body).toBe(400);
    expect(response.json()).toMatchObject({ code: 'invalid_answer' });
    expect(shown(await read(id))).toEqual(shown(before));
  }

  it('offers the switch beside the sign-in’s first step, and the registration ends in a code for the same request', async () => {
    const jar = new CookieJar();
    const pkce = pkcePair();
    const id = interactionIdOf(await authorize(jar, {}, pkce.challenge));
    const first = await read(id);
    expect(first.step).toBe(IDENTIFIER);
    expect(first.alternatives).toEqual([REGISTER]);

    // The marker: the registration's first step, in the same interaction,
    // with the way back beside it.
    const switched = await answer(jar, id, REGISTER);
    expect(switched.statusCode, switched.body).toBe(303);
    const registering = await read(id);
    expect(registering.step).toBe(IDENTIFIER);
    expect(registering.alternatives).toEqual([SIGN_IN]);

    // The registration, as prompt=create runs it: the address, its code, the
    // new password.
    const identified = await answer(jar, id, IDENTIFIER, { login_hint: NEW_EMAIL });
    expect(identified.statusCode, identified.body).toBe(303);
    const sent = await mailed(NEW_EMAIL);
    expect(sent.template).toBe('code');
    expect((await read(id)).step).toBe(EMAIL_CODE);
    const coded = await answer(jar, id, EMAIL_CODE, { otp: sent.code as string });
    expect(coded.statusCode, coded.body).toBe(303);
    const asked = await read(id);
    expect(asked.step).toBe(NEW_PASSWORD);
    expect(asked.params?.[NEW_PASSWORD]).toMatchObject({ purpose: 'register' });
    const registered = await answer(jar, id, NEW_PASSWORD, { new_password: NEW_PASSWORD_VALUE });
    expect(registered.statusCode, registered.body).toBe(303);
    const [credential] = await query<{ user_id: string }>(
      "SELECT user_id FROM user_credentials WHERE provider_type = 'password' AND external_sub = $1",
      [NEW_EMAIL]
    );
    const userId = credential?.user_id as string;
    expect(userId).toMatch(/.+/);

    // The request the sign-in started with goes on: its consent, then its
    // code at its redirect URI with its state, redeemed with its verifier.
    const consentId = interactionIdOf(registered);
    expect((await read(consentId)).step).toBe(CONSENT);
    const allowed = await answer(jar, consentId, CONSENT, { decision: 'allow' });
    expect(allowed.statusCode, allowed.body).toBe(303);
    const callback = new URL(String(allowed.headers['location']));
    expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
    expect(callback.searchParams.get('state')).toBe(STATE);
    const code = callback.searchParams.get('code') as string;
    expect(code).toMatch(/.+/);
    const token = await server().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    expect(token.statusCode, token.body).toBe(200);
    const idToken = decodeJwtClaims((token.json() as { id_token: string }).id_token);
    expect(idToken['sub']).toBe(userId);
    // A registration is no sign-in (#662).
    expect(idToken).not.toHaveProperty('auth_time');
    expect(idToken).not.toHaveProperty('amr');

    // The switch was recorded as a passed step.
    const passed = await query<{ data: Record<string, unknown> }>(
      "SELECT data FROM events WHERE type = 'urn:qauth:event:user.sign_in_step_passed:v1-rc.0'"
    );
    expect(passed.map((row) => row.data['step'])).toContain(REGISTER);
  }, 60_000);

  it('asks for the bot challenge first when the realm requires it at sign-up', async () => {
    await realmPolicies({ botChallenge: { requiredAtSignUp: true } });
    const jar = new CookieJar();
    const id = interactionIdOf(await authorize(jar));
    expect((await read(id)).alternatives).toEqual([REGISTER]);

    const switched = await answer(jar, id, REGISTER);
    expect(switched.statusCode, switched.body).toBe(303);
    expect((await read(id)).step).toBe(CAPTCHA);
    expect(mails.get(NEW_EMAIL) ?? []).toEqual([]);
  });

  describe('where it is not offered', () => {
    it.each([
      ['the realm’s sign-up is off', () => realmPolicies({ accounts: { allowSignUp: false } }), {}],
      ['the client’s hosted_flows name no register', () => clientFlows(null), {}],
      ['the client’s hosted_flows are empty', () => clientFlows([]), {}],
      ['the request has a max_age', async () => undefined, { max_age: '0' }],
      ['the request has prompt=login', async () => undefined, { prompt: 'login' }],
    ])(
      'neither offers nor takes it when %s',
      async (_, close: () => Promise<unknown>, extra: Record<string, string>) => {
        await close();
        const jar = new CookieJar();
        const id = interactionIdOf(await authorize(jar, extra));
        const first = await read(id);
        expect(first.step).toBe(IDENTIFIER);
        expect(first.alternatives ?? []).not.toContain(REGISTER);

        await expectRefused(await answer(jar, id, REGISTER), id, first);
      }
    );

    it('refuses the marker with the generic error once the realm stopped allowing sign-up', async () => {
      const jar = new CookieJar();
      const id = interactionIdOf(await authorize(jar));
      const first = await read(id);
      expect(first.alternatives).toEqual([REGISTER]);

      await realmPolicies({ accounts: { allowSignUp: false } });
      await expectRefused(await answer(jar, id, REGISTER), id, first);
    });

    it('offers it at the first step only: never beside the password', async () => {
      const jar = new CookieJar();
      const id = interactionIdOf(await authorize(jar));
      await answer(jar, id, IDENTIFIER, { login_hint: UNKNOWN_EMAIL });
      const password = await read(id);
      expect(password.step).toBe(PASSWORD);
      expect(password.alternatives ?? []).not.toContain(REGISTER);

      await expectRefused(await answer(jar, id, REGISTER), id, password);
    });
  });

  it('leads from the registration’s first step back to the sign-in, in the same interaction', async () => {
    await registerPasswordAccount(server(), EXISTING_EMAIL);
    mails.clear();
    const jar = new CookieJar();
    const id = interactionIdOf(await authorize(jar));
    await answer(jar, id, REGISTER);
    expect(shown(await read(id))).toMatchObject({ step: IDENTIFIER, alternatives: [SIGN_IN] });

    const back = await answer(jar, id, SIGN_IN);
    expect(back.statusCode, back.body).toBe(303);
    const signingIn = await read(id);
    expect(signingIn.step).toBe(IDENTIFIER);
    // The sign-in's first step again, the switch beside it.
    expect(signingIn.alternatives).toEqual([REGISTER]);

    // A sign-in, not a registration: the password, no code mailed, and the
    // person signed in.
    const signIns = async () =>
      (await query("SELECT 1 FROM events WHERE type = 'urn:qauth:event:user.signed_in:v1-rc.0'"))
        .length;
    const before = await signIns();
    await answer(jar, id, IDENTIFIER, { login_hint: EXISTING_EMAIL });
    expect((await read(id)).step).toBe(PASSWORD);
    const signedIn = await answer(jar, id, PASSWORD, { password: E2E_PASSWORD });
    expect(signedIn.statusCode, signedIn.body).toBe(303);
    expect(mails.get(EXISTING_EMAIL) ?? []).toEqual([]);
    expect(await signIns()).toBe(before + 1);
  }, 60_000);

  it('offers the same for a known and an unknown identifier', async () => {
    await registerPasswordAccount(server(), EXISTING_EMAIL);

    /** What the sign-in shows for `email`: its first step, then the step after the identifier. */
    const offers = async (email: string) => {
      const jar = new CookieJar();
      const id = interactionIdOf(await authorize(jar, { login_hint: email }));
      const first = shown(await read(id));
      const identified = await answer(jar, id, IDENTIFIER, { login_hint: email });
      expect(identified.statusCode, identified.body).toBe(303);
      return { first, next: shown(await read(id)) };
    };

    const known = await offers(EXISTING_EMAIL);
    const unknown = await offers(UNKNOWN_EMAIL);
    expect(known).toEqual(unknown);
    expect(known.first).toMatchObject({ step: IDENTIFIER, alternatives: [REGISTER] });
    expect(known.next.step).toBe(PASSWORD);
  });
});
