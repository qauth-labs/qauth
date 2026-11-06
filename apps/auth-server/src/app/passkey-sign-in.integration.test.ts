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
import { type SoftPasskey, softPasskey } from '../testing/soft-passkey';

/**
 * PASSKEY SIGN-IN ON THE HOSTED PAGES (#651; ADR-017 Decisions 4 and 10,
 * `graphs/flows/core/passkey`), end to end against real Postgres and Redis,
 * with INTERACTION_UI_ENABLED on and the passkey steps on (the boot's test
 * option: `WEBAUTHN_ENABLED` is refused at boot until #655).
 *
 * The passkey is a software authenticator (`testing/soft-passkey.ts`): an
 * ES256 key whose assertions the server's own WebAuthn verifier checks, as it
 * checks a browser's. It proves the issue's integration criteria:
 *
 * - With no `login_hint`, the sign-in starts passkey-first; a passkey the
 *   user verified signs in with `amr: ["pop","mfa"]`, recorded as a passkey
 *   sign-in.
 * - A correct password on a passkey-bound account does not complete: the
 *   next step is the passkey; password then passkey gives
 *   `amr: ["pwd","pop","mfa"]`.
 * - The first answer, the identifier, is the same for an account with a
 *   passkey and one without, in body and in timing.
 * - `/auth/login` refuses a passkey-bound account as it refuses a wrong
 *   password.
 *
 * The FiPA endpoint (#646) is not in this server yet: the engine's tests
 * prove it answers `redirect_to_web` to a client that lists no
 * `webauthn_get`.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
const RP_ID = 'auth.example.com';
const CLIENT_ID = 'passkey-notes-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const PASSKEY_EMAIL = 'passkey-owner@example.test';
const PASSWORD_EMAIL = 'password-only@example.test';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const WEBAUTHN_GET = stepUrn('webauthn_get');
const RECOVERY_CODES = stepUrn('recovery_codes');
const CONSENT = stepUrn('consent');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
const IP = '203.0.113.10';

/** The step view the ceremony page reads. */
interface StepView {
  readonly step: string;
  readonly csrf: string;
  readonly alternatives?: readonly string[];
  readonly params?: Record<string, Record<string, unknown>>;
  readonly error?: string;
  readonly revision?: number;
}

/** A sign-in in progress: its browser, its interaction and its PKCE verifier. */
interface SignIn {
  readonly jar: CookieJar;
  readonly id: string;
  readonly verifier: string;
}

describe('passkey sign-in on the hosted pages (#651, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';
  let clientRowId = '';

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer(
      {
        ...baseEnvironment(infra, await generateJwtPem()),
        INTERACTION_UI_ENABLED: 'true',
        // Each test registers its accounts through POST /auth/register.
        REGISTRATION_RATE_LIMIT: '10000',
      },
      { passkeySignIn: true }
    );
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    const app = booted.app;
    await resetE2eState(app);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
    const client = await app.repositories.oauthClients.create({
      realmId,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Passkey notes app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
      // A seeded client: its redirect URI receives authorization errors.
      provisionedByOperator: true,
    });
    clientRowId = client.id;
  }, 120_000);

  /** A password account with the client's consent given, and `passkey` bound when given. */
  async function account(
    email: string,
    passkey?: SoftPasskey,
    options: { readonly disabled?: boolean } = {}
  ): Promise<string> {
    const userId = await registerPasswordAccount(server(), email);
    if (passkey !== undefined) {
      const row = await server().repositories.userCredentials.create({
        userId,
        realmId,
        providerType: 'webauthn',
        externalSub: passkey.credentialId,
        credentialData: passkey.credentialData,
      });
      if (options.disabled === true) {
        await server().dbPool.query(
          'UPDATE user_credentials SET disabled_at = now() WHERE id = $1',
          [row.id]
        );
      }
    }
    await server().repositories.oauthConsents.upsertGrant(realmId, userId, clientRowId, SCOPES);
    return userId;
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

  /** Answer with a form post from the ceremony page. */
  async function answer(
    signIn: SignIn,
    type: string,
    fields: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    const { csrf } = await read(signIn.id);
    const response = await server().inject({
      method: 'POST',
      remoteAddress: IP,
      url: `${INTERACTION_API_PREFIX}/${signIn.id}/answer`,
      headers: { ...FORM, ...SAME_ORIGIN, cookie: signIn.jar.header() ?? '' },
      payload: new URLSearchParams({ type, csrf, ...fields }).toString(),
    });
    signIn.jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** A new sign-in at /oauth/authorize, with no `login_hint`. */
  async function authorize(): Promise<SignIn> {
    const jar = new CookieJar();
    const { verifier, challenge } = pkcePair();
    const authorized = await server().inject({
      method: 'GET',
      remoteAddress: IP,
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'passkey-state',
      }).toString()}`,
    });
    jar.absorb(authorized.headers['set-cookie']);
    const path = locationOf(authorized);
    expect(path.startsWith(CEREMONY_PAGE_PREFIX), path).toBe(true);
    return { jar, id: path.slice(CEREMONY_PAGE_PREFIX.length), verifier };
  }

  /** The passkey's answer to the interaction's current `webauthn_get` step. */
  async function assertion(
    signIn: SignIn,
    passkey: SoftPasskey,
    options: Parameters<SoftPasskey['assert']>[1] = {}
  ): Promise<string> {
    const view = await read(signIn.id);
    expect(view.step).toBe(WEBAUTHN_GET);
    const request = view.params?.[WEBAUTHN_GET];
    if (request === undefined) throw new Error('the webauthn_get step carries no options');
    return passkey.assert(
      { challenge: String(request['challenge']), rpId: String(request['rpId']) },
      options
    );
  }

  /** The code a finished interaction's redirect carries, through the recovery set and consent. */
  async function codeOf(signIn: SignIn, response: LightMyRequestResponse): Promise<string> {
    let current = response;
    let location = String(current.headers['location']);
    // The first sign-in that proves the passkey shows the account its recovery set.
    if (!location.startsWith(REDIRECT_URI) && (await read(signIn.id)).step === RECOVERY_CODES) {
      current = await answer(signIn, RECOVERY_CODES, { acknowledged: 'true' });
      expect(current.statusCode, current.body).toBe(303);
      location = String(current.headers['location']);
    }
    if (!location.startsWith(REDIRECT_URI)) {
      const path = locationOf(current);
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

  /** The ID token's claims for a finished sign-in. */
  async function idTokenOf(signIn: SignIn, response: LightMyRequestResponse) {
    const code = await codeOf(signIn, response);
    const exchanged = await server().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: signIn.verifier,
      }).toString(),
    });
    expect(exchanged.statusCode, exchanged.body).toBe(200);
    return decodeJwtClaims(exchanged.json<{ id_token: string }>().id_token);
  }

  async function eventsOf(type: string, userId: string): Promise<Record<string, unknown>[]> {
    const { rows } = await server().dbPool.query<{ data: Record<string, unknown> }>(
      'SELECT data FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
      [`urn:qauth:event:${type}:v1-rc.0`, userId]
    );
    return rows.map((row) => row.data);
  }

  it('starts passkey-first, and a verified passkey signs in with amr ["pop","mfa"]', async () => {
    const passkey = softPasskey(RP_ID);
    const userId = await account(PASSKEY_EMAIL, passkey);
    const signIn = await authorize();

    // The first step names no account: a discoverable passkey, with the
    // password and the identifier beside it.
    const first = await read(signIn.id);
    expect(first.step).toBe(WEBAUTHN_GET);
    expect(first.alternatives).toEqual(expect.arrayContaining([PASSWORD, IDENTIFIER]));
    expect(first.params?.[WEBAUTHN_GET]).toMatchObject({
      rpId: RP_ID,
      userVerification: 'required',
    });
    expect(first.params?.[WEBAUTHN_GET]).not.toHaveProperty('allowCredentials');

    const signedIn = await answer(signIn, WEBAUTHN_GET, {
      webauthn_response: await assertion(signIn, passkey),
    });
    expect(signedIn.statusCode, signedIn.body).toBe(303);

    const claims = await idTokenOf(signIn, signedIn);
    expect(claims['sub']).toBe(userId);
    expect(claims['amr']).toEqual(['pop', 'mfa']);
    expect(await eventsOf('user.signed_in', userId)).toEqual([
      expect.objectContaining({ method: 'passkey' }),
    ]);
  });

  it('refuses an assertion without the user-verification flag, and the step stays', async () => {
    const passkey = softPasskey(RP_ID);
    await account(PASSKEY_EMAIL, passkey);
    const signIn = await authorize();

    const refused = await answer(signIn, WEBAUTHN_GET, {
      webauthn_response: await assertion(signIn, passkey, { userVerified: false }),
    });

    expect(refused.statusCode, refused.body).toBe(303);
    expect(String(refused.headers['location'])).not.toContain(REDIRECT_URI);
    const view = await read(signIn.id);
    expect(view.step).toBe(WEBAUTHN_GET);
    expect(view.error).toBe('invalid_credentials');
  });

  it('does not complete on a correct password of a passkey-bound account; the passkey after it gives ["pwd","pop","mfa"]', async () => {
    const passkey = softPasskey(RP_ID);
    const userId = await account(PASSKEY_EMAIL, passkey);
    const signIn = await authorize();

    expect((await answer(signIn, IDENTIFIER, { login_hint: PASSKEY_EMAIL })).statusCode).toBe(303);
    const afterPassword = await answer(signIn, PASSWORD, { password: E2E_PASSWORD });
    expect(afterPassword.statusCode, afterPassword.body).toBe(303);
    // The downgrade rule: the account's strongest factor is still owed.
    expect(String(afterPassword.headers['location'])).not.toContain(REDIRECT_URI);
    expect((await read(signIn.id)).step).toBe(WEBAUTHN_GET);

    const signedIn = await answer(signIn, WEBAUTHN_GET, {
      webauthn_response: await assertion(signIn, passkey),
    });
    expect(signedIn.statusCode, signedIn.body).toBe(303);

    const claims = await idTokenOf(signIn, signedIn);
    expect(claims['sub']).toBe(userId);
    expect(claims['amr']).toEqual(['pwd', 'pop', 'mfa']);
  });

  it('counts a disabled passkey as bound: the password alone does not complete', async () => {
    const passkey = softPasskey(RP_ID);
    await account(PASSKEY_EMAIL, passkey, { disabled: true });
    const signIn = await authorize();

    await answer(signIn, IDENTIFIER, { login_hint: PASSKEY_EMAIL });
    const afterPassword = await answer(signIn, PASSWORD, { password: E2E_PASSWORD });

    // No step can complete it: the passkey is disabled and the account holds
    // no recovery code. The interaction ends as an expired one does, and no
    // code reaches the client.
    expect(afterPassword.statusCode, afterPassword.body).toBe(410);
    expect(String(afterPassword.headers['location'] ?? '')).not.toContain(REDIRECT_URI);
  });

  it('answers the identifier the same for an account with a passkey and one without, in body and timing', async () => {
    await account(PASSKEY_EMAIL, softPasskey(RP_ID));
    await account(PASSWORD_EMAIL);

    /** The identifier answer for `email`: its response, its time and the step it leads to. */
    const firstAnswer = async (email: string) => {
      const signIn = await authorize();
      const { id } = signIn;
      const startedAt = performance.now();
      const response = await answer(signIn, IDENTIFIER, { login_hint: email });
      const elapsed = performance.now() - startedAt;
      const step = await read(id);
      // Each ceremony has its own challenge; nothing else may differ.
      const params = JSON.parse(
        JSON.stringify(step.params ?? {}).replace(/"challenge":"[^"]*"/g, '"challenge":"<c>"')
      );
      return {
        elapsed,
        status: response.statusCode,
        location: String(response.headers['location']).replace(id, '<id>'),
        body: response.body.replaceAll(id, '<id>'),
        step: {
          step: step.step,
          alternatives: step.alternatives,
          params,
          error: step.error,
          revision: step.revision,
        },
      };
    };

    const withPasskey = await firstAnswer(PASSKEY_EMAIL);
    const without = await firstAnswer(PASSWORD_EMAIL);

    const { elapsed: passkeyElapsed, ...passkeyAnswer } = withPasskey;
    const { elapsed: plainElapsed, ...plainAnswer } = without;
    expect(passkeyAnswer).toEqual(plainAnswer);
    // A password is required of both, and the passkey offered beside it.
    expect(plainAnswer.step.step).toBe(PASSWORD);
    expect(plainAnswer.step.alternatives).toContain(WEBAUTHN_GET);
    expect(passkeyElapsed).toBeGreaterThanOrEqual(SIGN_IN_MIN_RESPONSE_TIME_MS - 5);
    expect(plainElapsed).toBeGreaterThanOrEqual(SIGN_IN_MIN_RESPONSE_TIME_MS - 5);
    expect(Math.abs(passkeyElapsed - plainElapsed)).toBeLessThan(250);
  });

  it('/auth/login refuses a passkey-bound account as it refuses a wrong password', async () => {
    await account(PASSKEY_EMAIL, softPasskey(RP_ID));

    const login = (password: string) =>
      server().inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: PASSKEY_EMAIL, password },
      });
    const correct = await login(E2E_PASSWORD);
    const wrong = await login('Wrong-Horse-Battery-Staple-42!');

    expect(correct.statusCode).toBe(401);
    expect(wrong.statusCode).toBe(401);
    // The problem document, without its `trace_id`, the one member that differs per request.
    const problem = (response: LightMyRequestResponse) => {
      const { trace_id: traceId, ...rest } = response.json() as Record<string, unknown>;
      expect(typeof traceId).toBe('string');
      return rest;
    };
    expect(problem(correct)).toEqual(problem(wrong));
  });
});
