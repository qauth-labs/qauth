import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
import {
  ROUND_LIMITS_KEY_PREFIX,
  SIGN_IN_MIN_RESPONSE_TIME_MS,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
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
import { NOT_VALID_BEFORE_MARGIN_MS } from './helpers/account-validity';

/**
 * THE OWNER'S PASSWORD RESET INSIDE THE ENGINE, AND THE SESSION EPOCH (#642;
 * ADR-017 Decisions 7, 8 and 10, ADR-019 Decision 3;
 * `graphs/flows/core/password-reset`), end to end against real Postgres and
 * Redis, with INTERACTION_UI_ENABLED on.
 *
 * It proves the issue's integration criteria:
 *
 * - The reset's start gets the same answer for an account, an unknown address
 *   and a disabled user, in body and in timing; only the account is mailed.
 * - After a reset every refresh token of the user fails and every older
 *   browser session is refused.
 * - A passkey-bound account cannot finish a reset with email alone; one
 *   whose passkey a password-only sign-in bound, and is new, can (#1064).
 * - The code a reset ends in carries no `amr` and no `auth_time`, and
 *   neither do its ID token and access token (#662).
 * - The reset is not offered under `max_age` or `prompt=login`.
 * - The password's failure counter and its disabled mark clear; a second
 *   factor's counter does not.
 * - The "password changed" notice goes out once per reset.
 * - A disabled user gets no mail and no change.
 *
 * And what the reviews of #642 added: a code a sign-in with the old password
 * minted is never exchanged after the reset, and an unclaimed account (its
 * address never proved) is not reset until #641 ends such an account.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
const CLIENT_ID = 'password-reset-notes-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const OWNER_EMAIL = 'reset-owner@example.test';
const UNKNOWN_EMAIL = 'nobody-here@example.test';
const DISABLED_EMAIL = 'reset-disabled@example.test';
const PASSKEY_EMAIL = 'reset-passkey@example.test';
const UNCLAIMED_EMAIL = 'reset-unclaimed@example.test';
const SETTLED_PASSKEY_EMAIL = 'reset-settled-passkey@example.test';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const PASSWORD_RESET = stepUrn('password_reset');
const EMAIL_CODE = stepUrn('email_code');
const NEW_PASSWORD = stepUrn('new_password');
const CONSENT = stepUrn('consent');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
/** An interaction id: 43 base64url characters. */
const INTERACTION_ID = /^[A-Za-z0-9_-]{43}$/;
/** The new password: long and unusual, so the realm's policy takes it. */
const NEW_PASSWORD_VALUE = 'Copper-Heron-Lattice-Orchard-81';
/** The failure ladder's Redis keys (`ladderCounterKey`). */
const LADDER_KEY_PREFIX = 'sign-in-ladder';

/** A mail the engine sent: its template, its code if it carries one, and its purpose. */
interface SentMail {
  readonly template: string;
  readonly code?: string;
  readonly purpose?: string;
}

/** The step view the ceremony page reads. */
interface StepView {
  readonly step: string;
  readonly csrf: string;
  readonly revision: number;
  readonly alternatives?: readonly string[];
  readonly params?: Record<string, unknown>;
  readonly error?: string;
  /** Why the sign-in went back to its first step (#1081): on one read only. */
  readonly notice?: string;
}

describe('the password reset and the session epoch (#642, real containers)', () => {
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
      // Each test registers its accounts through POST /auth/register.
      REGISTRATION_RATE_LIMIT: '10000',
    });
    const { emailService } = booted.app;
    const original = emailService.sendEngineMail.bind(emailService);
    emailService.sendEngineMail = async (realm, to, mail: EngineMail, context) => {
      const code = 'code' in mail && typeof mail.code === 'string' ? mail.code : undefined;
      const purpose =
        'purpose' in mail && typeof mail.purpose === 'string' ? mail.purpose : undefined;
      mails.set(to, [
        ...(mails.get(to) ?? []),
        {
          template: mail.template,
          ...(code === undefined ? {} : { code }),
          ...(purpose === undefined ? {} : { purpose }),
        },
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
      name: 'Password reset notes app',
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

  /** `/oauth/authorize` for the client, from the browser holding `jar`. */
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
        scope: SCOPES.join(' '),
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'reset-state',
        ...extra,
      }).toString()}`,
      headers: jar.header() === undefined ? {} : { cookie: jar.header() as string },
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** The path of a redirect, without the realm origin. */
  function locationOf(response: LightMyRequestResponse): string {
    expect([302, 303], response.body).toContain(response.statusCode);
    const location = String(response.headers['location']);
    return location.startsWith(`${ORIGIN}/`) ? location.slice(ORIGIN.length) : location;
  }

  /** The interaction id of a redirect to a ceremony page. */
  function interactionIdOf(response: LightMyRequestResponse): string {
    const path = locationOf(response);
    expect(path.startsWith(CEREMONY_PAGE_PREFIX), path).toBe(true);
    const id = path.slice(CEREMONY_PAGE_PREFIX.length);
    expect(id).toMatch(INTERACTION_ID);
    return id;
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
   * Wait until `count` mails went to `to`, and return them. The mail goes out
   * after the answer, off the request path.
   */
  async function mailed(to: string, count: number): Promise<readonly SentMail[]> {
    const deadline = performance.now() + 5_000;
    while ((mails.get(to)?.length ?? 0) < count && performance.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const sent = mails.get(to) ?? [];
    expect(sent).toHaveLength(count);
    return sent;
  }

  /** A sign-in of `email` answered up to its password step: the interaction and its browser. */
  async function atPasswordStep(
    email: string,
    extra: Record<string, string> = {}
  ): Promise<{ jar: CookieJar; id: string; challenge: { verifier: string; challenge: string } }> {
    const jar = new CookieJar();
    const challenge = pkcePair();
    const id = interactionIdOf(await authorize(jar, extra, challenge.challenge));
    expect((await read(id)).step).toBe(IDENTIFIER);
    const identified = await answer(jar, id, IDENTIFIER, { login_hint: email });
    expect(identified.statusCode, identified.body).toBe(303);
    expect((await read(id)).step).toBe(PASSWORD);
    return { jar, id, challenge };
  }

  /**
   * The code a finished interaction's redirect carries, through the consent
   * step when the request goes on there.
   */
  async function codeOf(jar: CookieJar, response: LightMyRequestResponse): Promise<string> {
    let location = String(response.headers['location']);
    if (!location.startsWith(REDIRECT_URI)) {
      const consentId = interactionIdOf(response);
      expect((await read(consentId)).step).toBe(CONSENT);
      const allowed = await answer(jar, consentId, CONSENT, { decision: 'allow' });
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

  async function refresh(refreshToken: string): Promise<LightMyRequestResponse> {
    return server().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
      }).toString(),
    });
  }

  /** The password credential of `email`: its hash, `email_verified` and disabled mark. */
  async function passwordOf(email: string): Promise<{
    credential_data: Record<string, unknown>;
    disabled_at: string | null;
  }> {
    const [row] = await query<{
      credential_data: Record<string, unknown>;
      disabled_at: string | null;
    }>(
      "SELECT credential_data, disabled_at FROM user_credentials WHERE provider_type = 'password' AND external_sub = $1",
      [email]
    );
    if (row === undefined) throw new Error(`no password credential for ${email}`);
    return row;
  }

  async function eventsOf(type: string, userId: string): Promise<number> {
    const [row] = await query<{ count: string }>(
      'SELECT count(*) AS count FROM events WHERE type = $1 AND subject_id = $2',
      [`urn:qauth:event:${type}:v1-rc.0`, userId]
    );
    return Number(row?.count ?? 0);
  }

  /** The failure ladder's counter keys in this test's Redis, by factor. */
  async function ladderKeys(factor: string): Promise<string[]> {
    return server().redis.keys(`${LADDER_KEY_PREFIX}:*:${factor}`);
  }

  it('answers the reset start alike for an account, an unknown address and a disabled user, and mails only the account', async () => {
    await registerPasswordAccount(server(), OWNER_EMAIL);
    const disabledId = await registerPasswordAccount(server(), DISABLED_EMAIL);
    await query('UPDATE users SET enabled = false WHERE id = $1', [disabledId]);
    mails.clear();

    /** The reset's start for `email`: its response, its time and the step it leads to. */
    const start = async (email: string) => {
      const { jar, id } = await atPasswordStep(email);
      expect((await read(id)).alternatives).toContain(PASSWORD_RESET);
      const startedAt = performance.now();
      const response = await answer(jar, id, PASSWORD_RESET);
      const elapsed = performance.now() - startedAt;
      const step = await read(id);
      return {
        elapsed,
        status: response.statusCode,
        location: String(response.headers['location']).replace(id, '<id>'),
        body: response.body.replaceAll(id, '<id>'),
        step: {
          step: step.step,
          alternatives: step.alternatives,
          params: step.params,
          error: step.error,
          revision: step.revision,
        },
      };
    };

    const { elapsed: ownerElapsed, ...owner } = await start(OWNER_EMAIL);
    const { elapsed: unknownElapsed, ...unknown } = await start(UNKNOWN_EMAIL);
    const { elapsed: disabledElapsed, ...disabled } = await start(DISABLED_EMAIL);

    expect(unknown).toEqual(owner);
    expect(disabled).toEqual(owner);
    expect(owner.status).toBe(303);
    expect(owner.step.step).toBe(EMAIL_CODE);
    expect(owner.step.params?.[EMAIL_CODE]).toEqual({
      purpose: 'recovery',
      length: 8,
      expires_in: 600,
      resend_after: 60,
    });
    // The engine's floor holds every answer, so none tells the addresses apart.
    for (const elapsed of [ownerElapsed, unknownElapsed, disabledElapsed]) {
      expect(elapsed).toBeGreaterThanOrEqual(SIGN_IN_MIN_RESPONSE_TIME_MS - 5);
      expect(Math.abs(elapsed - ownerElapsed)).toBeLessThan(250);
    }

    const [toOwner] = await mailed(OWNER_EMAIL, 1);
    expect(toOwner).toMatchObject({ template: 'code', purpose: 'recovery' });
    expect(toOwner?.code).toMatch(/^[0-9]{8}$/);
    expect(mails.get(UNKNOWN_EMAIL) ?? []).toEqual([]);
    expect(mails.get(DISABLED_EMAIL) ?? []).toEqual([]);
  });

  it('starts again at the first step after the fifth wrong code, which says code_burned once, alike for an account and an unknown address (#1081)', async () => {
    await registerPasswordAccount(server(), OWNER_EMAIL);
    mails.clear();

    /**
     * The reset of `email` up to five wrong codes, and the two step reads
     * that follow: what the ceremony page reads after the fifth answer's
     * 303, and on the next read.
     */
    const burn = async (email: string, mailedCode: boolean) => {
      const { jar, id } = await atPasswordStep(email);
      const started = await answer(jar, id, PASSWORD_RESET);
      expect(started.statusCode, started.body).toBe(303);
      expect((await read(id)).step).toBe(EMAIL_CODE);
      // A code that is surely wrong: never the one mailed to the account.
      const sent = mailedCode ? (await mailed(email, 1))[0]?.code : undefined;
      const wrong = sent === '00000000' ? '11111111' : '00000000';
      let fifth: LightMyRequestResponse | undefined;
      for (let attempt = 1; attempt <= 5; attempt += 1) {
        fifth = await answer(jar, id, EMAIL_CODE, { otp: wrong });
        expect(fifth.statusCode, fifth.body).toBe(303);
        if (attempt < 5) {
          expect(await read(id)).toMatchObject({ step: EMAIL_CODE, error: 'invalid_credentials' });
        }
      }
      const shown = (view: StepView) => ({
        step: view.step,
        alternatives: view.alternatives,
        params: view.params,
        error: view.error,
        notice: view.notice,
        revision: view.revision,
      });
      const first = shown(await read(id));
      const next = shown(await read(id));
      return {
        location: String(fifth?.headers['location']).replace(id, '<id>'),
        first,
        next,
      };
    };

    const known = await burn(OWNER_EMAIL, true);

    // The fifth wrong code burned it: the first step again, saying why.
    expect(known.location.endsWith(`${CEREMONY_PAGE_PREFIX}<id>`), known.location).toBe(true);
    expect(known.first.step).toBe(IDENTIFIER);
    expect(known.first.notice).toBe('code_burned');
    expect(known.first.error).toBeUndefined();
    // Once: the next read carries none, and is the same step otherwise.
    expect(known.next.notice).toBeUndefined();
    expect(known.next).toEqual({ ...known.first, notice: undefined });

    // The same for an address no account holds (ADR-017 Decision 4). The
    // five wrong codes above count against this client's IP too, and five
    // more would ask it for a captcha before the first step: the second
    // reset comes as from another IP, so that only the identifier differs.
    const ipKeys = await server().redis.keys(`${ROUND_LIMITS_KEY_PREFIX}:*:ip:*`);
    expect(ipKeys.length).toBeGreaterThan(0);
    await server().redis.del(...ipKeys);
    const unknown = await burn(UNKNOWN_EMAIL, false);
    expect(unknown).toEqual(known);
    expect(mails.get(UNKNOWN_EMAIL) ?? []).toEqual([]);
  });

  it('resets a password-only account and ends everything the old password opened', async () => {
    const userId = await registerPasswordAccount(server(), OWNER_EMAIL);
    await server().repositories.oauthConsents.upsertGrant(realmId, userId, clientRowId, SCOPES);

    // A browser that signed in before the reset, and the refresh token its
    // code started.
    const before = await atPasswordStep(OWNER_EMAIL);
    const signedIn = await answer(before.jar, before.id, PASSWORD, { password: E2E_PASSWORD });
    expect(signedIn.statusCode, signedIn.body).toBe(303);
    expect(before.jar.header() ?? '').toContain('qauth_session');
    const oldTokens = await exchange(await codeOf(before.jar, signedIn), before.challenge.verifier);
    expect(oldTokens.statusCode, oldTokens.body).toBe(200);
    const oldRefreshToken = (oldTokens.json() as { refresh_token?: string }).refresh_token;
    if (oldRefreshToken === undefined) throw new Error('the sign-in started no refresh family');
    // While its session lives, that browser gets a code without a sign-in:
    // one such code is held, not exchanged, until after the reset.
    const held = pkcePair();
    const heldCode = await codeOf(before.jar, await authorize(before.jar, {}, held.challenge));

    // Two wrong passwords count on the password's ladder; a second factor's
    // counter and the password's disabled mark are set as the ladder sets them.
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const wrong = await atPasswordStep(OWNER_EMAIL);
      const refused = await answer(wrong.jar, wrong.id, PASSWORD, { password: 'not-the-password' });
      expect(refused.statusCode, refused.body).toBe(303);
      expect(await read(wrong.id)).toMatchObject({ step: PASSWORD, error: 'invalid_credentials' });
    }
    const [passwordCounter] = await ladderKeys('password');
    if (passwordCounter === undefined) throw new Error('the wrong passwords were not counted');
    const totpCounter = passwordCounter.replace(/:password$/, ':totp');
    await server().redis.set(totpCounter, 'a second factor’s run of failures');
    await query(
      "UPDATE user_credentials SET disabled_at = $2 WHERE user_id = $1 AND provider_type = 'password'",
      [userId, Date.now()]
    );
    const signedInEvents = await eventsOf('user.signed_in', userId);
    const oldHash = (await passwordOf(OWNER_EMAIL)).credential_data['password_hash'];
    mails.clear();

    // The reset: the password step's alternative, the mailed code, a new password.
    const reset = await atPasswordStep(OWNER_EMAIL);
    const started = await answer(reset.jar, reset.id, PASSWORD_RESET);
    expect(started.statusCode, started.body).toBe(303);
    const [codeMail] = await mailed(OWNER_EMAIL, 1);
    const coded = await answer(reset.jar, reset.id, EMAIL_CODE, { otp: codeMail?.code ?? '' });
    expect(coded.statusCode, coded.body).toBe(303);
    const asked = await read(reset.id);
    expect(asked.step).toBe(NEW_PASSWORD);
    expect(asked.params?.[NEW_PASSWORD]).toMatchObject({ purpose: 'reset' });
    const done = await answer(reset.jar, reset.id, NEW_PASSWORD, {
      new_password: NEW_PASSWORD_VALUE,
    });
    expect(done.statusCode, done.body).toBe(303);
    // A reset signs nobody in: no browser session.
    expect(reset.jar.header() ?? '').not.toContain('qauth_session');

    // Its code carries no amr and no auth_time, and binds no session.
    const code = await codeOf(reset.jar, done);
    const [stored] = await query<{ auth_time: unknown; amr: unknown; session_id: unknown }>(
      'SELECT auth_time, amr, session_id FROM authorization_codes WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
      [userId]
    );
    expect(stored).toEqual({ auth_time: null, amr: null, session_id: null });
    const tokens = await exchange(code, reset.challenge.verifier);
    expect(tokens.statusCode, tokens.body).toBe(200);
    const idToken = decodeJwtClaims((tokens.json() as { id_token: string }).id_token);
    expect(idToken['sub']).toBe(userId);
    expect(idToken).not.toHaveProperty('auth_time');
    expect(idToken).not.toHaveProperty('amr');
    expect(idToken).not.toHaveProperty('sid');
    // Nor does the access token (#662): the mailbox is no sign-in.
    const accessToken = decodeJwtClaims((tokens.json() as { access_token: string }).access_token);
    expect(accessToken['sub']).toBe(userId);
    expect(accessToken).not.toHaveProperty('auth_time');
    expect(accessToken).not.toHaveProperty('amr');

    // The new password, the verified address, the cleared mark.
    const password = await passwordOf(OWNER_EMAIL);
    expect(password.credential_data).toMatchObject({ email_verified: true });
    expect(password.credential_data['password_hash']).toEqual(expect.any(String));
    expect(password.credential_data['password_hash']).not.toBe(oldHash);
    expect(password.disabled_at).toBeNull();
    // Every refresh token issued before the reset fails.
    const refused = await refresh(oldRefreshToken);
    expect(refused.statusCode, refused.body).toBe(400);
    expect(refused.json()).toMatchObject({ error: 'invalid_grant' });
    const revoked = await query<{ revoked_reason: string | null }>(
      "SELECT revoked_reason FROM refresh_tokens WHERE user_id = $1 AND revoked_reason = 'password_reset'",
      [userId]
    );
    expect(revoked.length).toBeGreaterThan(0);
    // Nor is a code the old password's sign-in minted ever exchanged.
    const heldExchange = await exchange(heldCode, held.verifier);
    expect(heldExchange.statusCode, heldExchange.body).toBe(400);
    expect(heldExchange.json()).toMatchObject({ error: 'invalid_grant' });
    // The older browser session is refused: the next request signs in again.
    const ended = await query<{ revoked_reason: string | null }>(
      'SELECT revoked_reason FROM sessions WHERE user_id = $1',
      [userId]
    );
    expect(ended).toEqual([{ revoked_reason: 'reset' }]);
    const again = interactionIdOf(await authorize(before.jar));
    expect((await read(again)).step).toBe(IDENTIFIER);
    // The epoch advanced once.
    expect(
      await query('SELECT epoch FROM user_session_epochs WHERE user_id = $1', [userId])
    ).toEqual([{ epoch: 1 }]);
    // The password's run of failures is gone; the second factor's stays.
    expect(await ladderKeys('password')).toEqual([]);
    expect(await server().redis.get(totpCounter)).toBe('a second factor’s run of failures');
    // One event, one notice, and no sign-in recorded.
    expect(await eventsOf('user.password_reset', userId)).toBe(1);
    expect(await eventsOf('user.signed_in', userId)).toBe(signedInEvents);
    const sent = await mailed(OWNER_EMAIL, 2);
    expect(sent.map((mail) => mail.template)).toEqual(['code', 'password_changed']);

    // The new password signs in. A session created within the margin after
    // the reset (the clocks of two nodes may differ by that much) counts as
    // older than it, so the sign-in waits it out.
    await new Promise((resolve) => setTimeout(resolve, NOT_VALID_BEFORE_MARGIN_MS + 100));
    const next = await atPasswordStep(OWNER_EMAIL);
    const withNew = await answer(next.jar, next.id, PASSWORD, { password: NEW_PASSWORD_VALUE });
    expect(withNew.statusCode, withNew.body).toBe(303);
    expect(next.jar.header() ?? '').toContain('qauth_session');
    expect(locationOf(await authorize(next.jar)).startsWith(REDIRECT_URI)).toBe(true);
  });

  it('offers no reset under prompt=login or max_age', async () => {
    await registerPasswordAccount(server(), OWNER_EMAIL);
    mails.clear();

    const fresh: readonly Record<string, string>[] = [{ prompt: 'login' }, { max_age: '0' }];
    for (const extra of fresh) {
      const { jar, id } = await atPasswordStep(OWNER_EMAIL, extra);
      expect((await read(id)).alternatives ?? [], JSON.stringify(extra)).not.toContain(
        PASSWORD_RESET
      );
      const refused = await answer(jar, id, PASSWORD_RESET);
      expect(refused.statusCode, JSON.stringify(extra)).toBe(400);
      expect((await read(id)).step).toBe(PASSWORD);
    }
    // Without either, the same step offers it.
    const { id } = await atPasswordStep(OWNER_EMAIL);
    expect((await read(id)).alternatives).toContain(PASSWORD_RESET);
    expect(mails.get(OWNER_EMAIL) ?? []).toEqual([]);
  });

  it('never finishes the reset of a passkey-bound account with email alone', async () => {
    const userId = await registerPasswordAccount(server(), PASSKEY_EMAIL);
    await server().repositories.userCredentials.create({
      userId,
      realmId,
      providerType: 'webauthn',
      externalSub: 'cmVzZXQtcGFzc2tleQ',
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
    const before = await passwordOf(PASSKEY_EMAIL);
    mails.clear();

    const { jar, id } = await atPasswordStep(PASSKEY_EMAIL);
    await answer(jar, id, PASSWORD_RESET);
    const [codeMail] = await mailed(PASSKEY_EMAIL, 1);
    // A right code: the passkey is next, which these pages cannot ask for, so
    // the reset goes no further. No new password is ever asked for.
    const coded = await answer(jar, id, EMAIL_CODE, { otp: codeMail?.code ?? '' });
    expect(coded.statusCode, coded.body).toBe(410);
    expect((await read(id)).step).toBe(EMAIL_CODE);

    expect(await passwordOf(PASSKEY_EMAIL)).toEqual(before);
    expect(await eventsOf('user.password_reset', userId)).toBe(0);
    expect(await query('SELECT 1 FROM user_session_epochs WHERE user_id = $1', [userId])).toEqual(
      []
    );
    expect((mails.get(PASSKEY_EMAIL) ?? []).map((mail) => mail.template)).toEqual(['code']);
  });

  it('resets past a passkey bound after a password-only sign-in while it is new, and not after (#1064)', async () => {
    /** A passkey as a sign-in that proved only the password binds it: new until `newUntil`. */
    const bind = (userId: string, credentialId: string, newUntil: number) =>
      server().repositories.userCredentials.create({
        userId,
        realmId,
        providerType: 'webauthn',
        externalSub: credentialId,
        newUntil,
        credentialData: {
          public_key: 'pQECAyYgASFYIK_voW-Xypst',
          algorithm: -7,
          sign_count: 0,
          transports: ['internal'],
          backup_eligible: false,
          backed_up: false,
          aaguid: '00000000-0000-0000-0000-000000000000',
          rp_id: 'auth.example.com',
          user_handle: 'dXNlci1oYW5kbGU',
          nickname: null,
          created_at: Date.now(),
          last_used_at: null,
          sign_counter_regressed_at: null,
        },
      });

    // Inside the realm's window (seven days by default): the mailbox and a
    // new password reset the account, and the passkey is never asked for.
    const userId = await registerPasswordAccount(server(), PASSKEY_EMAIL);
    await bind(userId, 'bmV3LXBhc3NrZXk', Date.now() + 7 * 86_400_000);
    mails.clear();
    const reset = await atPasswordStep(PASSKEY_EMAIL);
    await answer(reset.jar, reset.id, PASSWORD_RESET);
    const [codeMail] = await mailed(PASSKEY_EMAIL, 1);
    const coded = await answer(reset.jar, reset.id, EMAIL_CODE, { otp: codeMail?.code ?? '' });
    expect(coded.statusCode, coded.body).toBe(303);
    expect((await read(reset.id)).step).toBe(NEW_PASSWORD);
    const done = await answer(reset.jar, reset.id, NEW_PASSWORD, {
      new_password: NEW_PASSWORD_VALUE,
    });
    expect(done.statusCode, done.body).toBe(303);
    expect(await eventsOf('user.password_reset', userId)).toBe(1);
    // The passkey stays: the owner removes it from the account page.
    expect(
      await query(
        "SELECT 1 FROM user_credentials WHERE user_id = $1 AND provider_type = 'webauthn'",
        [userId]
      )
    ).toHaveLength(1);

    // Once the window passed, the passkey is a full factor: the mailbox alone
    // goes no further, as for any passkey-bound account.
    const laterId = await registerPasswordAccount(server(), SETTLED_PASSKEY_EMAIL);
    await bind(laterId, 'c2V0dGxlZC1wYXNza2V5', Date.now() - 1);
    const before = await passwordOf(SETTLED_PASSKEY_EMAIL);
    const blocked = await atPasswordStep(SETTLED_PASSKEY_EMAIL);
    await answer(blocked.jar, blocked.id, PASSWORD_RESET);
    const [blockedMail] = await mailed(SETTLED_PASSKEY_EMAIL, 1);
    const stopped = await answer(blocked.jar, blocked.id, EMAIL_CODE, {
      otp: blockedMail?.code ?? '',
    });
    expect(stopped.statusCode, stopped.body).toBe(410);
    expect(await passwordOf(SETTLED_PASSKEY_EMAIL)).toEqual(before);
    expect(await eventsOf('user.password_reset', laterId)).toBe(0);
  });

  it('mails a disabled user nothing and changes nothing of the account', async () => {
    const userId = await registerPasswordAccount(server(), DISABLED_EMAIL);
    await query('UPDATE users SET enabled = false WHERE id = $1', [userId]);
    mails.clear();
    const snapshot = async () => ({
      user: await query('SELECT * FROM users WHERE id = $1', [userId]),
      credentials: await query('SELECT * FROM user_credentials WHERE user_id = $1', [userId]),
      attributes: await query('SELECT * FROM user_attributes WHERE user_id = $1', [userId]),
      epochs: await query('SELECT * FROM user_session_epochs WHERE user_id = $1', [userId]),
    });
    const before = await snapshot();

    const { jar, id } = await atPasswordStep(DISABLED_EMAIL);
    const started = await answer(jar, id, PASSWORD_RESET);
    // The ordinary answer: the code step, as for any address.
    expect(started.statusCode, started.body).toBe(303);
    expect((await read(id)).step).toBe(EMAIL_CODE);
    // A guess at the code is refused as any wrong code is.
    const guessed = await answer(jar, id, EMAIL_CODE, { otp: '12345678' });
    expect(guessed.statusCode, guessed.body).toBe(303);
    expect(await read(id)).toMatchObject({ step: EMAIL_CODE, error: 'invalid_credentials' });

    // A reset of another account after it: its mail goes out, so the
    // dispatch ran, and none went to the disabled user's address.
    await registerPasswordAccount(server(), OWNER_EMAIL);
    const other = await atPasswordStep(OWNER_EMAIL);
    await answer(other.jar, other.id, PASSWORD_RESET);
    await mailed(OWNER_EMAIL, 1);
    expect(mails.get(DISABLED_EMAIL) ?? []).toEqual([]);
    expect(await snapshot()).toEqual(before);
  });

  it('mails an unclaimed account nothing and changes nothing of it, until #641 ends such an account', async () => {
    const userId = await registerPasswordAccount(server(), UNCLAIMED_EMAIL);
    // Its address never proved, as `/auth/register` leaves an account until
    // its owner follows the mailed link.
    await query(
      `UPDATE user_credentials SET credential_data = credential_data || '{"email_verified": false}'::jsonb
        WHERE user_id = $1 AND provider_type = 'password'`,
      [userId]
    );
    mails.clear();
    const snapshot = async () => ({
      credentials: await query('SELECT * FROM user_credentials WHERE user_id = $1', [userId]),
      epochs: await query('SELECT * FROM user_session_epochs WHERE user_id = $1', [userId]),
    });
    const before = await snapshot();

    const { jar, id } = await atPasswordStep(UNCLAIMED_EMAIL);
    const started = await answer(jar, id, PASSWORD_RESET);
    // The ordinary answer: the code step, as for any address.
    expect(started.statusCode, started.body).toBe(303);
    expect((await read(id)).step).toBe(EMAIL_CODE);

    // A reset of another account after it: its mail goes out, so the
    // dispatch ran, and none went to the unclaimed account's address.
    await registerPasswordAccount(server(), OWNER_EMAIL);
    const other = await atPasswordStep(OWNER_EMAIL);
    await answer(other.jar, other.id, PASSWORD_RESET);
    await mailed(OWNER_EMAIL, 1);
    expect(mails.get(UNCLAIMED_EMAIL) ?? []).toEqual([]);
    expect(await snapshot()).toEqual(before);
  });
});
