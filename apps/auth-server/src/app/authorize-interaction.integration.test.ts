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
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { SESSION_COOKIE, sessionCookieParts } from '../testing/session-cookie-value';

/**
 * `/oauth/authorize` STARTS AN INTERACTION (#628, ADR-019 Decision 6), end to
 * end against real Postgres and Redis, with INTERACTION_UI_ENABLED on.
 *
 * - The sign-in and the consent are interactions: the endpoint redirects to
 *   the ceremony path with the interaction id and nothing else, even for a
 *   2048-character `state`.
 * - When the interaction finishes, the code is minted with
 *   `mintAuthorizationCode` and the redirect carries `iss` (RFC 9207); the
 *   code redeems at the token endpoint.
 * - A finished interaction issues no second code: a replayed answer, or two
 *   answers at once, mint one code.
 * - `max_age` and a dangerous scope still force a fresh sign-in, now in an
 *   interaction.
 * - `prompt=none` answers as before and starts no interaction.
 * - A request that needs consent after the sign-in continues in a consent
 *   interaction, which the person can cancel (`access_denied`).
 * - An interaction started for a browser that is already signed in, a consent
 *   or a sign-in `max_age` asks for again, carries its session in: "Not you?"
 *   ends it, so the browser is signed out (#964).
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const MINUTE = 60_000;
const EMAIL = 'authorize-interaction@example.test';
const ORIGIN = 'https://auth.example.com';
const CLIENT_ID = 'interaction-notes-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const CONSENT = stepUrn('consent');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
const CREATED = 'urn:qauth:event:interaction.created:v1-rc.0';
const STEP_UP = 'urn:qauth:event:step_up.required:v1-rc.0';
/** An interaction id: 43 base64url characters. */
const INTERACTION_ID = /^[A-Za-z0-9_-]{43}$/;
/**
 * Where the user switch's stand-in route lives: a release candidate no route
 * serves, which the bare problem documents and the log censor cover, as in
 * `interaction.integration.test.ts`.
 */
const SWITCH_PREFIX = '/interaction/v1-rc.999';

/**
 * The user switch ("Not you?"), which no Interaction API operation answers
 * yet (#619): a test route that calls the helper, on the browser surface.
 */
async function switchRoute(app: FastifyInstance): Promise<void> {
  // Imported here, after the boot reset the module registry, so this is the
  // instance the app loaded.
  const { switchInteractionUser } = await import('./helpers/interaction');
  app.post(
    `${SWITCH_PREFIX}/:id/switch`,
    { config: { surface: 'browser' as const } },
    async (request, reply) =>
      switchInteractionUser(request, reply, (request.params as { id: string }).id)
  );
}

/**
 * The interaction id of a ceremony page location, relative or on the realm
 * origin; `undefined` for any other location.
 */
function ceremonyIdOf(location: string): string | undefined {
  const path = location.startsWith(`${ORIGIN}/`) ? location.slice(ORIGIN.length) : location;
  if (!path.startsWith(CEREMONY_PAGE_PREFIX)) return undefined;
  const id = path.slice(CEREMONY_PAGE_PREFIX.length);
  return INTERACTION_ID.test(id) ? id : undefined;
}

describe('/oauth/authorize starts an interaction (#628, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let userId = '';
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
      },
      { routes: switchRoute }
    );
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    const app = booted.app;
    await resetE2eState(app);
    userId = await registerPasswordAccount(app, EMAIL);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
    const client = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Interaction notes app',
      redirectUris: [REDIRECT_URI],
      scopes: ['openid', 'email', 'write:notes'],
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
      // A seeded client: its redirect URI receives authorization errors.
      provisionedByOperator: true,
    });
    clientRowId = client.id;
  }, 120_000);

  afterEach(() => {
    vi.useRealTimers();
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /** The user's stored consent to `scopes` for the client. */
  async function consentTo(scopes: string[]): Promise<void> {
    await server().repositories.oauthConsents.upsertGrant(realmId, userId, clientRowId, scopes);
  }

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
        scope: 'openid email',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'interaction-state',
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
    const id = ceremonyIdOf(location);
    if (id === undefined) throw new Error(`not a ceremony page: ${location}`);
    return id;
  }

  /** The step read, as the ceremony app's server makes it: the id alone, no cookie. */
  async function read(id: string): Promise<{ step: string; csrf: string; params?: unknown }> {
    const response = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}`,
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json() as { step: string; csrf: string; params?: unknown };
  }

  /** A form post to the answer (or cancel) endpoint from the ceremony page. */
  async function post(
    jar: CookieJar,
    id: string,
    fields: Record<string, string>,
    operation: 'answer' | 'cancel' = 'answer'
  ): Promise<LightMyRequestResponse> {
    const response = await server().inject({
      method: 'POST',
      url: `${INTERACTION_API_PREFIX}/${id}/${operation}`,
      headers: { ...FORM, ...SAME_ORIGIN, cookie: jar.header() ?? '' },
      payload: new URLSearchParams(fields).toString(),
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** Answer the identifier step; the next answer is the password's, with its CSRF value. */
  async function toPasswordStep(jar: CookieJar, id: string, loginHint = EMAIL): Promise<string> {
    const identifier = await post(jar, id, {
      type: IDENTIFIER,
      csrf: (await read(id)).csrf,
      login_hint: loginHint,
    });
    expect(identifier.statusCode, identifier.body).toBe(303);
    const step = await read(id);
    expect(step.step).toBe(PASSWORD);
    return step.csrf;
  }

  /** Sign in at the interaction `id`: the response to the password answer. */
  async function signIn(jar: CookieJar, id: string): Promise<LightMyRequestResponse> {
    const csrf = await toPasswordStep(jar, id);
    return post(jar, id, { type: PASSWORD, csrf, password: E2E_PASSWORD });
  }

  async function count(sql: string, params: unknown[] = []): Promise<number> {
    const { rows } = await server().dbPool.query<{ count: string }>(sql, params);
    return Number(rows[0]?.count ?? 0);
  }

  function codes(): Promise<number> {
    return count('SELECT count(*) AS count FROM authorization_codes WHERE oauth_client_id = $1', [
      clientRowId,
    ]);
  }

  function events(type: string): Promise<number> {
    return count('SELECT count(*) AS count FROM events WHERE type = $1', [type]);
  }

  /** "Not you?" at the interaction `id`, from the browser holding `jar`. */
  async function switchUser(jar: CookieJar, id: string): Promise<LightMyRequestResponse> {
    const response = await server().inject({
      method: 'POST',
      url: `${SWITCH_PREFIX}/${id}/switch`,
      headers: { cookie: jar.header() ?? '' },
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** Whether the session `sid` has ended, and why. */
  async function sessionEnd(sid: string) {
    const { rows } = await server().dbPool.query<{
      revoked: boolean;
      revoked_reason: string | null;
    }>('SELECT revoked_at IS NOT NULL AS revoked, revoked_reason FROM sessions WHERE id = $1', [
      sid,
    ]);
    return rows[0];
  }

  /** The `interaction.cancelled` events, oldest first. */
  async function cancelledEvents() {
    const { rows } = await server().dbPool.query<{
      data: Record<string, unknown>;
      subject_id: string | null;
    }>(
      "SELECT data, subject_id FROM events WHERE type = 'urn:qauth:event:interaction.cancelled:v1-rc.0' ORDER BY seq"
    );
    return rows;
  }

  it('redirects with the interaction id only, even for a 2048-character state, then issues the code with iss', async () => {
    await consentTo(['openid', 'email']);
    const jar = new CookieJar();
    const pkce = pkcePair();
    const state = 's'.repeat(2048);

    const started = await authorize(
      jar,
      { state, nonce: 'n'.repeat(512), login_hint: EMAIL },
      pkce.challenge
    );

    expect(started.statusCode).toBe(302);
    const location = String(started.headers['location']);
    expect(location.startsWith(CEREMONY_PAGE_PREFIX), location).toBe(true);
    expect(location.slice(CEREMONY_PAGE_PREFIX.length)).toMatch(INTERACTION_ID);
    expect(location.length).toBeLessThan(80);
    const id = interactionIdOf(started);
    expect((await read(id)).step).toBe(IDENTIFIER);

    // The prefill is personal data: for the browser that started it, never in the step read.
    const personal = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}/personal`,
      headers: { cookie: jar.header() as string },
    });
    expect(personal.statusCode, personal.body).toBe(200);
    expect(personal.json()).toEqual({
      step: IDENTIFIER,
      data: { [IDENTIFIER]: { login_hint: EMAIL } },
    });
    expect(JSON.stringify(await read(id))).not.toContain(EMAIL);

    const finished = await signIn(jar, id);

    expect(finished.statusCode, finished.body).toBe(303);
    const callback = new URL(String(finished.headers['location']));
    expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
    expect(callback.searchParams.get('state')).toBe(state);
    expect(callback.searchParams.get('iss')).toBe(ORIGIN);
    const code = callback.searchParams.get('code');
    expect(code).toMatch(/.+/);
    expect(await codes()).toBe(1);

    // The code is the request's: it redeems with its verifier.
    const token = await server().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    expect(token.statusCode, token.body).toBe(200);
    expect(token.json()).toMatchObject({ token_type: expect.any(String) });
  });

  it('issues no second code from a finished interaction: a replayed answer is refused', async () => {
    await consentTo(['openid', 'email']);
    const jar = new CookieJar();
    const id = interactionIdOf(await authorize(jar));
    const csrf = await toPasswordStep(jar, id);

    const first = await post(jar, id, { type: PASSWORD, csrf, password: E2E_PASSWORD });
    expect(first.statusCode, first.body).toBe(303);
    expect(new URL(String(first.headers['location'])).searchParams.get('code')).toMatch(/.+/);

    const replay = await post(jar, id, { type: PASSWORD, csrf, password: E2E_PASSWORD });
    expect(replay.statusCode).toBe(410);
    const read410 = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}`,
    });
    expect(read410.statusCode).toBe(410);
    expect(await codes()).toBe(1);
  });

  it('mints one code when the same answer is sent twice at once', async () => {
    await consentTo(['openid', 'email']);
    const jar = new CookieJar();
    const id = interactionIdOf(await authorize(jar));
    const csrf = await toPasswordStep(jar, id);

    const answers = await Promise.all([
      post(jar, id, { type: PASSWORD, csrf, password: E2E_PASSWORD }),
      post(jar, id, { type: PASSWORD, csrf, password: E2E_PASSWORD }),
    ]);

    const withCode = answers.filter((answer) => {
      const location = answer.headers['location'];
      return typeof location === 'string' && location.startsWith(REDIRECT_URI)
        ? new URL(location).searchParams.has('code')
        : false;
    });
    expect(withCode).toHaveLength(1);
    expect(await codes()).toBe(1);
  });

  it('forces a fresh sign-in for max_age, in an interaction, and issues the code after it', async () => {
    await consentTo(['openid', 'email']);
    const jar = await signInWithPassword(server(), EMAIL);
    // The session's sign-in is older than max_age allows.
    vi.setSystemTime(Date.now() + 5_000);
    const stepUpsBefore = await events(STEP_UP);

    const started = await authorize(jar, { max_age: '1' });

    const id = interactionIdOf(started);
    expect((await read(id)).step).toBe(IDENTIFIER);
    expect(await events(STEP_UP)).toBe(stepUpsBefore + 1);
    expect(await codes()).toBe(0);

    const finished = await signIn(jar, id);
    expect(finished.statusCode, finished.body).toBe(303);
    const callback = new URL(String(finished.headers['location']));
    expect(callback.searchParams.get('code')).toMatch(/.+/);
    expect(callback.searchParams.get('iss')).toBe(ORIGIN);
    expect(await codes()).toBe(1);
  });

  it('forces a fresh sign-in for a dangerous scope on an older session, even under a stored consent', async () => {
    await consentTo(['openid', 'email', 'write:notes']);
    const jar = await signInWithPassword(server(), EMAIL);
    // Live, but signed in before the fresh-login window.
    vi.setSystemTime(Date.now() + 3 * MINUTE);

    const started = await authorize(jar, { scope: 'openid write:notes' });

    const id = interactionIdOf(started);
    expect((await read(id)).step).toBe(IDENTIFIER);
    expect(await codes()).toBe(0);

    const finished = await signIn(jar, id);
    expect(finished.statusCode, finished.body).toBe(303);
    expect(new URL(String(finished.headers['location'])).searchParams.get('code')).toMatch(/.+/);
  });

  it('answers prompt=none as before, and starts no interaction', async () => {
    const createdBefore = await events(CREATED);
    const expectCallback = (response: LightMyRequestResponse) => {
      expect(response.statusCode).toBe(302);
      const callback = new URL(String(response.headers['location']));
      expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
      expect(callback.searchParams.get('state')).toBe('interaction-state');
      expect(callback.searchParams.get('iss')).toBe(ORIGIN);
      return callback.searchParams;
    };

    // No session.
    const anonymous = new CookieJar();
    expect(expectCallback(await authorize(anonymous, { prompt: 'none' })).get('error')).toBe(
      'login_required'
    );
    expect(anonymous.get('__Host-qauth_flow')).toBeUndefined();

    // A session, no consent.
    const jar = await signInWithPassword(server(), EMAIL);
    expect(expectCallback(await authorize(jar, { prompt: 'none' })).get('error')).toBe(
      'consent_required'
    );

    // A session and a consent: the code, with no page at all.
    await consentTo(['openid', 'email']);
    expect(expectCallback(await authorize(jar, { prompt: 'none' })).get('code')).toMatch(/.+/);

    expect(jar.get('__Host-qauth_flow')).toBeUndefined();
    expect(await events(CREATED)).toBe(createdBefore);
  });

  it('continues in a consent interaction after the sign-in, which the person can cancel', async () => {
    const jar = new CookieJar();
    const id = interactionIdOf(await authorize(jar));

    const signedIn = await signIn(jar, id);

    expect(signedIn.statusCode, signedIn.body).toBe(303);
    const next = interactionIdOf(signedIn);
    expect(next).not.toBe(id);
    expect(
      (await server().inject({ method: 'GET', url: `${INTERACTION_API_PREFIX}/${id}` })).statusCode
    ).toBe(410);
    const consent = await read(next);
    expect(consent.step).toBe(CONSENT);
    // A step read keys each step's params by the step's name.
    expect(consent.params).toMatchObject({
      [CONSENT]: {
        scopes: [
          { scope: 'openid', dangerous: false },
          { scope: 'email', dangerous: false },
        ],
      },
    });

    // An answer carrying a member the step does not declare is refused, and
    // the step is kept (#629): no answer names a scope.
    const answered = await post(jar, next, {
      type: CONSENT,
      csrf: consent.csrf,
      decision: 'allow',
      scope: 'openid email write:notes',
    });
    expect(answered.statusCode).toBe(400);
    expect((await read(next)).step).toBe(CONSENT);
    expect(await codes()).toBe(0);

    const cancelled = await post(jar, next, { csrf: (await read(next)).csrf }, 'cancel');
    expect(cancelled.statusCode).toBe(303);
    const callback = new URL(String(cancelled.headers['location']));
    expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
    expect(callback.searchParams.get('error')).toBe('access_denied');
    expect(callback.searchParams.get('state')).toBe('interaction-state');
    expect(callback.searchParams.get('iss')).toBe(ORIGIN);
    expect(await codes()).toBe(0);
  });

  it('signs the browser out on "Not you?" at the consent it started for, so the request signs in again (#964)', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const cookie = jar.get(SESSION_COOKIE);
    if (cookie === undefined) throw new Error('the sign-in set no session cookie');
    const { sid } = sessionCookieParts(cookie);
    // No stored consent: the consent screen names the signed-in user.
    const id = interactionIdOf(await authorize(jar));
    expect((await read(id)).step).toBe(CONSENT);

    const switched = await switchUser(jar, id);

    expect(switched.statusCode, switched.body).toBe(200);
    expect(switched.json()).toMatchObject({ kind: 'switched' });
    // Ended for good, as a sign-out by that user, and its cookie cleared.
    expect(await sessionEnd(sid)).toEqual({ revoked: true, revoked_reason: 'sign_out' });
    expect(jar.get(SESSION_COOKIE)).toBeUndefined();
    expect(await cancelledEvents()).toEqual([
      {
        data: expect.objectContaining({ reason: 'user_switch', sessionEnded: true }),
        subject_id: userId,
      },
    ]);

    // With a stored consent, a live session would get the code at once. The
    // browser as it is now, and one that kept the old cookie, sign in first.
    await consentTo(['openid', 'email']);
    const kept = new CookieJar();
    kept.absorb(`${SESSION_COOKIE}=${cookie}`);
    for (const browser of [jar, kept]) {
      expect((await read(interactionIdOf(await authorize(browser)))).step).toBe(IDENTIFIER);
    }
    expect(await codes()).toBe(0);
  });

  it('signs the browser out on "Not you?" at a sign-in max_age asks for again, before anyone signed in (#964)', async () => {
    await consentTo(['openid', 'email']);
    const jar = await signInWithPassword(server(), EMAIL);
    const cookie = jar.get(SESSION_COOKIE);
    if (cookie === undefined) throw new Error('the sign-in set no session cookie');
    const { sid } = sessionCookieParts(cookie);
    vi.setSystemTime(Date.now() + 5_000);
    const id = interactionIdOf(await authorize(jar, { max_age: '1' }));
    // The password screen, which shows the identifier with "Not you?".
    await toPasswordStep(jar, id);

    const switched = await switchUser(jar, id);

    expect(switched.statusCode, switched.body).toBe(200);
    expect(await sessionEnd(sid)).toEqual({ revoked: true, revoked_reason: 'sign_out' });
    expect(jar.get(SESSION_COOKIE)).toBeUndefined();
    // About the user whose session ended, though nobody signed in during it.
    expect(await cancelledEvents()).toEqual([
      { data: expect.objectContaining({ sessionEnded: true }), subject_id: userId },
    ]);
    // Without max_age the stored consent would give a code at once: the
    // browser signs in first now.
    expect((await read(interactionIdOf(await authorize(jar)))).step).toBe(IDENTIFIER);
    expect(await codes()).toBe(0);
  });

  it('keeps the browser signed in on "Not you?" beside another identifier at a sign-in max_age asks for again (#964)', async () => {
    await consentTo(['openid', 'email']);
    const jar = await signInWithPassword(server(), EMAIL);
    const cookie = jar.get(SESSION_COOKIE);
    if (cookie === undefined) throw new Error('the sign-in set no session cookie');
    const { sid } = sessionCookieParts(cookie);
    vi.setSystemTime(Date.now() + 5_000);
    const id = interactionIdOf(await authorize(jar, { max_age: '1' }));
    // The password screen shows the identifier the person gave, not the
    // signed-in account: "Not you?" there signs that account out, not this one.
    await toPasswordStep(jar, id, 'someone-else@example.test');

    const switched = await switchUser(jar, id);

    expect(switched.statusCode, switched.body).toBe(200);
    expect(await sessionEnd(sid)).toEqual({ revoked: false, revoked_reason: null });
    const kept = jar.get(SESSION_COOKIE);
    expect(kept === undefined ? undefined : sessionCookieParts(kept).sid).toBe(sid);
    expect(await cancelledEvents()).toEqual([
      { data: expect.not.objectContaining({ sessionEnded: expect.anything() }), subject_id: null },
    ]);
  });
});
