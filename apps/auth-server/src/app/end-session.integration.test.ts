import { INTERACTION_API_PREFIX, stepUrn } from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  decodeHtmlEntities,
  decodeJwtClaims,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { sessionIdOfCookie } from '../testing/session-cookie-value';

/**
 * RP-INITIATED LOGOUT (#675; OpenID Connect RP-Initiated Logout 1.0), end to
 * end against real Postgres and Redis. The flow graph is
 * `graphs/flows/core/logout`.
 *
 * A browser signs in at `/ui/login`, runs `/oauth/authorize` with its session
 * cookie, and the client redeems the code at `/oauth/token` for an ID token.
 * The app then sends the browser to `/oauth/end-session`:
 *
 * - with the ID token as `id_token_hint` and a registered
 *   `post_logout_redirect_uri`, the session ends at once: 303 to the URI with
 *   `state`, the session cookie cleared, the `sessions` row revoked
 *   (`sign_out`), its `session_clients` rows deleted, and the browser's next
 *   authorization request goes to the sign-in page instead of the client;
 * - with an unregistered URI, a 400 page answers, nothing ends and the
 *   browser is never redirected;
 * - without a hint, the signed-in browser gets the `logout_confirm` step as a
 *   plain form (INTERACTION_UI_ENABLED is off), and nothing ends until it is
 *   answered: `logout` ends the session, `stay` ends nothing;
 * - a POST without the session cookie (a cross-site form post leaves the
 *   SameSite=Lax cookie out) is sent again as a GET with the same parameters,
 *   and nothing is checked or ended on that leg; a POST with the cookie is
 *   answered as a GET.
 *
 * No refresh token is revoked by the route on any path.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

/** `SESSION_COOKIE_NAME`, written here: its module reads the environment at import. */
const SESSION_COOKIE = '__Host-qauth_session';
const ORIGIN = 'https://auth.example.com';
const CLIENT_ID = 'end-session-web-app';
const CLIENT_SECRET = 'end-session-web-app-secret-0123456789';
const REDIRECT_URI = 'https://client.example.com/callback';
const RETURN_URI = 'https://client.example.com/signed-out';
const SCOPES = ['openid', 'email'];
const EMAIL = 'end-session@example.test';
const LOGOUT_CONFIRM = stepUrn('logout_confirm');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the confirm page's form sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
const SIGNED_OUT = 'urn:qauth:event:user.signed_out:v1-rc.0';
const SIGN_OUT_FAILED = 'urn:qauth:event:user.sign_out_failed:v1-rc.0';

interface TokenResponse {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
}

/** The confirm step as the plain form draws it. */
interface ConfirmForm {
  readonly action: string;
  readonly fields: Record<string, string>;
}

describe('RP-initiated logout at /oauth/end-session (#675, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';
  let userId = '';
  let clientRowId = '';

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      // Each test runs several authorization and end-session requests from one
      // address; both share the authorization endpoint's budget.
      AUTHORIZE_RATE_LIMIT: '10000',
    });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
    delete process.env['AUTHORIZE_RATE_LIMIT'];
  });

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
    userId = await registerPasswordAccount(app, EMAIL);
    clientRowId = await seedClient(app);
  }, 120_000);

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /**
   * The confidential client, registering RETURN_URI as its one
   * post_logout_redirect_uri, with the user's stored consent so no consent
   * screen shows.
   */
  async function seedClient(app: FastifyInstance): Promise<string> {
    const client = await app.repositories.oauthClients.create({
      realmId,
      clientId: CLIENT_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(CLIENT_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'End-session web app',
      redirectUris: [REDIRECT_URI],
      postLogoutRedirectUris: [RETURN_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
    await app.repositories.oauthConsents.upsertGrant(realmId, userId, client.id, SCOPES);
    return client.id;
  }

  /** The session id the browser's signed session cookie carries. */
  function cookieSessionId(jar: CookieJar): string {
    const value = jar.get(SESSION_COOKIE);
    if (value === undefined) throw new Error('the browser holds no session cookie');
    return sessionIdOfCookie(value);
  }

  function cookieOf(jar: CookieJar): Record<string, string> {
    const header = jar.header();
    return header === undefined ? {} : { cookie: header };
  }

  /** `/oauth/authorize` from the browser holding `jar`. */
  async function authorize(
    jar: CookieJar
  ): Promise<{ response: LightMyRequestResponse; verifier: string }> {
    const pkce = pkcePair();
    const response = await server().inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'authorize-state',
        nonce: 'authorize-nonce',
      }).toString()}`,
      headers: cookieOf(jar),
    });
    jar.absorb(response.headers['set-cookie']);
    return { response, verifier: pkce.verifier };
  }

  /** The code of an authorization response that went back to the client. */
  function codeOf(response: LightMyRequestResponse): string | null {
    if (response.statusCode !== 302) return null;
    const location = String(response.headers['location']);
    if (!location.startsWith(`${REDIRECT_URI}?`)) return null;
    return new URL(location).searchParams.get('code');
  }

  /** Authorize from the signed-in browser and redeem the code: the token response. */
  async function codeFlow(jar: CookieJar): Promise<TokenResponse> {
    const { response, verifier } = await authorize(jar);
    const code = codeOf(response);
    if (code === null) throw new Error(`authorize returned no code: ${response.headers.location}`);
    const exchanged = await server().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: verifier,
      }).toString(),
    });
    expect(exchanged.statusCode, exchanged.body).toBe(200);
    return exchanged.json<TokenResponse>();
  }

  /** A browser signed in, holding an ID token from a real code exchange. */
  async function signedInWithIdToken(): Promise<{
    jar: CookieJar;
    sid: string;
    tokens: TokenResponse;
    idToken: string;
  }> {
    const jar = await signInWithPassword(server(), EMAIL);
    const sid = cookieSessionId(jar);
    const tokens = await codeFlow(jar);
    if (tokens.id_token === undefined) throw new Error('the exchange issued no ID token');
    expect(decodeJwtClaims(tokens.id_token)).toMatchObject({ sub: userId, sid });
    return { jar, sid, tokens, idToken: tokens.id_token };
  }

  /** `GET /oauth/end-session` from the browser holding `jar`. */
  async function endSession(
    jar: CookieJar,
    params: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    const response = await server().inject({
      method: 'GET',
      url: `/oauth/end-session?${new URLSearchParams(params).toString()}`,
      headers: cookieOf(jar),
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** Every `Set-Cookie` line of a response. */
  function setCookies(response: LightMyRequestResponse): string[] {
    const header = response.headers['set-cookie'];
    return header === undefined ? [] : Array.isArray(header) ? header : [header];
  }

  /** The response cleared the session cookie: `__Host-qauth_session=` with Max-Age=0. */
  function expectSessionCookieCleared(response: LightMyRequestResponse): void {
    const line = setCookies(response).find((one) => one.startsWith(`${SESSION_COOKIE}=`));
    expect(line, 'no Set-Cookie for the session cookie').toBeDefined();
    expect(line).toMatch(new RegExp(`^${SESSION_COOKIE}=;`));
    expect(line).toMatch(/;\s*Max-Age=0(;|$)/);
    expect(line).toMatch(/;\s*Path=\//);
  }

  function expectSessionCookieUntouched(response: LightMyRequestResponse): void {
    expect(setCookies(response).some((one) => one.startsWith(`${SESSION_COOKIE}=`))).toBe(false);
  }

  /** The `sessions` row of `sid`, as stored. */
  async function sessionRow(
    sid: string
  ): Promise<{ revoked_at: string | null; revoked_reason: string | null }> {
    const { rows } = await server().dbPool.query<{
      revoked_at: string | null;
      revoked_reason: string | null;
    }>(`SELECT revoked_at, revoked_reason FROM sessions WHERE id = $1`, [sid]);
    if (rows.length !== 1) throw new Error(`no sessions row for ${sid}`);
    return rows[0];
  }

  async function registryOf(sid: string): Promise<{ oauth_client_id: string }[]> {
    const { rows } = await server().dbPool.query<{ oauth_client_id: string }>(
      `SELECT oauth_client_id FROM session_clients WHERE session_id = $1`,
      [sid]
    );
    return rows;
  }

  /** The refresh tokens marked revoked, of any user. */
  async function revokedRefreshTokens(): Promise<number> {
    const { rows } = await server().dbPool.query<{ count: string }>(
      `SELECT count(*) AS count FROM refresh_tokens WHERE revoked OR revoked_at IS NOT NULL`
    );
    return Number(rows[0]?.count ?? 0);
  }

  async function eventsOf(
    type: string
  ): Promise<{ data: Record<string, unknown>; subject_id: string | null }[]> {
    const { rows } = await server().dbPool.query<{
      data: Record<string, unknown>;
      subject_id: string | null;
    }>('SELECT data, subject_id FROM events WHERE type = $1 ORDER BY seq', [type]);
    return rows;
  }

  /**
   * Whether the session still resolves for a browser that sends `cookie`,
   * read from the status page, which takes no parameter. A fresh jar, so the
   * clear the read may send does not touch the caller's.
   */
  async function statusFor(cookie: string | undefined): Promise<'signed_in' | 'signed_out'> {
    const response = await server().inject({
      method: 'GET',
      url: '/oauth/end-session/status',
      headers: cookie === undefined ? {} : { cookie },
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['content-type']).toMatch(/^text\/html/);
    if (response.body.includes('You are still signed in')) return 'signed_in';
    expect(response.body).toContain('You are signed out');
    return 'signed_out';
  }

  /** The session of `sid` is live: its row unrevoked, and the cookie still resolves. */
  async function expectSessionLive(jar: CookieJar, sid: string): Promise<void> {
    expect(await sessionRow(sid)).toEqual({ revoked_at: null, revoked_reason: null });
    expect(cookieSessionId(jar)).toBe(sid);
    expect(await statusFor(jar.header())).toBe('signed_in');
  }

  /**
   * The session of `sid` has ended: the old cookie no longer resolves, its
   * row is revoked (the session service marks it; it does not delete it),
   * and its registry rows are gone.
   */
  async function expectSessionEnded(oldCookie: string, sid: string): Promise<void> {
    expect(await statusFor(oldCookie)).toBe('signed_out');
    const row = await sessionRow(sid);
    expect(row.revoked_at).not.toBeNull();
    expect(row.revoked_reason).toBe('sign_out');
    expect(await registryOf(sid)).toEqual([]);
  }

  /** The confirm step of a page the route drew: its form's action and fields. */
  function confirmFormOf(response: LightMyRequestResponse): ConfirmForm {
    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['content-type']).toMatch(/^text\/html/);
    expect(response.body).toContain('Sign out?');
    const action = /<form method="post" action="([^"]+)"/.exec(response.body)?.[1];
    if (action === undefined) throw new Error('the confirm page has no form');
    const fields = Object.fromEntries(
      [...response.body.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)].map(
        ([, name, value]) => [name, decodeHtmlEntities(value)]
      )
    );
    return { action: decodeHtmlEntities(action), fields };
  }

  /** Press a button of the confirm form, from the browser holding `jar`. */
  async function answerConfirm(
    jar: CookieJar,
    form: ConfirmForm,
    decision: 'logout' | 'logout_all' | 'stay'
  ): Promise<LightMyRequestResponse> {
    const response = await server().inject({
      method: 'POST',
      url: form.action,
      headers: { ...FORM, ...SAME_ORIGIN, ...cookieOf(jar) },
      payload: new URLSearchParams({ ...form.fields, decision }).toString(),
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  describe('with a valid id_token_hint (§2, §3)', () => {
    it('ends the browser session and goes back to the registered URI with state', async () => {
      const { jar, sid, idToken } = await signedInWithIdToken();
      const oldCookie = jar.header() as string;
      expect(await registryOf(sid)).toEqual([{ oauth_client_id: clientRowId }]);

      const response = await endSession(jar, {
        id_token_hint: idToken,
        post_logout_redirect_uri: RETURN_URI,
        state: 'logout-state',
      });

      expect(response.statusCode, response.body).toBe(303);
      expect(response.headers['location']).toBe(`${RETURN_URI}?state=logout-state`);
      expect(response.headers['cache-control']).toBe('no-store');
      expectSessionCookieCleared(response);
      expect(jar.get(SESSION_COOKIE)).toBeUndefined();
      await expectSessionEnded(oldCookie, sid);
      expect(await eventsOf(SIGNED_OUT)).toEqual([
        expect.objectContaining({ data: expect.objectContaining({ sid }), subject_id: userId }),
      ]);
    });

    it('accepts the POST form of the same request (§2)', async () => {
      const { jar, sid, idToken } = await signedInWithIdToken();
      const oldCookie = jar.header() as string;

      const response = await server().inject({
        method: 'POST',
        url: '/oauth/end-session',
        headers: { ...FORM, ...cookieOf(jar) },
        payload: new URLSearchParams({
          id_token_hint: idToken,
          client_id: CLIENT_ID,
          post_logout_redirect_uri: RETURN_URI,
          state: 'post-state',
        }).toString(),
      });

      expect(response.statusCode, response.body).toBe(303);
      expect(response.headers['location']).toBe(`${RETURN_URI}?state=post-state`);
      expectSessionCookieCleared(response);
      await expectSessionEnded(oldCookie, sid);
    });

    it('sends a POST without the session cookie again as a GET, ending nothing on that leg', async () => {
      const { jar, sid, idToken } = await signedInWithIdToken();
      const params = {
        id_token_hint: idToken,
        client_id: CLIENT_ID,
        post_logout_redirect_uri: RETURN_URI,
        state: 'resend-state',
      };

      // A cross-site form post: the SameSite=Lax session cookie stays behind.
      const posted = await server().inject({
        method: 'POST',
        url: '/oauth/end-session',
        headers: FORM,
        payload: new URLSearchParams(params).toString(),
      });

      expect(posted.statusCode, posted.body).toBe(303);
      expect(posted.headers['cache-control']).toBe('no-store');
      const location = new URL(String(posted.headers['location']));
      expect(`${location.origin}${location.pathname}`).toBe(`${ORIGIN}/oauth/end-session`);
      expect(Object.fromEntries(location.searchParams)).toEqual(params);
      expectSessionCookieUntouched(posted);
      await expectSessionLive(jar, sid);
      expect(await eventsOf(SIGNED_OUT)).toEqual([]);
      expect(await eventsOf(SIGN_OUT_FAILED)).toEqual([]);

      // The browser follows the 303 with its cookie: now the session ends.
      const oldCookie = jar.header() as string;
      const followed = await server().inject({
        method: 'GET',
        url: `${location.pathname}${location.search}`,
        headers: cookieOf(jar),
      });
      jar.absorb(followed.headers['set-cookie']);
      expect(followed.statusCode, followed.body).toBe(303);
      expect(followed.headers['location']).toBe(`${RETURN_URI}?state=resend-state`);
      expectSessionCookieCleared(followed);
      await expectSessionEnded(oldCookie, sid);
    });

    it('ends the session with no return URI and shows the signed-out page', async () => {
      const { jar, sid, idToken } = await signedInWithIdToken();
      const oldCookie = jar.header() as string;

      const response = await endSession(jar, { id_token_hint: idToken });

      expect(response.statusCode, response.body).toBe(200);
      expect(response.headers['location']).toBeUndefined();
      expect(response.body).toContain('You are signed out');
      expectSessionCookieCleared(response);
      await expectSessionEnded(oldCookie, sid);
    });

    it('revokes no refresh token, and the refresh token still works', async () => {
      const { jar, tokens, idToken } = await signedInWithIdToken();
      expect(tokens.refresh_token).toBeDefined();

      const response = await endSession(jar, {
        id_token_hint: idToken,
        post_logout_redirect_uri: RETURN_URI,
      });
      expect(response.statusCode, response.body).toBe(303);

      expect(await revokedRefreshTokens()).toBe(0);
      const refreshed = await server().inject({
        method: 'POST',
        url: '/oauth/token',
        headers: FORM,
        payload: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token as string,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
        }).toString(),
      });
      expect(refreshed.statusCode, refreshed.body).toBe(200);
    });

    it('signs the browser out end to end: the next authorization asks for the password again', async () => {
      const { jar, idToken } = await signedInWithIdToken();
      // Before the logout, the browser's session answers an authorization
      // request with a code, and no sign-in page.
      const before = await authorize(jar);
      expect(codeOf(before.response)).toMatch(/.+/);
      const oldCookie = jar.header() as string;

      const response = await endSession(jar, {
        id_token_hint: idToken,
        post_logout_redirect_uri: RETURN_URI,
        state: 'e2e-state',
      });
      expect(response.statusCode, response.body).toBe(303);

      // The same browser, which dropped the cleared cookie, goes to sign-in.
      const after = await authorize(jar);
      expect(after.response.statusCode).toBe(302);
      expect(codeOf(after.response)).toBeNull();
      expect(after.response.headers['location']).toMatch(/^\/ui\/login\?return_to=/);
      // So does a browser that kept sending the old cookie: the session behind
      // it has ended, not only its cookie.
      const replay = await server().inject({
        method: 'GET',
        url: `/oauth/authorize?${new URLSearchParams({
          response_type: 'code',
          client_id: CLIENT_ID,
          redirect_uri: REDIRECT_URI,
          scope: SCOPES.join(' '),
          code_challenge: pkcePair().challenge,
          code_challenge_method: 'S256',
          state: 'replay-state',
        }).toString()}`,
        headers: { cookie: oldCookie },
      });
      expect(replay.statusCode).toBe(302);
      expect(replay.headers['location']).toMatch(/^\/ui\/login\?return_to=/);
    });
  });

  describe('a return URI the client did not register (§3.1)', () => {
    it('answers a 400 page, never redirects, and ends nothing', async () => {
      const { jar, sid, idToken } = await signedInWithIdToken();

      const response = await endSession(jar, {
        id_token_hint: idToken,
        post_logout_redirect_uri: 'https://client.example.com/elsewhere',
        state: 'unregistered-state',
      });

      expect(response.statusCode).toBe(400);
      expect(response.headers['location']).toBeUndefined();
      expect(response.headers['content-type']).toMatch(/^text\/html/);
      expect(response.body).toContain('This sign-out request is not valid');
      expect(response.body).not.toContain('unregistered-state');
      expectSessionCookieUntouched(response);
      await expectSessionLive(jar, sid);
      expect(await registryOf(sid)).toEqual([{ oauth_client_id: clientRowId }]);
      expect(await eventsOf(SIGNED_OUT)).toEqual([]);
      expect(await eventsOf(SIGN_OUT_FAILED)).toEqual([
        expect.objectContaining({
          data: expect.objectContaining({ reason: 'post_logout_redirect_uri_not_registered' }),
        }),
      ]);
      // The browser still gets a code.
      expect(codeOf((await authorize(jar)).response)).toMatch(/.+/);
    });

    it('refuses a client_id that is not the hint’s audience, and ends nothing (§2)', async () => {
      const { jar, sid, idToken } = await signedInWithIdToken();

      const response = await endSession(jar, {
        id_token_hint: idToken,
        client_id: 'another-client',
        post_logout_redirect_uri: RETURN_URI,
      });

      expect(response.statusCode).toBe(400);
      expect(response.headers['location']).toBeUndefined();
      await expectSessionLive(jar, sid);
    });
  });

  describe('without an id_token_hint: the confirm step', () => {
    it('shows the confirm step on a GET and ends nothing', async () => {
      const jar = await signInWithPassword(server(), EMAIL);
      const sid = cookieSessionId(jar);

      const response = await endSession(jar, {
        client_id: CLIENT_ID,
        post_logout_redirect_uri: RETURN_URI,
        state: 'confirm-state',
      });

      const form = confirmFormOf(response);
      expect(response.headers['location']).toBeUndefined();
      expect(response.headers['cache-control']).toBe('no-store');
      expect(form.action).toMatch(
        new RegExp(`^${INTERACTION_API_PREFIX}/[A-Za-z0-9_-]{43}/answer$`)
      );
      expect(form.fields).toMatchObject({ type: LOGOUT_CONFIRM });
      expect(form.fields['csrf']).toMatch(/.+/);
      expect(response.body).toContain(EMAIL);
      expectSessionCookieUntouched(response);
      await expectSessionLive(jar, sid);
      expect(await eventsOf(SIGNED_OUT)).toEqual([]);
    });

    it('ends nothing for a hint that does not verify: it counts as no hint', async () => {
      const jar = await signInWithPassword(server(), EMAIL);
      const sid = cookieSessionId(jar);

      const response = await endSession(jar, { id_token_hint: 'not.a.token' });

      confirmFormOf(response);
      expectSessionCookieUntouched(response);
      await expectSessionLive(jar, sid);
    });

    it('ends the session when the person answers logout, and goes back with state', async () => {
      const { jar, sid, tokens } = await signedInWithIdToken();
      const oldCookie = jar.header() as string;
      const form = confirmFormOf(
        await endSession(jar, {
          client_id: CLIENT_ID,
          post_logout_redirect_uri: RETURN_URI,
          state: 'confirm-state',
        })
      );

      const answered = await answerConfirm(jar, form, 'logout');

      expect(answered.statusCode, answered.body).toBe(303);
      expect(answered.headers['location']).toBe(`${RETURN_URI}?state=confirm-state`);
      expectSessionCookieCleared(answered);
      await expectSessionEnded(oldCookie, sid);
      expect(await eventsOf(SIGNED_OUT)).toEqual([
        expect.objectContaining({ data: expect.objectContaining({ sid }), subject_id: userId }),
      ]);
      expect(tokens.refresh_token).toBeDefined();
      expect(await revokedRefreshTokens()).toBe(0);
      // The browser signs in again for its next authorization.
      expect((await authorize(jar)).response.headers['location']).toMatch(
        /^\/ui\/login\?return_to=/
      );
    });

    it('ends the session on logout_all too, and goes to the status page with no return URI', async () => {
      const jar = await signInWithPassword(server(), EMAIL);
      const sid = cookieSessionId(jar);
      const oldCookie = jar.header() as string;
      const form = confirmFormOf(await endSession(jar, {}));

      const answered = await answerConfirm(jar, form, 'logout_all');

      expect(answered.statusCode, answered.body).toBe(303);
      expect(answered.headers['location']).toBe(`${ORIGIN}/oauth/end-session/status`);
      expectSessionCookieCleared(answered);
      await expectSessionEnded(oldCookie, sid);
    });

    it('ends nothing when the person stays signed in, and still goes back with state', async () => {
      const { jar, sid } = await signedInWithIdToken();
      const form = confirmFormOf(
        await endSession(jar, {
          client_id: CLIENT_ID,
          post_logout_redirect_uri: RETURN_URI,
          state: 'stay-state',
        })
      );

      const answered = await answerConfirm(jar, form, 'stay');

      expect(answered.statusCode, answered.body).toBe(303);
      expect(answered.headers['location']).toBe(`${RETURN_URI}?state=stay-state`);
      expectSessionCookieUntouched(answered);
      await expectSessionLive(jar, sid);
      expect(await registryOf(sid)).toEqual([{ oauth_client_id: clientRowId }]);
      expect(await eventsOf(SIGNED_OUT)).toEqual([]);
      expect(await eventsOf(SIGN_OUT_FAILED)).toEqual([
        expect.objectContaining({ data: expect.objectContaining({ reason: 'declined' }) }),
      ]);
      expect(await revokedRefreshTokens()).toBe(0);
      expect(codeOf((await authorize(jar)).response)).toMatch(/.+/);
    });

    it('ends nothing when the person cancels the step', async () => {
      const jar = await signInWithPassword(server(), EMAIL);
      const sid = cookieSessionId(jar);
      const form = confirmFormOf(
        await endSession(jar, {
          client_id: CLIENT_ID,
          post_logout_redirect_uri: RETURN_URI,
          state: 'cancel-state',
        })
      );

      const cancelled = await server().inject({
        method: 'POST',
        url: form.action.replace(/\/answer$/, '/cancel'),
        headers: { ...FORM, ...SAME_ORIGIN, ...cookieOf(jar) },
        payload: new URLSearchParams({ csrf: form.fields['csrf'] }).toString(),
      });
      jar.absorb(cancelled.headers['set-cookie']);

      expect(cancelled.statusCode, cancelled.body).toBe(303);
      expect(cancelled.headers['location']).toBe(`${RETURN_URI}?state=cancel-state`);
      expectSessionCookieUntouched(cancelled);
      await expectSessionLive(jar, sid);
    });
  });

  describe('a browser that is not signed in', () => {
    it('goes back to the registered URI with state, with nothing to end', async () => {
      const jar = new CookieJar();

      const response = await endSession(jar, {
        client_id: CLIENT_ID,
        post_logout_redirect_uri: RETURN_URI,
        state: 'nobody-state',
      });

      expect(response.statusCode, response.body).toBe(303);
      expect(response.headers['location']).toBe(`${RETURN_URI}?state=nobody-state`);
      expect(await eventsOf(SIGN_OUT_FAILED)).toEqual([
        expect.objectContaining({ data: expect.objectContaining({ reason: 'no_session' }) }),
      ]);
    });

    it('shows the signed-out page with no return URI', async () => {
      const response = await endSession(new CookieJar(), {});

      expect(response.statusCode, response.body).toBe(200);
      expect(response.body).toContain('You are signed out');
      expect(await statusFor(undefined)).toBe('signed_out');
    });
  });
});
