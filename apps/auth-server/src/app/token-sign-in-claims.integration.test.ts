import { sessionCacheKey } from '@qauth-labs/fastify-plugin-sessions';
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
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { SESSION_COOKIE, sessionIdOfCookie } from '../testing/session-cookie-value';

/**
 * HOW AND WHEN THE USER SIGNED IN, ON THE TOKENS OF A BROWSER SIGN-IN (#662;
 * ADR-017 Decision 10, ADR-020 §3; RFC 9068 §2.2.1, RFC 8176), end to end
 * against real Postgres and Redis, with INTERACTION_UI_ENABLED on.
 *
 * It proves the issue's integration criteria:
 *
 * - A password sign-in, on the hosted pages (the sign-in engine) and on the
 *   server-rendered `/ui/login`, gives an ID token and an access token with
 *   `amr: ["pwd"]` and the session's `auth_time`; the browser session, the
 *   code and the refresh family hold both.
 * - After a refresh, both claims are unchanged.
 * - A session created before the change, which stored no `amr`, gives tokens
 *   without `amr` (and its `auth_time`, as before).
 * - `max_age` still evaluates against the session's authentication time, not
 *   its creation, and the ID token asserts that time.
 *
 * Registration and reset codes are covered by their own suites
 * (`registration.integration.test.ts`, `password-reset.integration.test.ts`).
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const EMAIL = 'sign-in-claims@example.test';
const ORIGIN = 'https://auth.example.com';
const CLIENT_ID = 'sign-in-claims-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
const STEP_UP = 'urn:qauth:event:step_up.required:v1-rc.0';
/** An interaction id: 43 base64url characters. */
const INTERACTION_ID = /^[A-Za-z0-9_-]{43}$/;
const MINUTE = 60_000;

/** The tokens of a token response, their claims decoded. */
interface IssuedTokens {
  readonly access: Record<string, unknown>;
  readonly id?: Record<string, unknown>;
  readonly refreshToken?: string;
}

describe('amr and auth_time on the tokens of a browser sign-in (#662, real containers)', () => {
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
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      INTERACTION_UI_ENABLED: 'true',
    });
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
      name: 'Sign-in claims app',
      redirectUris: [REDIRECT_URI],
      scopes: ['openid', 'email'],
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
      // A seeded client: its redirect URI receives authorization errors.
      provisionedByOperator: true,
    });
    clientRowId = client.id;
    // A remembered consent: no consent step, and the code buys a refresh
    // token (a family) as well.
    await app.repositories.oauthConsents.upsertGrant(realmId, userId, clientRowId, [
      'openid',
      'email',
    ]);
  }, 120_000);

  afterEach(() => {
    vi.useRealTimers();
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

  /** `/oauth/authorize` for the client, from the browser holding `jar`. */
  async function authorize(
    jar: CookieJar,
    challenge: string,
    extra: Record<string, string> = {}
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
        state: 'sign-in-claims-state',
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

  /** The code of a redirect back to the client. */
  function codeOf(response: LightMyRequestResponse): string {
    expect([302, 303], response.body).toContain(response.statusCode);
    const callback = new URL(String(response.headers['location']));
    expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
    const code = callback.searchParams.get('code');
    if (code === null) throw new Error(`no code at ${callback.toString()}`);
    return code;
  }

  /** The step read, as the ceremony app's server makes it: the id alone, no cookie. */
  async function read(id: string): Promise<{ step: string; csrf: string }> {
    const response = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}`,
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json() as { step: string; csrf: string };
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

  /** Sign in with the password at the interaction `id`: the response to the password answer. */
  async function signInAt(jar: CookieJar, id: string): Promise<LightMyRequestResponse> {
    expect((await read(id)).step).toBe(IDENTIFIER);
    const identified = await answer(jar, id, IDENTIFIER, { login_hint: EMAIL });
    expect(identified.statusCode, identified.body).toBe(303);
    expect((await read(id)).step).toBe(PASSWORD);
    return answer(jar, id, PASSWORD, { password: E2E_PASSWORD });
  }

  /** The decoded tokens of a successful token response. */
  function tokensOf(response: LightMyRequestResponse): IssuedTokens {
    expect(response.statusCode, response.body).toBe(200);
    const body = response.json() as {
      access_token: string;
      id_token?: string;
      refresh_token?: string;
    };
    return {
      access: decodeJwtClaims(body.access_token),
      ...(body.id_token === undefined ? {} : { id: decodeJwtClaims(body.id_token) }),
      ...(body.refresh_token === undefined ? {} : { refreshToken: body.refresh_token }),
    };
  }

  async function exchange(code: string, verifier: string): Promise<IssuedTokens> {
    return tokensOf(
      await server().inject({
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
      })
    );
  }

  async function refresh(refreshToken: string): Promise<IssuedTokens> {
    return tokensOf(
      await server().inject({
        method: 'POST',
        url: '/oauth/token',
        headers: FORM,
        payload: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: CLIENT_ID,
        }).toString(),
      })
    );
  }

  /** The browser session the jar's cookie names. */
  function sidOf(jar: CookieJar): string {
    const cookie = jar.get(SESSION_COOKIE);
    if (cookie === undefined) throw new Error('the browser holds no session');
    return sessionIdOfCookie(cookie);
  }

  /** The session's stored `auth_time` (epoch ms) and `amr`. */
  async function sessionRow(sid: string): Promise<{ authTime: number; amr: unknown }> {
    const [row] = await query<{ auth_time: string; amr: unknown }>(
      'SELECT auth_time, amr FROM sessions WHERE id = $1',
      [sid]
    );
    if (row === undefined) throw new Error(`no session ${sid}`);
    return { authTime: Number(row.auth_time), amr: row.amr };
  }

  /**
   * Change the session's row as `sql` says and drop its cache entry, so the
   * next request reads the row: what a previous release left, or a session
   * that authenticated earlier than it was created.
   */
  async function rewriteSession(sid: string, sql: string): Promise<void> {
    await query(sql, [sid]);
    await server().redis.del(sessionCacheKey(realmId, sid));
  }

  /** The `auth_time` claim of a session that authenticated at `authTimeMs`. */
  const seconds = (authTimeMs: number) => Math.floor(authTimeMs / 1000);

  it('puts amr ["pwd"] and the auth_time of a hosted-page password sign-in on both tokens, and keeps them across refreshes', async () => {
    const jar = new CookieJar();
    const pkce = pkcePair();
    const id = interactionIdOf(await authorize(jar, pkce.challenge));
    const before = Date.now();
    const finished = await signInAt(jar, id);
    const after = Date.now();
    const code = codeOf(finished);

    // The session holds the engine's amr and auth_time: when the password
    // passed, during the answer.
    const session = await sessionRow(sidOf(jar));
    expect(session.amr).toEqual(['pwd']);
    expect(session.authTime).toBeGreaterThanOrEqual(before);
    expect(session.authTime).toBeLessThanOrEqual(after);
    // The code copied both at mint time.
    const [stored] = await query<{ auth_time: string; amr: unknown }>(
      'SELECT auth_time, amr FROM authorization_codes WHERE oauth_client_id = $1',
      [clientRowId]
    );
    expect({ authTime: Number(stored?.auth_time), amr: stored?.amr }).toEqual(session);

    const issued = await exchange(code, pkce.verifier);
    const claims = { auth_time: seconds(session.authTime), amr: ['pwd'] };
    expect(issued.id).toMatchObject({ sub: userId, ...claims });
    expect(issued.access).toMatchObject({ sub: userId, ...claims });
    // The family holds them for every rotation.
    const [family] = await query<{ auth_time: string; amr: unknown }>(
      'SELECT auth_time, amr FROM refresh_tokens WHERE user_id = $1',
      [userId]
    );
    expect({ authTime: Number(family?.auth_time), amr: family?.amr }).toEqual(session);

    // Refreshed later, twice: the sign-in stays what it was (RFC 9068 §2.2.1).
    vi.setSystemTime(Date.now() + 2 * MINUTE);
    const first = await refresh(issued.refreshToken as string);
    expect(first.access).toMatchObject({ sub: userId, ...claims });
    expect(first.access['iat']).toBeGreaterThan(issued.access['iat'] as number);
    vi.setSystemTime(Date.now() + 2 * MINUTE);
    const second = await refresh(first.refreshToken as string);
    expect(second.access).toMatchObject({ sub: userId, ...claims });
    // Refreshes reissue no ID token.
    expect(second.id).toBeUndefined();
  });

  it('puts amr ["pwd"] and the auth_time of a password sign-in on /ui/login on both tokens', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const session = await sessionRow(sidOf(jar));
    expect(session.amr).toEqual(['pwd']);
    const pkce = pkcePair();

    // Signed in, with a remembered consent: the code comes at once.
    const issued = await exchange(codeOf(await authorize(jar, pkce.challenge)), pkce.verifier);

    const claims = { auth_time: seconds(session.authTime), amr: ['pwd'] };
    expect(issued.id).toMatchObject({ sub: userId, ...claims });
    expect(issued.access).toMatchObject({ sub: userId, ...claims });
  });

  it('gives the tokens of a session created before the change no amr, and keeps its auth_time', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const sid = sidOf(jar);
    // What the previous release stored: no methods (the column's default).
    await rewriteSession(sid, `UPDATE sessions SET amr = '[]'::jsonb WHERE id = $1`);
    const session = await sessionRow(sid);
    expect(session.amr).toEqual([]);
    const pkce = pkcePair();

    const issued = await exchange(codeOf(await authorize(jar, pkce.challenge)), pkce.verifier);

    const [stored] = await query<{ amr: unknown }>(
      'SELECT amr FROM authorization_codes WHERE oauth_client_id = $1',
      [clientRowId]
    );
    expect(stored).toEqual({ amr: null });
    expect(issued.id).toMatchObject({ sub: userId, auth_time: seconds(session.authTime) });
    expect(issued.id).not.toHaveProperty('amr');
    expect(issued.access).toMatchObject({ sub: userId, auth_time: seconds(session.authTime) });
    expect(issued.access).not.toHaveProperty('amr');
    // Nor after a refresh.
    const refreshed = await refresh(issued.refreshToken as string);
    expect(refreshed.access).toMatchObject({ auth_time: seconds(session.authTime) });
    expect(refreshed.access).not.toHaveProperty('amr');
  });

  it('evaluates max_age against the session’s authentication time, not its creation', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const sid = sidOf(jar);
    // Created just now, but the sign-in it holds happened two minutes ago.
    await rewriteSession(
      sid,
      `UPDATE sessions SET auth_time = auth_time - ${2 * MINUTE} WHERE id = $1`
    );
    const session = await sessionRow(sid);
    const stepUps = async () =>
      (await query('SELECT 1 FROM events WHERE type = $1', [STEP_UP])).length;
    const stepUpsBefore = await stepUps();

    // One minute is too old for that sign-in: a fresh one is asked for.
    const stale = await authorize(jar, pkcePair().challenge, { max_age: '60' });
    expect((await read(interactionIdOf(stale))).step).toBe(IDENTIFIER);
    expect(await stepUps()).toBe(stepUpsBefore + 1);

    // Ten minutes are not: the code comes at once, and its tokens assert the
    // sign-in's time, not the code's.
    const pkce = pkcePair();
    const fresh = await authorize(jar, pkce.challenge, { max_age: '600' });
    const issued = await exchange(codeOf(fresh), pkce.verifier);
    expect(issued.id).toMatchObject({ auth_time: seconds(session.authTime), amr: ['pwd'] });
    expect(issued.access).toMatchObject({ auth_time: seconds(session.authTime), amr: ['pwd'] });
  });
});
