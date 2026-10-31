import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  decodeHtmlEntities,
  decodeJwtClaims,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  extractCsrfToken,
  generateJwtPem,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE ID TOKEN'S `sid` IS THE BROWSER SESSION BEHIND THE CODE (ADR-019
 * Decisions 3 and 4, issue #549), end to end against real Postgres and Redis.
 *
 * A browser signs in at `/ui/login`, runs `/oauth/authorize` with its session
 * cookie, and the client redeems the code at `/oauth/token`. The code records
 * the session, the exchange signs its id into the ID token as `sid`, and the
 * session records the client in `session_clients`, the registry back-channel
 * logout will read. The access token, the introspection response and the
 * refresh row never carry it. The headless Bearer hand-off, which gave a code
 * with no browser session, is retired (#524): a request with only a Bearer
 * token signs in first and gets no code.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

/** `SESSION_COOKIE_NAME`, written here: its module reads the environment at import. */
const SESSION_COOKIE = '__Host-qauth_session';
const CLIENT_ID = 'sid-web-app';
const CLIENT_SECRET = 'sid-web-app-secret-0123456789abcdef';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];

interface TokenResponse {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
}

describe('sid on ID tokens and authorization codes (#549, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer(baseEnvironment(infra, await generateJwtPem()));
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
    await resetE2eState(booted.app);
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /** The confidential client, with a stored consent for each user, so no screen shows. */
  async function seedClient(app: FastifyInstance, userIds: string[]): Promise<string> {
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    const client = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(CLIENT_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Session id web app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
    for (const userId of userIds) {
      await app.repositories.oauthConsents.upsertGrant(realm.id, userId, client.id, SCOPES);
    }
    return client.id;
  }

  /** The session id the browser's signed session cookie carries. */
  function cookieSessionId(jar: CookieJar): string {
    const value = jar.get(SESSION_COOKIE);
    if (value === undefined) throw new Error('the browser holds no session cookie');
    return value.slice(0, value.lastIndexOf('.'));
  }

  /** Sign `email` in on the browser whose cookies `jar` holds, as `/ui/login` does. */
  async function signInOn(app: FastifyInstance, jar: CookieJar, email: string): Promise<void> {
    const loginPage = await app.inject({
      method: 'GET',
      url: '/ui/login',
      headers: jar.header() === undefined ? {} : { cookie: jar.header() as string },
    });
    jar.absorb(loginPage.headers['set-cookie']);
    const login = await app.inject({
      method: 'POST',
      url: '/ui/login',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: jar.header() as string,
      },
      payload: new URLSearchParams({
        email,
        password: E2E_PASSWORD,
        csrf_token: extractCsrfToken(loginPage.body),
      }).toString(),
    });
    expect(login.statusCode).toBe(302);
    jar.absorb(login.headers['set-cookie']);
  }

  /** `/oauth/authorize`, authenticated by `headers`; the code it issues. */
  async function authorize(
    app: FastifyInstance,
    headers: Record<string, string>
  ): Promise<{ code: string; verifier: string }> {
    const pkce = pkcePair();
    const response = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'sid-state',
        nonce: 'sid-nonce',
      }).toString()}`,
      headers,
    });
    expect(response.statusCode).toBe(302);
    const location = response.headers['location'] as string;
    const code = new URL(location).searchParams.get('code');
    if (code === null) throw new Error(`authorize returned no code: ${location}`);
    return { code, verifier: pkce.verifier };
  }

  async function exchange(
    app: FastifyInstance,
    grant: { code: string; verifier: string }
  ): Promise<TokenResponse> {
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code: grant.code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: grant.verifier,
      }).toString(),
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json<TokenResponse>();
  }

  /** Authorize with the browser's cookie and redeem the code. */
  async function browserCodeFlow(app: FastifyInstance, jar: CookieJar): Promise<TokenResponse> {
    return exchange(app, await authorize(app, { cookie: jar.header() as string }));
  }

  function idTokenClaims(tokens: TokenResponse): Record<string, unknown> {
    if (tokens.id_token === undefined) throw new Error('the exchange issued no ID token');
    return decodeJwtClaims(tokens.id_token);
  }

  async function registryOf(
    app: FastifyInstance,
    sessionId: string
  ): Promise<{ oauth_client_id: string }[]> {
    const { rows } = await app.dbPool.query<{ oauth_client_id: string }>(
      `SELECT oauth_client_id FROM session_clients WHERE session_id = $1`,
      [sessionId]
    );
    return rows;
  }

  async function codeSession(app: FastifyInstance, code: string): Promise<string | null> {
    const { rows } = await app.dbPool.query<{ session_id: string | null }>(
      `SELECT session_id FROM authorization_codes WHERE code = $1`,
      [code]
    );
    if (rows.length !== 1) throw new Error(`no code row for ${code}`);
    return rows[0].session_id;
  }

  it('gives an ID token whose sid is the session id the cookie carries', async () => {
    const app = server();
    const userId = await registerPasswordAccount(app, 'ada@example.test');
    const clientRowId = await seedClient(app, [userId]);
    const jar = await signInWithPassword(app, 'ada@example.test');
    const sid = cookieSessionId(jar);

    const grant = await authorize(app, { cookie: jar.header() as string });
    expect(await codeSession(app, grant.code)).toBe(sid);
    const claims = idTokenClaims(await exchange(app, grant));

    expect(claims['sid']).toBe(sid);
    expect(claims['sub']).toBe(userId);
    // The session is the one the user signed in with, and it served the client.
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    expect(await app.repositories.sessions.findById(realm?.id as string, sid)).toMatchObject({
      userId,
      revokedAt: null,
    });
    expect(await registryOf(app, sid)).toEqual([{ oauth_client_id: clientRowId }]);
  });

  // One browser holds one session cookie today, so the second sign-in replaces
  // the first; the cookie layout for several accounts at once (ADR-019
  // Decision 3, 2026-10-10) will keep each account's session and its `sid`.
  // What this proves now: each account's sign-in on the browser is its own
  // session, and its ID token names that one.
  it('gives two accounts signed in on one browser different sid values', async () => {
    const app = server();
    const alice = await registerPasswordAccount(app, 'alice@example.test');
    const bob = await registerPasswordAccount(app, 'bob@example.test');
    await seedClient(app, [alice, bob]);
    const browser = new CookieJar();

    await signInOn(app, browser, 'alice@example.test');
    const aliceSid = cookieSessionId(browser);
    const aliceClaims = idTokenClaims(await browserCodeFlow(app, browser));

    await signInOn(app, browser, 'bob@example.test');
    const bobSid = cookieSessionId(browser);
    const bobClaims = idTokenClaims(await browserCodeFlow(app, browser));

    expect(aliceClaims).toMatchObject({ sub: alice, sid: aliceSid });
    expect(bobClaims).toMatchObject({ sub: bob, sid: bobSid });
    expect(aliceSid).not.toBe(bobSid);
  });

  it('records the session and the client when the consent form mints the code', async () => {
    const app = server();
    const userId = await registerPasswordAccount(app, 'consenting@example.test');
    // No stored consent: the consent screen shows, and its form mints the code.
    const clientRowId = await seedClient(app, []);
    const jar = await signInWithPassword(app, 'consenting@example.test');
    const sid = cookieSessionId(jar);
    const pkce = pkcePair();

    const authorizeResponse = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'sid-state',
      }).toString()}`,
      headers: { cookie: jar.header() as string },
    });
    const consentUrl = authorizeResponse.headers['location'] as string;
    expect(consentUrl.startsWith('/ui/consent?')).toBe(true);
    const screen = await app.inject({
      method: 'GET',
      url: consentUrl,
      headers: { cookie: jar.header() as string },
    });
    expect(screen.statusCode).toBe(200);
    const hidden = Object.fromEntries(
      [...screen.body.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)].map(
        ([, name, value]) => [name, decodeHtmlEntities(value)]
      )
    );
    const decision = await app.inject({
      method: 'POST',
      url: '/ui/consent',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: jar.header() as string,
      },
      payload: new URLSearchParams({ ...hidden, decision: 'allow' }).toString(),
    });
    expect(decision.statusCode).toBe(302);
    const code = new URL(decision.headers['location'] as string).searchParams.get('code');
    if (code === null) throw new Error('the consent form issued no code');

    expect(await codeSession(app, code)).toBe(sid);
    expect(await registryOf(app, sid)).toEqual([{ oauth_client_id: clientRowId }]);
    const claims = idTokenClaims(await exchange(app, { code, verifier: pkce.verifier }));
    expect(claims).toMatchObject({ sub: userId, sid });
  });

  it('records one session_clients row for two codes of one client in one session', async () => {
    const app = server();
    const userId = await registerPasswordAccount(app, 'repeat@example.test');
    const clientRowId = await seedClient(app, [userId]);
    const jar = await signInWithPassword(app, 'repeat@example.test');
    const sid = cookieSessionId(jar);

    const first = await authorize(app, { cookie: jar.header() as string });
    const second = await authorize(app, { cookie: jar.header() as string });
    expect(first.code).not.toBe(second.code);

    expect(await codeSession(app, first.code)).toBe(sid);
    expect(await codeSession(app, second.code)).toBe(sid);
    expect(await registryOf(app, sid)).toEqual([{ oauth_client_id: clientRowId }]);
    // So does the registry seen from the user and from the client.
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    expect(await app.repositories.sessions.listClientsForUser(realm?.id as string, userId)).toEqual(
      [expect.objectContaining({ sessionId: sid, oauthClientId: clientRowId })]
    );
  });

  it('keeps the session id out of the access token, the introspection response and the refresh row', async () => {
    const app = server();
    const userId = await registerPasswordAccount(app, 'grace@example.test');
    await seedClient(app, [userId]);
    const jar = await signInWithPassword(app, 'grace@example.test');
    const sid = cookieSessionId(jar);

    const tokens = await browserCodeFlow(app, jar);
    expect(idTokenClaims(tokens)['sid']).toBe(sid);

    const accessClaims = decodeJwtClaims(tokens.access_token);
    expect(Object.hasOwn(accessClaims, 'sid')).toBe(false);
    expect(JSON.stringify(accessClaims)).not.toContain(sid);

    const introspection = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        token: tokens.access_token,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }).toString(),
    });
    expect(introspection.statusCode).toBe(200);
    expect(introspection.json()).toMatchObject({ active: true, sub: userId });
    expect(Object.hasOwn(introspection.json(), 'sid')).toBe(false);
    expect(introspection.body).not.toContain(sid);

    expect(tokens.refresh_token).toBeDefined();
    const refreshed = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token as string,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }).toString(),
    });
    expect(refreshed.statusCode, refreshed.body).toBe(200);
    expect(refreshed.body).not.toContain(sid);
    expect(
      JSON.stringify(decodeJwtClaims(refreshed.json<TokenResponse>().access_token))
    ).not.toContain(sid);

    // Both rows of the family, whole, as stored.
    const { rows } = await app.dbPool.query<{ row: string }>(
      `SELECT to_jsonb(r)::text AS row FROM refresh_tokens r ORDER BY created_at, id`
    );
    expect(rows).toHaveLength(2);
    for (const { row } of rows) expect(row).not.toContain(sid);
  });

  it('issues no code from the retired headless Bearer hand-off (#524)', async () => {
    const app = server();
    const userId = await registerPasswordAccount(app, 'headless@example.test');
    await seedClient(app, [userId]);
    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'headless@example.test', password: E2E_PASSWORD },
    });
    expect(login.statusCode).toBe(200);
    const bearer = login.json<{ access_token: string }>().access_token;

    const response = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkcePair().challenge,
        code_challenge_method: 'S256',
        state: 'sid-state',
      }).toString()}`,
      headers: { authorization: `Bearer ${bearer}` },
    });

    expect(response.statusCode).toBe(302);
    expect(response.headers['location']).toMatch(/^\/ui\/login\?return_to=/);
    const { rows } = await app.dbPool.query(`SELECT 1 FROM authorization_codes`);
    expect(rows).toEqual([]);
  });

  it('sets the code’s session to null when the session is deleted, and keeps the code', async () => {
    const app = server();
    const userId = await registerPasswordAccount(app, 'purged@example.test');
    await seedClient(app, [userId]);
    const jar = await signInWithPassword(app, 'purged@example.test');
    const sid = cookieSessionId(jar);
    const grant = await authorize(app, { cookie: jar.header() as string });
    expect(await codeSession(app, grant.code)).toBe(sid);

    // What a purge of ended sessions does to the row.
    await app.dbPool.query(`DELETE FROM sessions WHERE id = $1`, [sid]);

    expect(await codeSession(app, grant.code)).toBeNull();
    expect(await registryOf(app, sid)).toEqual([]);
  });

  it('deletes the session’s registry rows when the user signs out', async () => {
    const app = server();
    const userId = await registerPasswordAccount(app, 'leaving@example.test');
    const clientRowId = await seedClient(app, [userId]);
    const jar = await signInWithPassword(app, 'leaving@example.test');
    const sid = cookieSessionId(jar);
    await browserCodeFlow(app, jar);
    expect(await registryOf(app, sid)).toEqual([{ oauth_client_id: clientRowId }]);

    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'leaving@example.test', password: E2E_PASSWORD },
    });
    const logout = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: { authorization: `Bearer ${login.json<{ access_token: string }>().access_token}` },
    });
    expect(logout.statusCode).toBe(200);

    expect(await registryOf(app, sid)).toEqual([]);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    expect(await app.repositories.sessions.findById(realm?.id as string, sid)).toMatchObject({
      revokedReason: 'sign_out_everywhere',
    });
  });
});
