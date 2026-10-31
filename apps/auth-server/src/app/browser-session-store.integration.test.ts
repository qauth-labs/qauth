import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

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
  type PemKeyPair,
  pkcePair,
  provisionRealmKeys,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { sessionIdOfCookie } from '../testing/session-cookie-value';
import type { RealmRow } from './helpers/request-realm';

/**
 * BROWSER SIGN-IN AND THE SESSION LOOKUP RUN ON THE SESSION SERVICE, AGAINST A
 * REAL POSTGRES AND REDIS (ADR-019 Decision 3, issue #488).
 *
 * Each test boots the real auth-server, empties its state, and drives the real
 * routes: `/ui/login` creates a `sessions` row, `/oauth/authorize` and the
 * consent screen find it through `fastify.sessionService`, the consent screen's
 * CSRF values live in a Redis side record and never in Postgres, `/oauth/token`
 * and `/auth/login` create no row, and a cookie of one realm names no session
 * at another realm's host.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const HOST_B = 'beta.example.com';
const EMAIL = 'session-owner@example.com';
const CLIENT_ID = 'e2e-session-client';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const USER_AGENT = 'SessionSuite/1.0 (integration)';
const CLIENT_ADDRESS = '203.0.113.9';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/**
 * `SESSION_COOKIE_NAME`, written out: importing the cookie helper would load
 * the env module before `bootAuthServer` sets the environment.
 */
const SESSION_COOKIE_NAME = '__Host-qauth_session';

/** A `sessions` row, as Postgres returns it. */
interface SessionRow {
  id: string;
  realm_id: string;
  user_id: string;
  auth_time: string;
  amr: string[];
  assurance_level: string | null;
  ip_address: string | null;
  user_agent: string | null;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
}

describe('browser sessions on the session service (#488, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  });

  /** Boot on an empty state with a public PKCE client and a verified account in the default realm. */
  async function boot(): Promise<{ app: FastifyInstance; realm: RealmRow; userId: string }> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const server = await bootAuthServer(baseEnvironment(infra, jwt));
    booted.push(server);
    const { app } = server;
    await resetE2eState(app);

    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('the default realm boot step left no realm');
    await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'E2E session client',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      enabled: true,
      requirePkce: true,
    });
    const userId = await registerPasswordAccount(app, EMAIL);
    return { app, realm, userId };
  }

  /** Sign in through the real `/ui/login` form, from a known address and user agent. */
  async function signIn(app: FastifyInstance): Promise<CookieJar> {
    const jar = new CookieJar();
    const page = await app.inject({ method: 'GET', url: '/ui/login' });
    jar.absorb(page.headers['set-cookie']);
    const login = await app.inject({
      method: 'POST',
      url: '/ui/login',
      remoteAddress: CLIENT_ADDRESS,
      headers: { ...FORM, 'user-agent': USER_AGENT, cookie: jar.header() as string },
      payload: new URLSearchParams({
        email: EMAIL,
        password: E2E_PASSWORD,
        csrf_token: extractCsrfToken(page.body),
      }).toString(),
    });
    expect(login.statusCode).toBe(302);
    jar.absorb(login.headers['set-cookie']);
    return jar;
  }

  /** The active `sid` the jar's session cookie carries (`<kid>.<payload>.<mac>`, #493). */
  function sidOf(jar: CookieJar): string {
    const value = jar.get(SESSION_COOKIE_NAME);
    if (value === undefined) throw new Error('the jar holds no session cookie');
    return sessionIdOfCookie(value);
  }

  async function sessionRows(app: FastifyInstance): Promise<SessionRow[]> {
    const { rows } = await app.dbPool.query<SessionRow>(
      'SELECT * FROM sessions ORDER BY created_at, id'
    );
    return rows;
  }

  function authorizeUrl(challenge: string): string {
    return `/oauth/authorize?${new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPES.join(' '),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: 'session-state',
    }).toString()}`;
  }

  /** Redeem a code at `/oauth/token`, as the public client. */
  async function redeem(app: FastifyInstance, code: string, verifier: string) {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: verifier,
      }).toString(),
    });
  }

  it('a password sign-in creates one sessions row with the realm, user, auth_time, address and user agent', async () => {
    const { app, realm, userId } = await boot();

    const before = Date.now();
    const jar = await signIn(app);
    const after = Date.now();

    const rows = await sessionRows(app);
    expect(rows).toHaveLength(1);
    const [row] = rows;
    expect(row).toMatchObject({
      id: sidOf(jar),
      realm_id: realm.id,
      user_id: userId,
      assurance_level: null,
      ip_address: CLIENT_ADDRESS,
      user_agent: USER_AGENT,
      revoked_at: null,
    });
    expect(Number(row.auth_time)).toBeGreaterThanOrEqual(before);
    expect(Number(row.auth_time)).toBeLessThanOrEqual(after);
  }, 60_000);

  it('/oauth/authorize finds the session through the service and copies auth_time to the code; the token request creates no row', async () => {
    const { app, realm, userId } = await boot();
    const client = await app.repositories.oauthClients.findByClientId(realm.id, CLIENT_ID);
    if (!client) throw new Error('client not seeded');
    await app.repositories.oauthConsents.upsertGrant(realm.id, userId, client.id, SCOPES);
    const jar = await signIn(app);
    const [session] = await sessionRows(app);
    const lookups = vi.spyOn(app.sessionService, 'get');

    const pkce = pkcePair();
    const authorize = await app.inject({
      method: 'GET',
      url: authorizeUrl(pkce.challenge),
      headers: { cookie: jar.header() as string },
    });

    expect(authorize.statusCode).toBe(302);
    const code = new URL(authorize.headers['location'] as string).searchParams.get('code');
    expect(code).not.toBeNull();
    expect(lookups).toHaveBeenCalledWith({ realmId: realm.id, sid: session.id });
    const { rows: codes } = await app.dbPool.query<{
      auth_time: string | null;
      assurance_level: string | null;
    }>('SELECT auth_time, assurance_level FROM authorization_codes');
    expect(codes).toEqual([{ auth_time: session.auth_time, assurance_level: null }]);

    const token = await redeem(app, code as string, pkce.verifier);
    expect(token.statusCode).toBe(200);
    const idToken = decodeJwtClaims((token.json() as { id_token: string }).id_token);
    expect(idToken['auth_time']).toBe(Math.floor(Number(session.auth_time) / 1000));
    // The exchange wrote a session record before #488, which nothing read.
    expect(await sessionRows(app)).toHaveLength(1);
  }, 60_000);

  it('POST /auth/login creates no session row', async () => {
    const { app } = await boot();

    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: EMAIL, password: E2E_PASSWORD },
    });

    expect(login.statusCode).toBe(200);
    expect(await sessionRows(app)).toEqual([]);
  }, 60_000);

  it('the consent screen works, with its CSRF values in the Redis side record and not in Postgres', async () => {
    const { app, realm } = await boot();
    const jar = await signIn(app);
    const sid = sidOf(jar);
    const pkce = pkcePair();

    const authorize = await app.inject({
      method: 'GET',
      url: authorizeUrl(pkce.challenge),
      headers: { cookie: jar.header() as string },
    });
    expect(authorize.statusCode).toBe(302);
    const consentUrl = authorize.headers['location'] as string;
    expect(consentUrl.startsWith('/ui/consent?')).toBe(true);

    const screen = await app.inject({
      method: 'GET',
      url: consentUrl,
      headers: { cookie: jar.header() as string },
    });
    expect(screen.statusCode).toBe(200);
    // The identifier the user signed in with, from the side record.
    expect(decodeHtmlEntities(screen.body)).toContain(`Signed in as ${EMAIL}`);
    const csrfToken = extractCsrfToken(screen.body);

    const sideKey = `browser-session-side:${realm.id}:${sid}`;
    const side = await app.redis.hgetall(sideKey);
    expect(side).toMatchObject({
      identifier: EMAIL,
      csrfToken,
      [`consentScopes:${CLIENT_ID}`]: JSON.stringify(SCOPES),
      [`consentResources:${CLIENT_ID}`]: '[]',
    });
    // It expires with the session's absolute end, never later.
    const [session] = await sessionRows(app);
    const expiresAt = await app.redis.pexpiretime(sideKey);
    expect(expiresAt).toBe(Number(session.expires_at));
    // Nothing of it reached Postgres: the row is the session's columns only.
    const { rows } = await app.dbPool.query<{ row: string }>(
      'SELECT to_jsonb(s)::text AS row FROM sessions s'
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].row).not.toContain(csrfToken);
    expect(rows[0].row).not.toContain('consentScopes');

    const hidden = Object.fromEntries(
      [...screen.body.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)].map(
        ([, name, value]) => [name, decodeHtmlEntities(value)]
      )
    );
    const decision = await app.inject({
      method: 'POST',
      url: '/ui/consent',
      headers: { ...FORM, cookie: jar.header() as string },
      payload: new URLSearchParams({ ...hidden, decision: 'allow' }).toString(),
    });

    expect(decision.statusCode).toBe(302);
    const callback = new URL(decision.headers['location'] as string);
    expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
    expect(callback.searchParams.get('code')).not.toBeNull();
    // The token is burned; the bindings stay.
    expect(await app.redis.hget(sideKey, 'csrfToken')).toBeNull();
    expect(await app.redis.hget(sideKey, `consentScopes:${CLIENT_ID}`)).not.toBeNull();
    expect(await sessionRows(app)).toHaveLength(1);
  }, 60_000);

  it('a cookie from realm A at realm B resolves to no session', async () => {
    const { app } = await boot();
    await app.repositories.realms.createWithPrimaryHost(
      { name: 'beta', issuer: `https://${HOST_B}`, enabled: true },
      HOST_B
    );
    // Realm B has its own keys, a cookie key among them, as a realm created
    // with its keys does.
    await provisionRealmKeys(app, 'beta');
    const jar = await signIn(app);
    expect(sidOf(jar)).toBeTruthy();
    const lookups = vi.spyOn(app.sessionService, 'get');

    const atB = await app.inject({
      method: 'GET',
      url: '/consents',
      headers: { host: HOST_B, cookie: jar.header() as string },
    });
    expect(atB.statusCode).toBe(401);
    expect(atB.json()).toMatchObject({ status: 401, code: 'unauthorized' });
    // The cookie names realm A's cookie key, which realm B does not hold, and
    // its MAC names realm A (#493): it does not verify at B, so no session is
    // even looked up there, and the cookie is cleared.
    expect(lookups).not.toHaveBeenCalled();
    expect(String(atB.headers['set-cookie'])).toContain(`${SESSION_COOKIE_NAME}=;`);

    // The same cookie at its own realm's host still names the session.
    const atA = await app.inject({
      method: 'GET',
      url: '/consents',
      headers: { cookie: jar.header() as string },
    });
    expect(atA.statusCode).toBe(200);
  }, 60_000);
});
