import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  extractCsrfToken,
  generateJwtPem,
  type PemKeyPair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { SESSION_COOKIE, sessionCookieParts } from '../testing/session-cookie-value';

/**
 * THE BROWSER COOKIES ARE SIGNED WITH THE REALM'S COOKIE KEY, AGAINST A REAL
 * POSTGRES AND REDIS (ADR-019 Decision 3 and Decision 9, issue #493).
 *
 * Each test boots the real auth-server and signs in through the real
 * `/ui/login` form. The session cookie is `<kid>.<payload>.<mac>`, signed with
 * the realm's active `cookie_hmac` key, which the signer hands the
 * browser-facing role: no process reads `SESSION_COOKIE_SECRET` to sign or
 * verify a cookie. The variable is read only by the key boot step, where a
 * different value replaces the stored cookie key, so a change of it is how a
 * deployment rotates the cookie key until rotation through the store ships
 * (#544, #551).
 *
 * A server reads a realm's cookie keys at most once a minute, so a test that
 * changes them boots another server on the same containers to see the
 * change, as a node that starts after it does.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const EMAIL = 'cookie-owner@example.com';
const LOGIN_CSRF_COOKIE = '__Host-qauth_login_csrf';
const SECRET_ONE = 'the-first-session-cookie-secret-of-this-deployment';
const SECRET_TWO = 'the-second-session-cookie-secret-of-this-deployment';

/** The `Set-Cookie` header the response set for `name`. */
function setCookieFor(headers: Record<string, unknown>, name: string): string {
  const all = [headers['set-cookie'] ?? []].flat() as string[];
  const found = all.find((value) => value.startsWith(`${name}=`));
  if (found === undefined) throw new Error(`no Set-Cookie for ${name}: ${JSON.stringify(all)}`);
  return found;
}

/** A `Set-Cookie` header's attributes after the name-value pair, as written. */
function attributesOf(header: string): string[] {
  return header
    .split(';')
    .slice(1)
    .map((part) => part.trim());
}

describe('the browser cookies on the realm cookie key (#493, real containers)', () => {
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
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
    // The harness clears only its listed prefixes between boots.
    delete process.env['SESSION_COOKIE_TTL'];
    delete process.env['SESSION_COOKIE_SECURE'];
  });

  /**
   * The base environment with `overrides`; an `undefined` override leaves the
   * variable out, so the server boots without it.
   */
  function environment(overrides: Record<string, string | undefined> = {}): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const merged: Record<string, string | undefined> = {
      ...baseEnvironment(infra, jwt),
      ...overrides,
    };
    return Object.fromEntries(
      Object.entries(merged).filter((entry): entry is [string, string] => entry[1] !== undefined)
    );
  }

  /** Boot a server on the suite's containers, keeping what they hold. */
  async function bootOn(
    overrides: Record<string, string | undefined> = {}
  ): Promise<FastifyInstance> {
    const server = await bootAuthServer(environment(overrides));
    booted.push(server);
    return server.app;
  }

  /** Boot on an empty state, with a verified password account in the default realm. */
  async function bootFresh(
    overrides: Record<string, string | undefined> = {}
  ): Promise<FastifyInstance> {
    const app = await bootOn(overrides);
    await resetE2eState(app);
    await registerPasswordAccount(app, EMAIL);
    return app;
  }

  /** The default realm's cookie keys, by status, as the key store holds them. */
  async function cookieKeys(app: FastifyInstance): Promise<{ kid: string; status: string }[]> {
    const { rows } = await app.dbPool.query<{ kid: string; status: string }>(
      `SELECT k.kid, k.status FROM realm_keys k JOIN realms r ON r.id = k.realm_id
       WHERE r.name = $1 AND k.purpose = 'cookie_hmac' ORDER BY k.created_at, k.kid`,
      [E2E_REALM_NAME]
    );
    return rows;
  }

  async function activeCookieKid(app: FastifyInstance): Promise<string> {
    const active = (await cookieKeys(app)).filter((key) => key.status === 'active');
    expect(active).toHaveLength(1);
    return active[0].kid;
  }

  /** Sign in through `/ui/login` by hand: the login page's and the form post's responses. */
  async function signInByHand(app: FastifyInstance) {
    const jar = new CookieJar();
    const page = await app.inject({ method: 'GET', url: '/ui/login' });
    jar.absorb(page.headers['set-cookie']);
    const login = await app.inject({
      method: 'POST',
      url: '/ui/login',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: jar.header() as string,
      },
      payload: new URLSearchParams({
        email: EMAIL,
        password: E2E_PASSWORD,
        csrf_token: extractCsrfToken(page.body),
      }).toString(),
    });
    return { page, login };
  }

  /** `GET /consents`: 200 for a browser with a live session, 401 without one. */
  async function consents(app: FastifyInstance, jar: CookieJar) {
    return app.inject({
      method: 'GET',
      url: '/consents',
      headers: jar.header() === undefined ? {} : { cookie: jar.header() as string },
    });
  }

  it('sets the session cookie as __Host-, Path=/, HttpOnly, SameSite=Lax, Secure and no Domain', async () => {
    // SESSION_COOKIE_SECURE is on unless a development stack turns it off.
    const app = await bootFresh({ SESSION_COOKIE_SECURE: 'true' });

    const { page, login } = await signInByHand(app);

    expect(login.statusCode).toBe(302);
    const header = setCookieFor(login.headers, SESSION_COOKIE);
    expect(SESSION_COOKIE.startsWith('__Host-')).toBe(true);
    expect(attributesOf(header)).toEqual(
      expect.arrayContaining(['Path=/', 'HttpOnly', 'SameSite=Lax', 'Secure'])
    );
    expect(header).not.toMatch(/;\s*Domain=/i);
    // The login-CSRF cookie the page set carries the same attributes.
    const csrfHeader = setCookieFor(page.headers, LOGIN_CSRF_COOKIE);
    expect(attributesOf(csrfHeader)).toEqual(
      expect.arrayContaining(['Path=/', 'HttpOnly', 'SameSite=Lax', 'Secure'])
    );
    expect(csrfHeader).not.toMatch(/;\s*Domain=/i);
  }, 90_000);

  it("sets Max-Age to the time left until the session's absolute end", async () => {
    // The realm's maximum lifespan ends sessions sooner than SESSION_COOKIE_TTL.
    const app = await bootFresh({ SESSION_COOKIE_TTL: '7200', SESSION_COOKIE_SECURE: 'false' });
    await app.dbPool.query('UPDATE realms SET sso_max_lifespan = 5400 WHERE name = $1', [
      E2E_REALM_NAME,
    ]);
    app.realmHostCache.clear();

    const { login } = await signInByHand(app);
    const answeredAt = Date.now();

    expect(login.statusCode).toBe(302);
    const header = setCookieFor(login.headers, SESSION_COOKIE);
    const maxAge = Number(/Max-Age=(\d+)/.exec(header)?.[1]);
    const { sid } = sessionCookieParts(header.split(';')[0].slice(`${SESSION_COOKIE}=`.length));
    const { rows } = await app.dbPool.query<{ expires_at: string }>(
      'SELECT expires_at FROM sessions WHERE id = $1',
      [sid]
    );
    const expiresAt = Number(rows[0]?.expires_at);
    // The session ends 5400 s after it was created, not SESSION_COOKIE_TTL after.
    expect(maxAge).toBeLessThanOrEqual(5400);
    expect(maxAge).toBeGreaterThan(5400 - 30);
    // And the cookie ends with it: never after, at most a moment before.
    expect(maxAge).toBeLessThanOrEqual(Math.ceil((expiresAt - answeredAt) / 1000) + 1);
    expect(maxAge).toBeGreaterThanOrEqual(Math.floor((expiresAt - answeredAt) / 1000) - 2);
  }, 90_000);

  it("signs the cookie with the realm's active cookie key, which it names", async () => {
    const app = await bootFresh();

    const jar = await signInWithPassword(app, EMAIL);

    const value = jar.get(SESSION_COOKIE);
    if (value === undefined) throw new Error('the sign-in set no session cookie');
    expect(sessionCookieParts(value).kid).toBe(await activeCookieKid(app));
    expect((await consents(app, jar)).statusCode).toBe(200);
  }, 90_000);

  it('keeps a cookie of the previous key verifiable after a cookie-key rotation, and refuses it after its retention', async () => {
    // The first node imports SESSION_COOKIE_SECRET as the realm's cookie key.
    const first = await bootFresh({ SESSION_COOKIE_SECRET: SECRET_ONE });
    const firstKid = await activeCookieKid(first);
    const before = await signInWithPassword(first, EMAIL);
    expect(sessionCookieParts(before.get(SESSION_COOKIE) as string).kid).toBe(firstKid);

    // A node that boots with another secret rotates the cookie key: the old
    // key is retired, and stays the previous key.
    const second = await bootOn({ SESSION_COOKIE_SECRET: SECRET_TWO });
    const secondKid = await activeCookieKid(second);
    expect(secondKid).not.toBe(firstKid);
    expect(await cookieKeys(second)).toEqual(
      expect.arrayContaining([{ kid: firstKid, status: 'retired' }])
    );

    expect((await consents(second, before)).statusCode).toBe(200);
    const after = await signInWithPassword(second, EMAIL);
    expect(sessionCookieParts(after.get(SESSION_COOKIE) as string).kid).toBe(secondKid);

    // The end of the old key's retention: the store no longer holds it, as
    // the retention purge (#542) leaves it. A node that reads the keys after
    // that refuses the cookie it signed, and clears it.
    await second.dbPool.query('DELETE FROM realm_keys WHERE kid = $1', [firstKid]);
    const third = await bootOn({ SESSION_COOKIE_SECRET: SECRET_TWO });

    const refused = await consents(third, before);
    expect(refused.statusCode).toBe(401);
    expect(setCookieFor(refused.headers, SESSION_COOKIE)).toMatch(
      new RegExp(`^${SESSION_COOKIE}=;.*Max-Age=0`)
    );
    expect((await consents(third, after)).statusCode).toBe(200);
  }, 180_000);

  it('a web-role process with no SESSION_COOKIE_SECRET signs in with the key the signer supplies', async () => {
    // The account is registered on a process that holds every role.
    const all = await bootFresh({ SESSION_COOKIE_SECRET: undefined });
    const generatedKid = await activeCookieKid(all);

    const web = await bootOn({ SESSION_COOKIE_SECRET: undefined, SERVICE_ROLES: 'web,signer' });
    expect(process.env['SESSION_COOKIE_SECRET']).toBeUndefined();

    const jar = await signInWithPassword(web, EMAIL);

    const value = jar.get(SESSION_COOKIE);
    if (value === undefined) throw new Error('the sign-in set no session cookie');
    expect(sessionCookieParts(value).kid).toBe(generatedKid);
    expect((await consents(web, jar)).statusCode).toBe(200);
  }, 180_000);
});
