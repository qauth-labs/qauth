import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type CookieJar,
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
import { NOT_VALID_BEFORE_MARGIN_MS } from './helpers/account-validity';

/**
 * WHAT AN ACCOUNT HELD BEFORE IT WAS DISABLED STAYS REFUSED AFTER IT IS
 * ENABLED AGAIN (#748, GHSA-vw34-9q55-2vg3), end to end against real Postgres
 * and Redis.
 *
 * Since 0.1.0 a disabled account's sessions and tokens are refused where they
 * are used. A session or a refresh token that nobody used while the account
 * was disabled used to work again once it was enabled: whoever held it came
 * back without signing in. Disabling now records `users.not_valid_before`
 * (the trigger of migration 0044, here through a plain `UPDATE`, as an
 * operator types it), and every session and token issued before it is
 * refused for good. What the account is issued after it is enabled again
 * works.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const CLIENT_ID = 'disablement-native-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const EMAIL = 'disablement-owner@example.test';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const RESOURCE_SERVER_ID = 'disablement-resource-server';
const RESOURCE_SERVER_SECRET = 'disablement-resource-server-secret-of-sufficient-length';
/**
 * `SESSION_COOKIE_NAME`, written out: importing the cookie helper would load
 * the env module before `bootAuthServer` sets the environment.
 */
const SESSION_COOKIE_NAME = '__Host-qauth_session';

/** What a signed-in browser and its client hold. */
interface Held {
  readonly cookie: string;
  readonly sid: string;
  readonly accessToken: string;
  readonly refreshToken: string;
}

describe('an account enabled again does not bring back what it held before (#748, real containers)', () => {
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

  /** The booted auth server; only called from a test that was not skipped. */
  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /**
   * A verified account, a public client it has already granted its scopes
   * (so `/oauth/authorize` answers with a code at once), and a confidential
   * resource server that introspects the client's tokens.
   *
   * @returns the account's id
   */
  async function seed(app: FastifyInstance): Promise<string> {
    const userId = await registerPasswordAccount(app, EMAIL);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    const client = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Disablement native app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
    await app.repositories.oauthConsents.upsertGrant(realm.id, userId, client.id, SCOPES);
    await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: RESOURCE_SERVER_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(RESOURCE_SERVER_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Disablement resource server',
      redirectUris: [],
      grantTypes: ['client_credentials'],
      audience: [CLIENT_ID],
      enabled: true,
    });
    return userId;
  }

  /** `GET /oauth/authorize` for a fresh PKCE pair, with `cookie`. */
  async function authorize(
    app: FastifyInstance,
    cookie: string
  ): Promise<{ response: LightMyRequestResponse; verifier: string }> {
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
        state: 'disablement-state',
      }).toString()}`,
      headers: { cookie },
    });
    return { response, verifier: pkce.verifier };
  }

  /** A form-encoded `POST /oauth/token`. */
  function tokenRequest(
    app: FastifyInstance,
    form: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams(form).toString(),
    });
  }

  /** Use `refreshToken` as the public client. */
  function refresh(app: FastifyInstance, refreshToken: string): Promise<LightMyRequestResponse> {
    return tokenRequest(app, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    });
  }

  /** Sign in on the hosted page, then run the code flow: what the browser and the client hold. */
  async function signInAndObtainTokens(app: FastifyInstance): Promise<Held> {
    const jar = await signInWithPassword(app, EMAIL);
    const cookie = jar.header() as string;
    const value = jar.get(SESSION_COOKIE_NAME);
    if (value === undefined) throw new Error('the sign-in set no session cookie');
    const { response, verifier } = await authorize(app, cookie);
    expect(response.statusCode).toBe(302);
    const code = new URL(response.headers['location'] as string).searchParams.get('code');
    if (code === null) throw new Error(`no code in ${response.headers['location']}`);
    const tokens = await tokenRequest(app, {
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      code_verifier: verifier,
      redirect_uri: REDIRECT_URI,
    });
    expect(tokens.statusCode).toBe(200);
    const body = tokens.json() as { access_token: string; refresh_token: string };
    return {
      cookie,
      sid: sessionIdOfCookie(value),
      accessToken: body.access_token,
      refreshToken: body.refresh_token,
    };
  }

  /** Switch the account as an operator does by hand; the trigger records the disablement. */
  async function setEnabled(app: FastifyInstance, userId: string, enabled: boolean) {
    await app.dbPool.query('UPDATE users SET enabled = $1 WHERE id = $2', [enabled, userId]);
  }

  async function notValidBefore(app: FastifyInstance, userId: string): Promise<number | null> {
    const { rows } = await app.dbPool.query<{ not_valid_before: string | null }>(
      'SELECT not_valid_before FROM users WHERE id = $1',
      [userId]
    );
    const value = rows[0]?.not_valid_before;
    return value === null || value === undefined ? null : Number(value);
  }

  /**
   * Wait until a credential issued now counts as issued after the
   * disablement: past `not_valid_before`, the margin the check allows for the
   * clocks of its issue times, and the second an access token's `iat` drops.
   */
  async function waitPastDisablement(app: FastifyInstance, userId: string): Promise<void> {
    const disabledAt = await notValidBefore(app, userId);
    if (disabledAt === null) throw new Error('the account was never disabled');
    const wait = disabledAt + NOT_VALID_BEFORE_MARGIN_MS + 1000 + 50 - Date.now();
    if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
  }

  /**
   * Wait out the check's margin, so a credential issued before this call
   * counts as issued before a disablement after it only because it was, not
   * because it falls within the margin.
   */
  async function waitPastMargin(): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, NOT_VALID_BEFORE_MARGIN_MS + 100));
  }

  /** `POST /oauth/introspect` by the resource server: the `active` member. */
  async function introspect(app: FastifyInstance, accessToken: string): Promise<unknown> {
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      headers: FORM,
      payload: new URLSearchParams({
        token: accessToken,
        client_id: RESOURCE_SERVER_ID,
        client_secret: RESOURCE_SERVER_SECRET,
      }).toString(),
    });
    expect(response.statusCode).toBe(200);
    return (response.json() as { active: unknown }).active;
  }

  /** The `reason` of every event of `type`, in the order they were recorded. */
  async function reasonsOf(app: FastifyInstance, type: string): Promise<unknown[]> {
    const { rows } = await app.dbPool.query<{ data: Record<string, unknown> }>(
      'SELECT data FROM events WHERE type = $1 ORDER BY seq',
      [type]
    );
    return rows.map((row) => row.data['reason']);
  }

  it('refuses the old refresh token with invalid_grant and sends the old session cookie to sign-in', async () => {
    const app = server();
    const userId = await seed(app);
    const held = await signInAndObtainTokens(app);
    await waitPastMargin();

    // Disabled and enabled again, with nothing used in between.
    await setEnabled(app, userId, false);
    await setEnabled(app, userId, true);
    expect(await notValidBefore(app, userId)).not.toBeNull();

    const refreshed = await refresh(app, held.refreshToken);
    expect(refreshed.statusCode).toBe(400);
    expect(refreshed.json()).toMatchObject({ error: 'invalid_grant' });
    const { rows: tokens } = await app.dbPool.query<{ revoked_reason: string | null }>(
      'SELECT revoked_reason FROM refresh_tokens WHERE user_id = $1',
      [userId]
    );
    expect(tokens).toEqual([{ revoked_reason: 'issued_before_disablement' }]);
    expect(await reasonsOf(app, 'urn:qauth:event:token.request_failed:v1-rc.0')).toEqual([
      'issued_before_disablement',
    ]);

    const { response } = await authorize(app, held.cookie);
    expect(response.statusCode).toBe(302);
    expect(response.headers['location']).toMatch(/^\/ui\/login\?/);
    expect(String(response.headers['set-cookie'])).toContain(`${SESSION_COOKIE_NAME}=;`);
    const { rows: sessions } = await app.dbPool.query<{
      revoked_at: string | null;
      revoked_reason: string | null;
    }>('SELECT revoked_at, revoked_reason FROM sessions WHERE id = $1', [held.sid]);
    expect(sessions).toEqual([{ revoked_at: expect.any(String), revoked_reason: 'admin' }]);
    // The refusal is for good: the token stays refused, as a revoked one.
    expect((await refresh(app, held.refreshToken)).statusCode).toBe(400);
  }, 60_000);

  it('accepts a session and a refresh token issued after the account was enabled again', async () => {
    const app = server();
    const userId = await seed(app);
    const old = await signInAndObtainTokens(app);
    // So what was held before is refused for being issued before the
    // disablement, not for falling within the margin.
    await waitPastMargin();
    await setEnabled(app, userId, false);
    await setEnabled(app, userId, true);
    await waitPastDisablement(app, userId);

    const fresh = await signInAndObtainTokens(app);

    // The new session gives a code at once, as a live session does.
    const { response } = await authorize(app, fresh.cookie);
    expect(response.statusCode).toBe(302);
    expect(new URL(response.headers['location'] as string).searchParams.get('code')).not.toBeNull();
    const refreshed = await refresh(app, fresh.refreshToken);
    expect(refreshed.statusCode).toBe(200);
    expect(await introspect(app, fresh.accessToken)).toBe(true);
    // What was held before stays refused beside it.
    expect((await refresh(app, old.refreshToken)).statusCode).toBe(400);
    expect(await introspect(app, old.accessToken)).toBe(false);
  }, 60_000);

  it('reports an access token issued before the disablement as inactive, and userinfo refuses it', async () => {
    const app = server();
    const userId = await seed(app);
    const held = await signInAndObtainTokens(app);
    expect(await introspect(app, held.accessToken)).toBe(true);
    await waitPastMargin();

    await setEnabled(app, userId, false);
    await setEnabled(app, userId, true);

    expect(await introspect(app, held.accessToken)).toBe(false);
    expect(await reasonsOf(app, 'urn:qauth:event:token.introspection_failed:v1-rc.0')).toEqual([
      'issued_before_disablement',
    ]);
    const userinfo = await app.inject({
      method: 'GET',
      url: '/oauth/userinfo',
      headers: { authorization: `Bearer ${held.accessToken}` },
    });
    expect(userinfo.statusCode).toBe(401);
  }, 60_000);

  it('refuses a session started while the disabling transaction was still open', async () => {
    const app = server();
    const userId = await seed(app);
    const operator = await app.dbPool.connect();
    let signedIn: Promise<CookieJar> | undefined;
    try {
      await operator.query('BEGIN');
      await operator.query('UPDATE users SET enabled = false WHERE id = $1', [userId]);
      // Until the commit every other transaction reads the account as
      // enabled: the sign-in passes its checks and creates its session, past
      // the margin of the time the row changed, then waits for the row lock
      // to record the sign-in time on the account.
      await waitPastMargin();
      signedIn = signInWithPassword(app, EMAIL);
      await waitPastMargin();
      expect(
        (
          await app.dbPool.query<{ count: string }>(
            'SELECT count(*) FROM sessions WHERE user_id = $1',
            [userId]
          )
        ).rows[0].count
      ).toBe('1');
      await operator.query('COMMIT');
    } catch (error) {
      // Released with its transaction open, the client would keep the row
      // lock in the pool and stall the tests after this one.
      await operator.query('ROLLBACK');
      throw error;
    } finally {
      operator.release();
    }
    const jar = await signedIn;
    await setEnabled(app, userId, true);

    const { response } = await authorize(app, jar.header() as string);
    expect(response.statusCode).toBe(302);
    expect(response.headers['location']).toMatch(/^\/ui\/login\?/);
  }, 60_000);

  it('leaves an account that was never disabled as it was', async () => {
    const app = server();
    const userId = await seed(app);
    const held = await signInAndObtainTokens(app);

    // Other updates of the account record nothing.
    await app.dbPool.query('UPDATE users SET last_login_at = 1 WHERE id = $1', [userId]);
    await setEnabled(app, userId, true);

    expect(await notValidBefore(app, userId)).toBeNull();
    expect((await refresh(app, held.refreshToken)).statusCode).toBe(200);
    expect(await introspect(app, held.accessToken)).toBe(true);
    const { response } = await authorize(app, held.cookie);
    expect(new URL(response.headers['location'] as string).searchParams.get('code')).not.toBeNull();
  }, 60_000);
});
