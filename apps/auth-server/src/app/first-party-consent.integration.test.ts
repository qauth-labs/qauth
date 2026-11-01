import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * ADMINISTRATIVE CONSENT FOR OPERATOR-FLAGGED FIRST-PARTY CLIENTS, AND A
 * FRESH LOGIN FOR NATIVE PROFILES (ADR-017 Decision 9, issue #633), end to end
 * against real Postgres and Redis.
 *
 * - A `web_redirect` client (the portal's profile) asking for scopes none of
 *   which is dangerous gets a code with no consent screen, no `oauth_consents`
 *   row, and one `consent.administrative` event.
 * - A dangerous scope and `prompt=consent` still show the consent screen.
 * - A `native_backend` client's request is `prompt=login` whatever it says:
 *   with a live session and no `prompt` it meets the login page, and with
 *   `prompt=none` it gets `login_required`.
 * - The same request from a client without a profile still shows the screen.
 *
 * The profiles are written as an operator writes them, past the repository,
 * which never stores one (#631); the database CHECKs hold either way.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const MINUTE = 60_000;
const EMAIL = 'first-party-user@example.test';
const PORTAL_ID = 'portal';
const NATIVE_ID = 'notes-backend';
const PLAIN_ID = 'notes-app';
const PORTAL_CALLBACK = 'https://portal.example.com/auth/callback';
const NATIVE_CALLBACK = 'https://notes.example.com/app/callback';
const PLAIN_CALLBACK = 'https://client.example.com/callback';
const ADMINISTRATIVE = 'urn:qauth:event:consent.administrative:v1-rc.0';
/** A public key the clients authenticate with; no test here reaches the token endpoint. */
const CLIENT_JWKS = {
  keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
};

describe('administrative consent and the native fresh login (#633, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      // One test signs the same account in twice from one address.
      LOGIN_RATE_LIMIT: '100',
    });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
    delete process.env['LOGIN_RATE_LIMIT'];
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    await resetE2eState(booted.app);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /**
   * A signed-in user and three operator-provisioned clients with the same
   * scopes, one of them dangerous: the portal (`web_redirect`), a native
   * app's backend (`native_backend`) and a client with no profile.
   *
   * @returns the user's id and the browser session's cookie
   */
  async function signedInUser(app: FastifyInstance): Promise<{ userId: string; cookie: string }> {
    const userId = await registerPasswordAccount(app, EMAIL);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    for (const [clientId, name, redirectUri, authMethod] of [
      [PORTAL_ID, 'Developer Portal', PORTAL_CALLBACK, 'private_key_jwt'],
      [NATIVE_ID, 'Notes', NATIVE_CALLBACK, 'private_key_jwt'],
      [PLAIN_ID, 'Notes App', PLAIN_CALLBACK, 'none'],
    ] as const) {
      await app.repositories.oauthClients.create({
        realmId: realm.id,
        clientId,
        clientSecretHash: 'unused',
        tokenEndpointAuthMethod: authMethod,
        ...(authMethod === 'private_key_jwt' ? { jwks: CLIENT_JWKS } : {}),
        name,
        redirectUris: [redirectUri],
        scopes: ['openid', 'email', 'write:notes'],
        grantTypes: ['authorization_code', 'refresh_token'],
        enabled: true,
        requirePkce: true,
        // A seeded client: its redirect URI receives authorization errors.
        provisionedByOperator: true,
      });
    }
    // The operator flags two of them (ADR-017 Decision 2), as the seed
    // manifest does: the repository never writes a profile.
    await app.dbPool.query(
      `UPDATE oauth_clients
          SET first_party_profile = 'web_redirect', first_party_reason = 'The developer portal.'
        WHERE client_id = $1`,
      [PORTAL_ID]
    );
    await app.dbPool.query(
      `UPDATE oauth_clients
          SET first_party_profile = 'native_backend', first_party_reason = 'The notes app.',
              first_party_policy = '{"flows":["login"],"email_code_after_password":false,"pkce_required":true}'
        WHERE client_id = $1`,
      [NATIVE_ID]
    );
    const jar = await signInWithPassword(app, EMAIL);
    return { userId, cookie: jar.header() as string };
  }

  const CALLBACKS: Record<string, string> = {
    [PORTAL_ID]: PORTAL_CALLBACK,
    [NATIVE_ID]: NATIVE_CALLBACK,
    [PLAIN_ID]: PLAIN_CALLBACK,
  };

  /** `/oauth/authorize` for `clientId` with the browser session's cookie. */
  function authorize(
    app: FastifyInstance,
    cookie: string,
    clientId: string,
    extra: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: CALLBACKS[clientId],
        scope: 'openid email',
        code_challenge: pkcePair().challenge,
        code_challenge_method: 'S256',
        state: 'fp-state',
        ...extra,
      }).toString()}`,
      headers: { cookie },
    });
  }

  function location(response: LightMyRequestResponse): string {
    expect(response.statusCode).toBe(302);
    return response.headers['location'] as string;
  }

  async function administrativeEvents(
    app: FastifyInstance
  ): Promise<{ data: unknown; client_id: string; subject_id: string }[]> {
    const { rows } = await app.dbPool.query<{
      data: unknown;
      client_id: string;
      subject_id: string;
    }>('SELECT data, client_id, subject_id FROM events WHERE type = $1 ORDER BY seq', [
      ADMINISTRATIVE,
    ]);
    return rows;
  }

  async function count(app: FastifyInstance, sql: string, params: unknown[]): Promise<number> {
    const { rows } = await app.dbPool.query<{ count: string }>(sql, params);
    return Number(rows[0].count);
  }

  function codesOf(app: FastifyInstance, clientId: string): Promise<number> {
    return count(
      app,
      `SELECT count(*) AS count FROM authorization_codes c
         JOIN oauth_clients o ON o.id = c.oauth_client_id WHERE o.client_id = $1`,
      [clientId]
    );
  }

  /** Follow a redirect to the consent screen and check that it renders. */
  async function expectConsentScreen(
    app: FastifyInstance,
    cookie: string,
    response: LightMyRequestResponse
  ): Promise<void> {
    const target = location(response);
    expect(target.startsWith('/ui/consent?')).toBe(true);
    const screen = await app.inject({ method: 'GET', url: target, headers: { cookie } });
    expect(screen.statusCode).toBe(200);
    expect(screen.body).toContain('name="decision"');
  }

  it('gives a web_redirect client a code with no consent screen, no consent row and one administrative event', async () => {
    const app = server();
    const { userId, cookie } = await signedInUser(app);

    const target = new URL(location(await authorize(app, cookie, PORTAL_ID)));
    expect(`${target.origin}${target.pathname}`).toBe(PORTAL_CALLBACK);
    expect(target.searchParams.get('code')).toMatch(/.+/);
    expect(target.searchParams.get('state')).toBe('fp-state');
    expect(target.searchParams.get('error')).toBeNull();
    expect(await codesOf(app, PORTAL_ID)).toBe(1);

    expect(await administrativeEvents(app)).toEqual([
      {
        data: { basis: 'web_redirect', scopes: ['openid', 'email'], path: '/oauth/authorize' },
        client_id: PORTAL_ID,
        subject_id: userId,
      },
    ]);
    // No stored consent: the waiver writes no oauth_consents row.
    expect(
      await count(app, 'SELECT count(*) AS count FROM oauth_consents WHERE user_id = $1', [userId])
    ).toBe(0);
  });

  it('audits every waiver: a second request is a second event, and still no consent row', async () => {
    const app = server();
    const { userId, cookie } = await signedInUser(app);
    for (let i = 0; i < 2; i++) {
      expect(
        new URL(location(await authorize(app, cookie, PORTAL_ID))).searchParams.has('code')
      ).toBe(true);
    }
    expect(await administrativeEvents(app)).toHaveLength(2);
    expect(
      await count(app, 'SELECT count(*) AS count FROM oauth_consents WHERE user_id = $1', [userId])
    ).toBe(0);
  });

  it('shows the consent screen for a dangerous scope', async () => {
    const app = server();
    const { cookie } = await signedInUser(app);

    // The session is seconds old, so the dangerous scope's fresh login is met
    // and the request goes on to the screen.
    await expectConsentScreen(
      app,
      cookie,
      await authorize(app, cookie, PORTAL_ID, { scope: 'openid write:notes' })
    );
    expect(await codesOf(app, PORTAL_ID)).toBe(0);
    expect(await administrativeEvents(app)).toEqual([]);
  });

  it('shows the consent screen under prompt=consent', async () => {
    const app = server();
    const { cookie } = await signedInUser(app);

    await expectConsentScreen(
      app,
      cookie,
      await authorize(app, cookie, PORTAL_ID, { prompt: 'consent' })
    );
    expect(await codesOf(app, PORTAL_ID)).toBe(0);
    expect(await administrativeEvents(app)).toEqual([]);
  });

  it('sends a native_backend client with a live session and no prompt to the login page', async () => {
    const app = server();
    const { cookie } = await signedInUser(app);
    // The session stays live, but its sign-in is older than the fresh-login
    // window: what a native app's browser leg meets when the browser already
    // holds a QAuth session.
    vi.setSystemTime(Date.now() + 3 * MINUTE);

    const toLogin = location(await authorize(app, cookie, NATIVE_ID));
    expect(toLogin.startsWith('/ui/login?return_to=')).toBe(true);
    const page = await app.inject({ method: 'GET', url: toLogin, headers: { cookie } });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('name="password"');
    expect(await codesOf(app, NATIVE_ID)).toBe(0);

    // The same request from the portal is served from the same session: the
    // fresh login is the native profile's alone.
    expect(
      new URL(location(await authorize(app, cookie, PORTAL_ID))).searchParams.has('code')
    ).toBe(true);

    // A visible login, and the native leg completes under the waiver.
    const fresh = (await signInWithPassword(app, EMAIL)).header() as string;
    const done = new URL(location(await authorize(app, fresh, NATIVE_ID)));
    expect(`${done.origin}${done.pathname}`).toBe(NATIVE_CALLBACK);
    expect(done.searchParams.get('code')).toMatch(/.+/);
    expect(await codesOf(app, NATIVE_ID)).toBe(1);
    expect((await administrativeEvents(app)).map(({ data }) => data)).toEqual([
      { basis: 'web_redirect', scopes: ['openid', 'email'], path: '/oauth/authorize' },
      { basis: 'native_backend', scopes: ['openid', 'email'], path: '/oauth/authorize' },
    ]);
  });

  it('shows a native_backend client the consent screen under prompt=consent, on a fresh sign-in', async () => {
    const app = server();
    const { cookie } = await signedInUser(app);

    // The sign-in is seconds old, so the forced login is met; prompt=consent
    // is the request's own and still asks for the screen.
    await expectConsentScreen(
      app,
      cookie,
      await authorize(app, cookie, NATIVE_ID, { prompt: 'consent' })
    );
    expect(await codesOf(app, NATIVE_ID)).toBe(0);
    expect(await administrativeEvents(app)).toEqual([]);
  });

  it('answers a native_backend client with login_required under prompt=none, however fresh the session', async () => {
    const app = server();
    const { cookie } = await signedInUser(app);

    // The session is seconds old: a client without the profile would get a
    // code here.
    const target = new URL(location(await authorize(app, cookie, NATIVE_ID, { prompt: 'none' })));
    expect(`${target.origin}${target.pathname}`).toBe(NATIVE_CALLBACK);
    expect(target.searchParams.get('error')).toBe('login_required');
    expect(target.searchParams.get('state')).toBe('fp-state');
    expect(target.searchParams.get('iss')).toMatch(/^https?:\/\//);
    expect(target.searchParams.get('code')).toBeNull();
    expect(await codesOf(app, NATIVE_ID)).toBe(0);
    expect(await administrativeEvents(app)).toEqual([]);
  });

  it('leaves a client without a profile to the stored consent: the screen, then the skip once remembered', async () => {
    const app = server();
    const { userId, cookie } = await signedInUser(app);

    await expectConsentScreen(app, cookie, await authorize(app, cookie, PLAIN_ID));
    expect(await codesOf(app, PLAIN_ID)).toBe(0);

    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    const client = await app.repositories.oauthClients.findByClientId(realm.id, PLAIN_ID);
    if (!client) throw new Error('client missing');
    await app.repositories.oauthConsents.upsertGrant(realm.id, userId, client.id, [
      'openid',
      'email',
    ]);
    expect(new URL(location(await authorize(app, cookie, PLAIN_ID))).searchParams.has('code')).toBe(
      true
    );
    expect(await administrativeEvents(app)).toEqual([]);
  });
});
