import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  decodeHtmlEntities,
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
 * THE AUTHORIZATION CODE GRANT MINTS A REFRESH TOKEN ONLY FOR A CLIENT WHOSE
 * `grant_types` LIST `refresh_token` (issue #1078), end to end against real
 * Postgres and Redis.
 *
 * The `refresh_token` grant refuses any other client with
 * `unauthorized_client`, so a refresh token minted for it is a credential it
 * cannot use, and a family that waits in the database until it expires or the
 * consent is withdrawn. A covering stored consent alone is therefore not
 * enough: the client must also be registered for the grant. Both places that
 * mint codes are covered, the consent screen's POST with "Remember this
 * decision" ticked and the consent skip of `/oauth/authorize` that the stored
 * consent then allows.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const EMAIL = 'refresh-grant-owner@example.test';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

/** A confidential client registered for the code grant alone, as in the report. */
const CODE_ONLY_ID = 'code-only-web-app';
const CODE_ONLY_SECRET = 'code-only-web-app-secret-of-sufficient-length';
/** A public client registered for both grants. */
const REFRESHING_ID = 'refreshing-native-app';

/** How a test client authenticates at the token endpoint. */
const CREDENTIALS: Record<string, Record<string, string>> = {
  [CODE_ONLY_ID]: { client_id: CODE_ONLY_ID, client_secret: CODE_ONLY_SECRET },
  [REFRESHING_ID]: { client_id: REFRESHING_ID },
};

interface TokenResponse {
  readonly access_token?: string;
  readonly refresh_token?: string;
  readonly id_token?: string;
  readonly scope?: string;
}

describe('a refresh token only for a client with the refresh_token grant (#1078, real containers)', () => {
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

  /**
   * The two clients, with the same scopes and redirect URI, and a signed-in
   * user.
   *
   * @returns the browser session's cookie and the clients' row ids
   */
  async function setup(
    app: FastifyInstance
  ): Promise<{ cookie: string; userId: string; rowIds: Record<string, string> }> {
    const userId = await registerPasswordAccount(app, EMAIL);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    const codeOnly = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CODE_ONLY_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(CODE_ONLY_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Code-only web app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code'],
      enabled: true,
      requirePkce: true,
    });
    const refreshing = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: REFRESHING_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Refreshing native app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
    const jar = await signInWithPassword(app, EMAIL);
    return {
      cookie: jar.header() as string,
      userId,
      rowIds: { [CODE_ONLY_ID]: codeOnly.id, [REFRESHING_ID]: refreshing.id },
    };
  }

  /**
   * Run the authorization request of `clientId` for a fresh PKCE pair and
   * return the code. When the consent screen is shown, the user allows the
   * request with "Remember this decision" ticked, which stores the consent;
   * `expectScreen` says whether the screen is expected.
   */
  async function authorize(
    app: FastifyInstance,
    cookie: string,
    clientId: string,
    expectScreen: boolean
  ): Promise<{ code: string; verifier: string }> {
    const pkce = pkcePair();
    const authorizeResponse = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'refresh-grant-state',
      }).toString()}`,
      headers: { cookie },
    });
    expect(authorizeResponse.statusCode).toBe(302);
    let location = authorizeResponse.headers['location'] as string;

    expect(location.startsWith('/ui/consent?')).toBe(expectScreen);
    if (expectScreen) {
      const screen = await app.inject({ method: 'GET', url: location, headers: { cookie } });
      expect(screen.statusCode).toBe(200);
      const hidden = Object.fromEntries(
        [...screen.body.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)].map(
          ([, name, value]) => [name, decodeHtmlEntities(value)]
        )
      );
      const decision = await app.inject({
        method: 'POST',
        url: '/ui/consent',
        headers: { ...FORM, cookie },
        payload: new URLSearchParams({
          ...hidden,
          csrf_token: extractCsrfToken(screen.body),
          decision: 'allow',
          allow_forever: '1',
        }).toString(),
      });
      expect(decision.statusCode).toBe(302);
      location = decision.headers['location'] as string;
    }

    const code = new URL(location).searchParams.get('code');
    if (code === null) throw new Error(`no code in ${location}`);
    return { code, verifier: pkce.verifier };
  }

  /** Redeem `code` as `clientId`. */
  async function exchange(
    app: FastifyInstance,
    clientId: string,
    code: string,
    verifier: string
  ): Promise<TokenResponse> {
    const response = await tokenRequest(app, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      ...CREDENTIALS[clientId],
    });
    expect(response.statusCode).toBe(200);
    return response.json<TokenResponse>();
  }

  /** How many refresh tokens the client with row id `rowId` holds, revoked or not. */
  async function refreshRowsOf(app: FastifyInstance, rowId: string): Promise<number> {
    const { rows } = await app.dbPool.query<{ count: string }>(
      'SELECT count(*) AS count FROM refresh_tokens WHERE oauth_client_id = $1',
      [rowId]
    );
    return Number(rows[0].count);
  }

  /** How many active stored consents the user holds for the client with row id `rowId`. */
  async function activeConsentsOf(
    app: FastifyInstance,
    userId: string,
    rowId: string
  ): Promise<number> {
    const { rows } = await app.dbPool.query<{ count: string }>(
      `SELECT count(*) AS count FROM oauth_consents
        WHERE user_id = $1 AND oauth_client_id = $2 AND revoked_at IS NULL`,
      [userId, rowId]
    );
    return Number(rows[0].count);
  }

  it('gives a client without the refresh_token grant no refresh token under a remembered consent, and writes no refresh-token row', async () => {
    const app = server();
    const { cookie, userId, rowIds } = await setup(app);
    const rowId = rowIds[CODE_ONLY_ID];

    // The consent screen, answered with "Remember this decision".
    const first = await authorize(app, cookie, CODE_ONLY_ID, true);
    expect(await activeConsentsOf(app, userId, rowId)).toBe(1);
    const firstTokens = await exchange(app, CODE_ONLY_ID, first.code, first.verifier);
    expect(firstTokens.access_token).toEqual(expect.any(String));
    expect(firstTokens.id_token).toEqual(expect.any(String));
    expect(firstTokens).not.toHaveProperty('refresh_token');

    // The remembered consent skips the screen on the next request; the
    // exchange still mints no refresh token.
    const second = await authorize(app, cookie, CODE_ONLY_ID, false);
    const secondTokens = await exchange(app, CODE_ONLY_ID, second.code, second.verifier);
    expect(secondTokens.access_token).toEqual(expect.any(String));
    expect(secondTokens).not.toHaveProperty('refresh_token');

    expect(await refreshRowsOf(app, rowId)).toBe(0);
    // The consent stays as it was stored: the client simply cannot refresh.
    expect(await activeConsentsOf(app, userId, rowId)).toBe(1);
  });

  it('still gives a client with the refresh_token grant a refresh token under a remembered consent, which refreshes', async () => {
    const app = server();
    const { cookie, rowIds } = await setup(app);
    const rowId = rowIds[REFRESHING_ID];

    const first = await authorize(app, cookie, REFRESHING_ID, true);
    const firstTokens = await exchange(app, REFRESHING_ID, first.code, first.verifier);
    expect(firstTokens.refresh_token).toMatch(/^[0-9a-f]{64}$/);

    const second = await authorize(app, cookie, REFRESHING_ID, false);
    const secondTokens = await exchange(app, REFRESHING_ID, second.code, second.verifier);
    expect(secondTokens.refresh_token).toMatch(/^[0-9a-f]{64}$/);
    expect(await refreshRowsOf(app, rowId)).toBe(2);

    const refreshed = await tokenRequest(app, {
      grant_type: 'refresh_token',
      refresh_token: secondTokens.refresh_token as string,
      ...CREDENTIALS[REFRESHING_ID],
    });
    expect(refreshed.statusCode).toBe(200);
    expect(refreshed.json<TokenResponse>().refresh_token).toMatch(/^[0-9a-f]{64}$/);
  });
});
