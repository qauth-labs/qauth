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
 * A SECOND REDEMPTION OF AN AUTHORIZATION CODE REVOKES THE REFRESH FAMILY THE
 * FIRST ONE STARTED (ADR-017 Decision 10, issue #627), end to end against real
 * Postgres and Redis.
 *
 * OAuth 2.1 §4.1.3: the server "MUST deny the request and SHOULD revoke (when
 * possible) all access tokens and refresh tokens previously issued based on
 * that authorization code". The replay answers `invalid_grant`, every token of
 * the family, rotations included, is revoked, and the client's refresh token
 * stops working. A replay that is not itself a valid request, here one with
 * the wrong PKCE verifier, revokes nothing (OAuth 2.1 §7.5.3).
 *
 * Both places that mint codes are covered: the consent-skip path of
 * `/oauth/authorize` and the consent screen's POST.
 *
 * A browser code presented without `redirect_uri` answers `invalid_grant`, no
 * longer a schema validation error, and the code stays redeemable.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const CLIENT_ID = 'replay-native-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const EMAIL = 'replay-owner@example.test';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

type MintPath = 'consent skip' | 'consent screen';

interface RefreshRow {
  readonly revoked: boolean;
  readonly revoked_reason: string | null;
  readonly authorization_code_id: string | null;
}

describe('authorization code replay revokes its refresh family (#627, real containers)', () => {
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
   * A public client and a signed-in user. On the consent-skip path the user
   * has already granted the client its scopes; on the consent-screen path the
   * user grants them on the screen.
   *
   * @returns the browser session's cookie
   */
  async function signedInUser(app: FastifyInstance, path: MintPath): Promise<string> {
    const userId = await registerPasswordAccount(app, EMAIL);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    const client = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Replay native app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
    if (path === 'consent skip') {
      await app.repositories.oauthConsents.upsertGrant(userId, client.id, realm.id, SCOPES);
    }
    const jar = await signInWithPassword(app, EMAIL);
    return jar.header() as string;
  }

  /**
   * Run the authorization request for a fresh PKCE pair and return the code.
   * On the consent-screen path the user allows the request and asks for the
   * decision to be remembered, so the exchange starts a refresh family.
   */
  async function authorize(
    app: FastifyInstance,
    cookie: string,
    path: MintPath
  ): Promise<{ code: string; verifier: string }> {
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
        state: 'replay-state',
      }).toString()}`,
      headers: { cookie },
    });
    expect(authorizeResponse.statusCode).toBe(302);
    let location = authorizeResponse.headers['location'] as string;

    if (path === 'consent screen') {
      expect(location.startsWith('/ui/consent?')).toBe(true);
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

  function exchange(
    app: FastifyInstance,
    code: string,
    verifier: string,
    extra: Record<string, string> = { redirect_uri: REDIRECT_URI }
  ): Promise<LightMyRequestResponse> {
    return tokenRequest(app, {
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      code_verifier: verifier,
      ...extra,
    });
  }

  function refresh(app: FastifyInstance, refreshToken: string): Promise<LightMyRequestResponse> {
    return tokenRequest(app, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    });
  }

  async function familyOf(app: FastifyInstance, code: string): Promise<RefreshRow[]> {
    const { rows } = await app.dbPool.query<RefreshRow>(
      `SELECT t.revoked, t.revoked_reason, t.authorization_code_id
       FROM refresh_tokens t
       WHERE t.family_id = (
         SELECT f.family_id FROM refresh_tokens f
         JOIN authorization_codes c ON c.id = f.authorization_code_id
         WHERE c.code = $1)
       ORDER BY t.created_at, t.id`,
      [code]
    );
    return rows;
  }

  async function tokenFailureReasons(app: FastifyInstance): Promise<unknown[]> {
    const { rows } = await app.dbPool.query<{ data: { reason?: string } }>(
      `SELECT data FROM events WHERE type = 'urn:qauth:event:token.request_failed:v1-rc.0' ORDER BY seq`
    );
    return rows.map((row) => row.data.reason);
  }

  it.each<MintPath>(['consent skip', 'consent screen'])(
    'a replayed code minted on the %s path answers invalid_grant and revokes the family, rotations included',
    async (path) => {
      const app = server();
      const cookie = await signedInUser(app, path);
      const { code, verifier } = await authorize(app, cookie, path);

      const first = await exchange(app, code, verifier);
      expect(first.statusCode).toBe(200);
      const issued = first.json() as { refresh_token?: string };
      if (issued.refresh_token === undefined)
        throw new Error('the exchange issued no refresh token');
      // One rotation, so the family has a token the code row does not name.
      const rotated = await refresh(app, issued.refresh_token);
      expect(rotated.statusCode).toBe(200);
      const latest = (rotated.json() as { refresh_token: string }).refresh_token;

      const replay = await exchange(app, code, verifier);

      expect(replay.statusCode).toBe(400);
      expect(replay.json()).toMatchObject({ error: 'invalid_grant' });
      expect(replay.headers['cache-control']).toBe('no-store');
      const family = await familyOf(app, code);
      expect(family).toHaveLength(2);
      // The exchange's token names the code; its rotation was already
      // revoked as `rotated` and keeps that reason. The live child is revoked
      // by the replay.
      expect(family[0]).toMatchObject({ revoked: true, revoked_reason: 'rotated' });
      expect(family[0].authorization_code_id).not.toBeNull();
      expect(family[1]).toMatchObject({
        revoked: true,
        revoked_reason: 'code_replay',
        authorization_code_id: null,
      });
      expect(await tokenFailureReasons(app)).toEqual(['code_replay']);

      // The client's refresh token is dead from now on.
      const afterwards = await refresh(app, latest);
      expect(afterwards.statusCode).toBe(400);
      expect(afterwards.json()).toMatchObject({ error: 'invalid_grant' });
    },
    60_000
  );

  it('a replay with the wrong PKCE verifier is refused and revokes nothing (OAuth 2.1 §7.5.3)', async () => {
    const app = server();
    const cookie = await signedInUser(app, 'consent skip');
    const { code, verifier } = await authorize(app, cookie, 'consent skip');
    const first = await exchange(app, code, verifier);
    expect(first.statusCode).toBe(200);
    const refreshToken = (first.json() as { refresh_token: string }).refresh_token;

    const replay = await exchange(app, code, pkcePair().verifier);

    expect(replay.statusCode).toBe(400);
    expect(replay.json()).toMatchObject({ error: 'invalid_grant' });
    expect((await familyOf(app, code)).map((row) => row.revoked)).toEqual([false]);
    expect(await tokenFailureReasons(app)).toEqual(['pkce_mismatch']);
    expect((await refresh(app, refreshToken)).statusCode).toBe(200);
  }, 60_000);

  it.each([
    ['without redirect_uri', {}],
    ['with an empty redirect_uri', { redirect_uri: '' }],
  ])(
    'a browser code presented %s answers invalid_grant, not a validation error, and stays redeemable',
    async (_label, extra) => {
      const app = server();
      const cookie = await signedInUser(app, 'consent skip');
      const { code, verifier } = await authorize(app, cookie, 'consent skip');

      const missing = await exchange(app, code, verifier, extra);

      expect(missing.statusCode).toBe(400);
      expect(missing.json()).toMatchObject({ error: 'invalid_grant' });
      expect(await tokenFailureReasons(app)).toEqual(['redirect_uri_missing']);
      // Refused before the code is spent: the client can still redeem it.
      const redeemed = await exchange(app, code, verifier);
      expect(redeemed.statusCode).toBe(200);
    },
    60_000
  );

  it('a different redirect_uri still answers invalid_grant', async () => {
    const app = server();
    const cookie = await signedInUser(app, 'consent skip');
    const { code, verifier } = await authorize(app, cookie, 'consent skip');

    const other = await exchange(app, code, verifier, {
      redirect_uri: 'https://client.example.com/other',
    });

    expect(other.statusCode).toBe(400);
    expect(other.json()).toMatchObject({ error: 'invalid_grant' });
    expect(await tokenFailureReasons(app)).toEqual(['redirect_uri_mismatch']);
  }, 60_000);
});
