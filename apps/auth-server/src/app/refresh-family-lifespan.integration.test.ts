import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
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

/**
 * A REALM'S `sso_max_lifespan` CAPS ITS REFRESH-TOKEN FAMILIES (ADR-019
 * Decision 3, issue #552), end to end against real Postgres and Redis.
 *
 * A family starts at the code exchange. With a limit set, no token of the
 * family expires after the family's start plus the limit, nor after the end of
 * the browser session that backed the code, and a refresh at or past that end
 * revokes the whole family and answers `invalid_grant`. A silent
 * re-authorization just before the session's end therefore starts a family
 * that ends with the session. The limit is read from the realm at each
 * refresh, so lowering it ends an older family at its next refresh. Without a
 * limit every refresh slides the expiry forward, as before, for a native app
 * or a confidential client. A browser-based client's family never slides
 * (RFC 10017 §6.3.2.3, #928): no rotated token expires after the family's
 * first.
 *
 * The suite moves the clock the server reads (`Date` only; timers stay real)
 * to reach minute 59 or 61 of a family without waiting.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const REFRESH_TOKEN_LIFESPAN_SECONDS = 604_800;
const SCOPES = ['openid', 'email'];

/** A client the suite runs the code flow for; a confidential one has a secret. */
interface FamilyClient {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly secret?: string;
}

/** A public native app: its one redirect URI is a private-use scheme's. */
const NATIVE_APP: FamilyClient = {
  clientId: 'family-native-app',
  redirectUri: 'com.example.family:/callback',
};
/** A public browser-based app: it calls back on an `https` URI (#928). */
const BROWSER_APP: FamilyClient = {
  clientId: 'family-browser-app',
  redirectUri: 'https://client.example.com/callback',
};
/** A confidential client on the browser app's redirect URI (#928). */
const CONFIDENTIAL_APP: FamilyClient = {
  clientId: 'family-web-server',
  redirectUri: 'https://client.example.com/callback',
  secret: 'family-web-server-secret',
};

interface RefreshRow {
  readonly family_created_at: string;
  readonly family_session_expires_at: string | null;
  readonly expires_at: string;
  readonly revoked: boolean;
  readonly revoked_reason: string | null;
}

describe('refresh-token families under the realm’s sso_max_lifespan (#552, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      REFRESH_TOKEN_LIFESPAN: String(REFRESH_TOKEN_LIFESPAN_SECONDS),
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
   * Set the realm's `sso_max_lifespan`, as an operator does in the database,
   * and drop the host cache so the next request reads the new row rather than
   * waiting out the cache time.
   */
  async function setRealmLimit(app: FastifyInstance, seconds: number | null): Promise<void> {
    await app.dbPool.query('UPDATE realms SET sso_max_lifespan = $1 WHERE name = $2', [
      seconds,
      E2E_REALM_NAME,
    ]);
    app.realmHostCache.clear();
  }

  /**
   * Run the code flow for a client, the public native app unless another is
   * named, with the user's stored consent, so the exchange starts a
   * refresh-token family.
   *
   * @returns the refresh token, its family and the family's start (epoch ms)
   */
  async function startFamily(
    app: FastifyInstance,
    familyClient: FamilyClient = NATIVE_APP
  ): Promise<{
    refreshToken: string;
    familyId: string;
    familyCreatedAt: number;
    sessionEnd: number;
    cookie: string;
  }> {
    const email = 'family-owner@example.test';
    const userId = await registerPasswordAccount(app, email);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    const client = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: familyClient.clientId,
      clientSecretHash:
        familyClient.secret === undefined
          ? 'unused-public-client'
          : await app.passwordHasher.hashPassword(familyClient.secret),
      tokenEndpointAuthMethod: familyClient.secret === undefined ? 'none' : 'client_secret_post',
      name: `Family app ${familyClient.clientId}`,
      redirectUris: [familyClient.redirectUri],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
    await app.repositories.oauthConsents.upsertGrant(realm.id, userId, client.id, SCOPES);
    const jar = await signInWithPassword(app, email);
    const cookie = jar.header() as string;
    const { refreshToken, familyId, familyCreatedAt, sessionEnd } = await codeFamily(
      app,
      cookie,
      {},
      familyClient
    );
    return { refreshToken, familyId, familyCreatedAt, sessionEnd, cookie };
  }

  /**
   * Authorize with the browser session's cookie and exchange the code: a new
   * refresh-token family. `prompt=none` makes it the silent re-authorization a
   * client runs to refresh a sign-in.
   *
   * @returns the family's refresh token, id and start, and the end of the
   *   browser session the code recorded
   */
  async function codeFamily(
    app: FastifyInstance,
    cookie: string,
    extra: Record<string, string> = {},
    familyClient: FamilyClient = NATIVE_APP
  ): Promise<{
    refreshToken: string;
    familyId: string;
    familyCreatedAt: number;
    sessionEnd: number;
  }> {
    const pkce = pkcePair();
    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: familyClient.clientId,
        redirect_uri: familyClient.redirectUri,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'family-state',
        ...extra,
      }).toString()}`,
      headers: { cookie },
    });
    expect(authorize.statusCode).toBe(302);
    const code = new URL(authorize.headers['location'] as string).searchParams.get('code');
    if (code === null)
      throw new Error(`authorize returned no code: ${authorize.headers['location']}`);

    const exchange = await tokenRequest(app, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: familyClient.redirectUri,
      code_verifier: pkce.verifier,
      ...credentialsOf(familyClient),
    });
    expect(exchange.statusCode).toBe(200);
    const refreshToken = (exchange.json() as { refresh_token?: string }).refresh_token;
    if (refreshToken === undefined) throw new Error('the exchange issued no refresh token');

    const {
      rows: [row],
    } = await app.dbPool.query<{
      family_id: string;
      family_created_at: string;
      family_session_expires_at: string | null;
    }>(
      `SELECT family_id, family_created_at, family_session_expires_at FROM refresh_tokens
       WHERE previous_token_hash IS NULL ORDER BY created_at DESC, id DESC LIMIT 1`
    );
    if (row.family_session_expires_at === null) throw new Error('the family has no session end');
    return {
      refreshToken,
      familyId: row.family_id,
      familyCreatedAt: Number(row.family_created_at),
      sessionEnd: Number(row.family_session_expires_at),
    };
  }

  function tokenRequest(
    app: FastifyInstance,
    form: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams(form).toString(),
    });
  }

  /** The client's own token request fields: its id, and its secret if it has one. */
  function credentialsOf(familyClient: FamilyClient): Record<string, string> {
    return familyClient.secret === undefined
      ? { client_id: familyClient.clientId }
      : { client_id: familyClient.clientId, client_secret: familyClient.secret };
  }

  /** Refresh at `at` on the server's clock, as the native app unless another is named. */
  async function refreshAt(
    app: FastifyInstance,
    refreshToken: string,
    at: number,
    familyClient: FamilyClient = NATIVE_APP
  ): Promise<LightMyRequestResponse> {
    vi.setSystemTime(at);
    return tokenRequest(app, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      ...credentialsOf(familyClient),
    });
  }

  async function familyRows(app: FastifyInstance, familyId: string): Promise<RefreshRow[]> {
    const { rows } = await app.dbPool.query<RefreshRow>(
      `SELECT family_created_at, family_session_expires_at, expires_at, revoked, revoked_reason
       FROM refresh_tokens WHERE family_id = $1 ORDER BY created_at, id`,
      [familyId]
    );
    return rows;
  }

  async function tokenFailureReasons(app: FastifyInstance): Promise<unknown[]> {
    const { rows } = await app.dbPool.query<{ data: { reason?: string } }>(
      `SELECT data FROM events WHERE type = 'urn:qauth:event:token.request_failed:v1-rc.0' ORDER BY seq`
    );
    return rows.map((row) => row.data.reason);
  }

  it('refreshes at minute 59 of a one-hour family, and the new token expires by minute 60', async () => {
    const app = server();
    await setRealmLimit(app, 3600);
    const family = await startFamily(app);
    // The session began a moment before the exchange, under the same limit,
    // so its end is the family's end.
    const familyEnd = Math.min(family.familyCreatedAt + 60 * MINUTE, family.sessionEnd);
    expect(family.familyCreatedAt + 60 * MINUTE - familyEnd).toBeLessThan(MINUTE);

    // The exchange's own token already ends with the family.
    expect(await familyRows(app, family.familyId)).toEqual([
      expect.objectContaining({ expires_at: String(familyEnd), revoked: false }),
    ]);

    const refreshed = await refreshAt(
      app,
      family.refreshToken,
      family.familyCreatedAt + 59 * MINUTE
    );
    expect(refreshed.statusCode).toBe(200);
    expect(refreshed.json()).toHaveProperty('refresh_token');

    const rows = await familyRows(app, family.familyId);
    expect(rows).toHaveLength(2);
    // The rotation copied the family's start and session end, and capped the
    // new token there.
    expect(rows[1]).toEqual({
      family_created_at: String(family.familyCreatedAt),
      family_session_expires_at: String(family.sessionEnd),
      expires_at: String(familyEnd),
      revoked: false,
      revoked_reason: null,
    });
    expect(Number(rows[1].expires_at)).toBeLessThanOrEqual(familyEnd);
  });

  it('answers invalid_grant at minute 61 and revokes the whole family', async () => {
    const app = server();
    await setRealmLimit(app, 3600);
    const family = await startFamily(app);

    const atThirty = await refreshAt(
      app,
      family.refreshToken,
      family.familyCreatedAt + 30 * MINUTE
    );
    expect(atThirty.statusCode).toBe(200);
    const current = (atThirty.json() as { refresh_token: string }).refresh_token;

    const atSixtyOne = await refreshAt(app, current, family.familyCreatedAt + 61 * MINUTE);
    expect(atSixtyOne.statusCode).toBe(400);
    expect(atSixtyOne.json()).toMatchObject({ error: 'invalid_grant' });
    expect(atSixtyOne.json()).not.toHaveProperty('refresh_token');

    // Every token of the family is revoked: the one rotated at minute 30
    // keeps its reason, and the live one names the family's end.
    expect(await familyRows(app, family.familyId)).toEqual([
      expect.objectContaining({ revoked: true, revoked_reason: 'rotated' }),
      expect.objectContaining({ revoked: true, revoked_reason: 'family_expired' }),
    ]);
    expect(await tokenFailureReasons(app)).toEqual(['refresh_family_expired']);
  });

  it('slides the expiry as before for a native app when the realm sets no sso_max_lifespan', async () => {
    const app = server();
    await setRealmLimit(app, null);
    const family = await startFamily(app);
    const lifespanMs = REFRESH_TOKEN_LIFESPAN_SECONDS * 1000;
    expect(await familyRows(app, family.familyId)).toEqual([
      expect.objectContaining({ expires_at: String(family.familyCreatedAt + lifespanMs) }),
    ]);

    // Each refresh gives a whole lifespan from its own time, so the family
    // outlives the lifespan of its first token.
    const sixDays = family.familyCreatedAt + 6 * DAY;
    const first = await refreshAt(app, family.refreshToken, sixDays);
    expect(first.statusCode).toBe(200);
    const twelveDays = family.familyCreatedAt + 12 * DAY;
    const second = await refreshAt(
      app,
      (first.json() as { refresh_token: string }).refresh_token,
      twelveDays
    );
    expect(second.statusCode).toBe(200);

    const rows = await familyRows(app, family.familyId);
    expect(rows.map((row) => Number(row.expires_at))).toEqual([
      family.familyCreatedAt + lifespanMs,
      sixDays + lifespanMs,
      twelveDays + lifespanMs,
    ]);
    expect(rows.every((row) => row.family_created_at === String(family.familyCreatedAt))).toBe(
      true
    );
  });

  it('ends an older family at its next refresh once the realm lowers sso_max_lifespan', async () => {
    const app = server();
    await setRealmLimit(app, null);
    const family = await startFamily(app);

    // Ninety minutes in, with no limit: the refresh succeeds and the new
    // token is good for a week.
    const atNinety = await refreshAt(
      app,
      family.refreshToken,
      family.familyCreatedAt + 90 * MINUTE
    );
    expect(atNinety.statusCode).toBe(200);
    const current = (atNinety.json() as { refresh_token: string }).refresh_token;

    // The operator lowers the limit to one hour. The live token's own expiry
    // is days away, but the family is two hours old at its next refresh.
    await setRealmLimit(app, 3600);
    const next = await refreshAt(app, current, family.familyCreatedAt + 120 * MINUTE);
    expect(next.statusCode).toBe(400);
    expect(next.json()).toMatchObject({ error: 'invalid_grant' });

    const rows = await familyRows(app, family.familyId);
    expect(Number(rows[1].expires_at)).toBeGreaterThan(family.familyCreatedAt + DAY);
    expect(rows).toEqual([
      expect.objectContaining({ revoked: true, revoked_reason: 'rotated' }),
      expect.objectContaining({ revoked: true, revoked_reason: 'family_expired' }),
    ]);
  });
  it("ends a family started one minute before its session's end with that session", async () => {
    const app = server();
    await setRealmLimit(app, 3600);
    const first = await startFamily(app);

    // One minute before the session's end the client re-authorizes silently.
    // The family it starts ends with the session, not an hour later.
    vi.setSystemTime(first.sessionEnd - MINUTE);
    const late = await codeFamily(app, first.cookie, { prompt: 'none' });
    expect(late.familyId).not.toBe(first.familyId);
    expect(late.sessionEnd).toBe(first.sessionEnd);
    expect(await familyRows(app, late.familyId)).toEqual([
      expect.objectContaining({
        family_created_at: String(first.sessionEnd - MINUTE),
        family_session_expires_at: String(first.sessionEnd),
        expires_at: String(first.sessionEnd),
      }),
    ]);

    // Thirty seconds before the end it still rotates, capped at the end.
    const atHalf = await refreshAt(app, late.refreshToken, first.sessionEnd - MINUTE / 2);
    expect(atHalf.statusCode).toBe(200);
    const current = (atHalf.json() as { refresh_token: string }).refresh_token;
    expect((await familyRows(app, late.familyId))[1]).toMatchObject({
      expires_at: String(first.sessionEnd),
    });

    // Past the session's end the family is over, however young it is.
    const after = await refreshAt(app, current, first.sessionEnd + 1000);
    expect(after.statusCode).toBe(400);
    expect(after.json()).toMatchObject({ error: 'invalid_grant' });
    expect(await familyRows(app, late.familyId)).toEqual([
      expect.objectContaining({ revoked: true, revoked_reason: 'rotated' }),
      expect.objectContaining({ revoked: true, revoked_reason: 'family_expired' }),
    ]);
    expect(await tokenFailureReasons(app)).toEqual(['refresh_family_expired']);
  });

  it('caps a /auth/login family at its start plus the limit, with no session end', async () => {
    const app = server();
    await setRealmLimit(app, 3600);
    const email = 'first-party@example.test';
    await registerPasswordAccount(app, email);

    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(login.statusCode).toBe(200);

    const { rows } = await app.dbPool.query<RefreshRow>(
      `SELECT family_created_at, family_session_expires_at, expires_at, revoked, revoked_reason
       FROM refresh_tokens`
    );
    expect(rows).toEqual([
      {
        family_created_at: rows[0].family_created_at,
        family_session_expires_at: null,
        expires_at: String(Number(rows[0].family_created_at) + 60 * MINUTE),
        revoked: false,
        revoked_reason: null,
      },
    ]);
  });

  describe('a browser-based client’s family ends with its first token (RFC 10017 §6.3.2.3, #928)', () => {
    const lifespanMs = REFRESH_TOKEN_LIFESPAN_SECONDS * 1000;

    /**
     * Refresh the family on days 2, 4 and 6 of its first token's week, each
     * time with the token the previous refresh issued.
     *
     * @returns the last token issued
     */
    async function refreshEveryOtherDay(
      app: FastifyInstance,
      family: { refreshToken: string; familyCreatedAt: number },
      familyClient: FamilyClient
    ): Promise<string> {
      let current = family.refreshToken;
      for (const day of [2, 4, 6]) {
        const refreshed = await refreshAt(
          app,
          current,
          family.familyCreatedAt + day * DAY,
          familyClient
        );
        expect(refreshed.statusCode, refreshed.body).toBe(200);
        current = (refreshed.json() as { refresh_token: string }).refresh_token;
      }
      return current;
    }

    it("gives no rotated token of a public browser app a later expiry than the family's first", async () => {
      const app = server();
      await setRealmLimit(app, null);
      const family = await startFamily(app, BROWSER_APP);
      const firstExpiry = family.familyCreatedAt + lifespanMs;

      // Each refresh would slide a week from its own time; with no realm
      // limit, every token of the family keeps the first one's expiry.
      const current = await refreshEveryOtherDay(app, family, BROWSER_APP);
      const rows = await familyRows(app, family.familyId);
      expect(rows.map((row) => Number(row.expires_at))).toEqual([
        firstExpiry,
        firstExpiry,
        firstExpiry,
        firstExpiry,
      ]);
      expect(rows.every((row) => row.family_created_at === String(family.familyCreatedAt))).toBe(
        true
      );

      // At the first token's expiry the family is over.
      const late = await refreshAt(app, current, firstExpiry, BROWSER_APP);
      expect(late.statusCode).toBe(400);
      expect(late.json()).toMatchObject({ error: 'invalid_grant' });
      expect(await tokenFailureReasons(app)).toEqual(['refresh_token_expired']);
    });

    it('slides the expiry as before for a confidential client on the same redirect URI', async () => {
      const app = server();
      await setRealmLimit(app, null);
      const family = await startFamily(app, CONFIDENTIAL_APP);

      await refreshEveryOtherDay(app, family, CONFIDENTIAL_APP);
      const rows = await familyRows(app, family.familyId);
      expect(rows.map((row) => Number(row.expires_at))).toEqual([
        family.familyCreatedAt + lifespanMs,
        family.familyCreatedAt + 2 * DAY + lifespanMs,
        family.familyCreatedAt + 4 * DAY + lifespanMs,
        family.familyCreatedAt + 6 * DAY + lifespanMs,
      ]);
    });
  });
});
