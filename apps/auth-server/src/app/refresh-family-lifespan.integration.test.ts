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
 * A REALM'S `sso_max_lifespan` CAPS ITS REFRESH-TOKEN FAMILIES (ADR-019
 * Decision 3, issue #552), end to end against real Postgres and Redis.
 *
 * A family starts at the code exchange. With a limit set, no token of the
 * family expires after the family's start plus the limit, and a refresh at or
 * past that end revokes the whole family and answers `invalid_grant`. The
 * limit is read from the realm at each refresh, so lowering it ends an older
 * family at its next refresh. Without a limit every refresh slides the expiry
 * forward, as before.
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
const CLIENT_ID = 'family-native-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];

interface RefreshRow {
  readonly family_created_at: string;
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
   * Run the code flow for a public client with the user's stored consent, so
   * the exchange starts a refresh-token family.
   *
   * @returns the refresh token, its family and the family's start (epoch ms)
   */
  async function startFamily(
    app: FastifyInstance
  ): Promise<{ refreshToken: string; familyId: string; familyCreatedAt: number }> {
    const email = 'family-owner@example.test';
    const userId = await registerPasswordAccount(app, email);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    const client = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Family native app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
    await app.repositories.oauthConsents.upsertGrant(userId, client.id, realm.id, SCOPES);
    const jar = await signInWithPassword(app, email);
    const pkce = pkcePair();

    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'family-state',
      }).toString()}`,
      headers: { cookie: jar.header() as string },
    });
    expect(authorize.statusCode).toBe(302);
    const code = new URL(authorize.headers['location'] as string).searchParams.get('code');
    if (code === null)
      throw new Error(`authorize returned no code: ${authorize.headers['location']}`);

    const exchange = await tokenRequest(app, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: pkce.verifier,
    });
    expect(exchange.statusCode).toBe(200);
    const refreshToken = (exchange.json() as { refresh_token?: string }).refresh_token;
    if (refreshToken === undefined) throw new Error('the exchange issued no refresh token');

    const { rows } = await app.dbPool.query<{ family_id: string; family_created_at: string }>(
      'SELECT family_id, family_created_at FROM refresh_tokens'
    );
    expect(rows).toHaveLength(1);
    return {
      refreshToken,
      familyId: rows[0].family_id,
      familyCreatedAt: Number(rows[0].family_created_at),
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

  /** Refresh at `at` on the server's clock. */
  async function refreshAt(
    app: FastifyInstance,
    refreshToken: string,
    at: number
  ): Promise<LightMyRequestResponse> {
    vi.setSystemTime(at);
    return tokenRequest(app, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    });
  }

  async function familyRows(app: FastifyInstance, familyId: string): Promise<RefreshRow[]> {
    const { rows } = await app.dbPool.query<RefreshRow>(
      `SELECT family_created_at, expires_at, revoked, revoked_reason
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
    const familyEnd = family.familyCreatedAt + 60 * MINUTE;

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
    // The rotation copied the family's start and capped the new token there.
    expect(rows[1]).toEqual({
      family_created_at: String(family.familyCreatedAt),
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

  it('slides the expiry as before when the realm sets no sso_max_lifespan', async () => {
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
});
