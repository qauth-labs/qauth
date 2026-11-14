import { randomBytes, randomUUID } from 'node:crypto';

import {
  createFixtureNetwork,
  type EgressTransport,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/fastify-plugin-ssf/src/testing/egress-network';
import * as contract from '@qauth-labs/shared-account-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { createLocalJWKSet, type JSONWebKeySet, jwtVerify } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  registerPasswordAccount,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE ACCOUNT API'S SESSIONS (#1110; ADR-017 Decision 8, ADR-019 Decisions 3
 * and 7, ADR-020 §3), against a real Postgres and Redis, with
 * INTERACTION_UI_ENABLED on so a session's cookie can be tried on the hosted
 * account page. One case per acceptance criterion:
 *
 * - the list shows the user's live sessions, most recently used first, and
 *   marks the one the token came through (its `sid`);
 * - ending one session makes its cookie useless, ends the refresh families
 *   its sign-in opened, and sends one back-channel logout per app it signed
 *   in to with a back-channel logout URI;
 * - signing out everywhere ends every session, revokes every refresh family
 *   and sends the back-channel logouts, keeping the token's own session only
 *   when asked;
 * - another user's session answers `not_found`, untouched.
 *
 * The relying parties' back-channel logout URIs are local HTTPS receivers
 * behind the egress client's network edges, as the hosted account page suite
 * has them. Tokens are minted as the code exchange mints the account API's,
 * for the account console's backend.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const network = vi.hoisted(() => ({ current: undefined as EgressTransport | undefined }));

vi.mock('../../../../libs/server/egress/src/lib/transport', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const current = (): EgressTransport => {
    if (network.current === undefined) throw new Error('no fixture network');
    return network.current;
  };
  return {
    ...actual,
    NODE_TRANSPORT: {
      resolveHost: (...args: Parameters<EgressTransport['resolveHost']>) =>
        current().resolveHost(...args),
      exchange: (...args: Parameters<EgressTransport['exchange']>) => current().exchange(...args),
    },
  };
});

const ORIGIN = 'https://auth.example.com';
const ACCOUNT_AUDIENCE = contract.ACCOUNT_API_AUDIENCE;
const PREFIX = contract.ACCOUNT_API_PREFIX;
const CONSOLE_ID = 'account-console';
const ACCOUNT_PAGE = '/ui/account';
/** A public address the fixture DNS hands out; a local server stands for it. */
const RECEIVER_ADDRESS = '93.184.215.14';
const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
const FIREFOX_ON_LINUX = 'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0';
const SAFARI_ON_IPHONE =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';

/** A browser signed in to an account: its session and its cookie. */
interface Browser {
  readonly sid: string;
  readonly authTime: number;
  readonly jar: CookieJar;
}

/** A session as the API lists it. */
interface ListedSession {
  readonly id: string;
  readonly current: boolean;
  readonly createdAt: string;
  readonly lastSeenAt: string;
  readonly device: { readonly label: string };
}

describe('the account API’s sessions (#1110, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let net: FixtureNetwork | undefined;
  let receiver: FixtureServer;
  let dockerUp = false;
  let realmId = '';
  let signCookie: ((session: { sid: string; realmId: string }) => Promise<string>) | undefined;
  /** Sign-ins so far: each one's `auth_time` is its own, as its refresh families find it. */
  let signIns = 0;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    net = await createFixtureNetwork();
    receiver = await net.serve(RECEIVER_ADDRESS, (_req, _body, res) => {
      res.writeHead(200);
      res.end();
    });
    network.current = net.transport;
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      INTERACTION_UI_ENABLED: 'true',
      // Each case registers its own accounts from one address.
      REGISTRATION_RATE_LIMIT: '10000',
      VERIFICATION_RATE_LIMIT: '10000',
    });
    // Imported after the boot, as the harness imports the app: the module
    // reads the environment the boot sets, and shares the app's instances.
    const { signSessionCookie, SESSION_COOKIE_NAME } = await import('./helpers/session-cookie');
    const app = booted.app;
    signCookie = async (session) =>
      `${SESSION_COOKIE_NAME}=${await signSessionCookie(app, session)}`;
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await net?.close();
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp || booted === undefined || net === undefined) {
      ctx.skip();
      return;
    }
    net.dns.clear();
    net.dns.set('rp.egress.test', [RECEIVER_ADDRESS]);
    receiver.requests.length = 0;
  });

  function app(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  async function query<Row extends Record<string, unknown>>(
    sql: string,
    params: unknown[] = []
  ): Promise<Row[]> {
    const { rows } = await app().dbPool.query<Row>(sql, params);
    return rows;
  }

  /** A verified password account. */
  function account(): Promise<string> {
    return registerPasswordAccount(app(), `sessions-${randomUUID()}@example.test`);
  }

  /** A browser signed in to the account with `userAgent`, as a sign-in creates it. */
  async function signedIn(userId: string, userAgent = FIREFOX_ON_LINUX): Promise<Browser> {
    if (signCookie === undefined) throw new Error('server not booted');
    const session = await app().sessionService.create({
      realmId,
      userId,
      authTime: Date.now() - 1_000 - ++signIns * 10,
      amr: ['pwd'],
      ipAddress: '192.0.2.10',
      userAgent,
    });
    const jar = new CookieJar();
    jar.absorb(await signCookie({ sid: session.sid, realmId }));
    return { sid: session.sid, authTime: session.authTime, jar };
  }

  /** An account API token issued through `browser`'s session, as the code exchange mints it. */
  function token(
    userId: string,
    browser: Browser | null,
    claims: { scope?: string; act?: { sub: string } } = {}
  ): Promise<string> {
    return app().jwtUtils.signAccessToken(
      { id: realmId },
      {
        sub: userId,
        clientId: CONSOLE_ID,
        aud: ACCOUNT_AUDIENCE,
        scope: claims.scope ?? 'qauth:account:read qauth:account:write',
        amr: ['pwd'],
        ...(browser === null
          ? {}
          : { sid: browser.sid, authTime: Math.floor(browser.authTime / 1000) * 1000 }),
        ...(claims.act === undefined ? {} : { act: claims.act }),
      }
    );
  }

  function call(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    bearer: string,
    payload?: Record<string, unknown>
  ): Promise<LightMyRequestResponse> {
    return app().inject({
      method,
      url: `${PREFIX}${path}`,
      headers: { authorization: `Bearer ${bearer}` },
      ...(payload === undefined ? {} : { payload }),
    });
  }

  /** What the hosted account page answers `browser`'s cookie: 200 while its session is live. */
  async function accountPageStatus(browser: Browser): Promise<number> {
    const response = await app().inject({
      method: 'GET',
      url: ACCOUNT_PAGE,
      headers: { cookie: browser.jar.header() ?? '' },
    });
    return response.statusCode;
  }

  /** A relying party of the realm, with a back-channel logout URI if one is given. */
  async function relyingParty(uri: string | null): Promise<{ id: string; clientId: string }> {
    const clientId = `rp-${randomUUID()}`;
    const [row] = await query<{ id: string }>(
      `INSERT INTO oauth_clients
         (realm_id, client_id, client_secret_hash, name, redirect_uris,
          backchannel_logout_uri, backchannel_logout_uri_source,
          backchannel_logout_session_required)
       VALUES ($1, $2, 'h', 'Relying party', '["https://rp.example/cb"]', $3, $4, true)
       RETURNING id::text AS id`,
      [realmId, clientId, uri, uri === null ? null : 'client']
    );
    return { id: row?.id as string, clientId };
  }

  /** The session served `clients`, as the code mint records it. */
  async function served(sid: string, clients: readonly { id: string }[]): Promise<void> {
    for (const client of clients) {
      await query('INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2)', [
        sid,
        client.id,
      ]);
    }
  }

  /**
   * The realm's back-channel logout fan-out has a position: the first
   * fan-out that sees a destination starts at the horizon, so a session must
   * end only once it exists.
   */
  async function backChannelLogoutReady(): Promise<void> {
    await vi.waitFor(
      async () =>
        expect(
          await query(
            `SELECT 1 FROM event_delivery_positions
              WHERE realm_id = $1 AND destination_kind = 'backchannel_logout'`,
            [realmId]
          )
        ).toHaveLength(1),
      { timeout: 15_000, interval: 100 }
    );
  }

  /** The audience and `sid` of every logout token the receiver got, each verified, sorted. */
  async function logoutTokens(): Promise<string[]> {
    const discovery = await app().inject({
      method: 'GET',
      url: '/.well-known/openid-configuration',
    });
    const { jwks_uri: jwksUri } = discovery.json<{ jwks_uri: string }>();
    const jwks = await app().inject({ method: 'GET', url: new URL(jwksUri).pathname });
    const keys = createLocalJWKSet(jwks.json<JSONWebKeySet>());
    const seen: string[] = [];
    for (const request of receiver.requests) {
      const logoutToken = new URLSearchParams(request.body.toString('utf8')).get('logout_token');
      const { payload } = await jwtVerify(logoutToken as string, keys, {
        issuer: ORIGIN,
        typ: 'logout+jwt',
      });
      expect(payload['events']).toEqual({ [BACKCHANNEL_LOGOUT_EVENT]: {} });
      seen.push(`${String(payload.aud)} ${String(payload['sid'])}`);
    }
    return seen.sort();
  }

  /** A refresh family the sign-in at `authTime` opened for `client`. */
  async function refreshFamily(
    userId: string,
    client: { id: string },
    authTime: number
  ): Promise<string> {
    const row = await app().repositories.refreshTokens.create({
      tokenHash: randomBytes(32).toString('hex'),
      userId,
      oauthClientId: client.id,
      familyCreatedAt: Date.now(),
      familySessionExpiresAt: null,
      authTime,
      amr: ['pwd'],
      scopes: ['openid'],
      expiresAt: Date.now() + 600_000,
    });
    return row.id;
  }

  async function revokedReasonOf(refreshTokenId: string): Promise<string | null> {
    const [row] = await query<{ revoked: boolean; revoked_reason: string | null }>(
      'SELECT revoked, revoked_reason FROM refresh_tokens WHERE id = $1::uuid',
      [refreshTokenId]
    );
    return row?.revoked === true ? (row.revoked_reason ?? 'revoked') : null;
  }

  async function liveSessionsOf(userId: string): Promise<string[]> {
    const rows = await query<{ id: string }>(
      'SELECT id::text AS id FROM sessions WHERE user_id = $1 AND revoked_at IS NULL ORDER BY id',
      [userId]
    );
    return rows.map((row) => row.id);
  }

  async function signedOutEventsOf(userId: string): Promise<Record<string, unknown>[]> {
    const rows = await query<{ data: Record<string, unknown> }>(
      'SELECT data FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
      ['urn:qauth:event:user.signed_out:v1-rc.0', userId]
    );
    return rows.map((row) => row.data);
  }

  it('lists the user’s live sessions, most recently used first, with a device label, and marks the token’s own', async () => {
    const userId = await account();
    const laptop = await signedIn(userId, FIREFOX_ON_LINUX);
    const phone = await signedIn(userId, SAFARI_ON_IPHONE);
    const ended = await signedIn(userId);
    await app().sessionService.revoke({
      realmId,
      sid: ended.sid,
      userId,
      reason: 'sign_out',
      actor: { type: 'user', id: userId },
    });
    const someoneElse = await signedIn(await account());
    // The laptop was used after the phone signed in.
    await query('UPDATE sessions SET last_seen_at = $1 WHERE id = $2::uuid', [
      Date.now() + 1_000,
      laptop.sid,
    ]);
    const bearer = await token(userId, phone, { scope: 'qauth:account:read' });

    const response = await call('GET', '/sessions', bearer);

    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    const page = response.json<{ items: ListedSession[]; nextCursor: string | null }>();
    expect(page.nextCursor).toBeNull();
    expect(page.items.map((item) => [item.id, item.current, item.device.label])).toEqual([
      [laptop.sid, false, 'Firefox on Linux'],
      [phone.sid, true, 'Safari on iPhone'],
    ]);
    for (const item of page.items) {
      expect(Object.keys(item).sort()).toEqual([
        'createdAt',
        'current',
        'device',
        'id',
        'lastSeenAt',
      ]);
      expect(Date.parse(item.createdAt)).not.toBeNaN();
      expect(Date.parse(item.lastSeenAt)).toBeGreaterThanOrEqual(Date.parse(item.createdAt));
    }
    expect(response.body).not.toContain('192.0.2.10');
    expect(response.body).not.toContain(someoneElse.sid);

    // A page at a time, with the list's own cursor; another list's is refused.
    const first = await call('GET', '/sessions?limit=1', bearer);
    const { items, nextCursor } = first.json<{ items: ListedSession[]; nextCursor: string }>();
    expect(items.map((item) => item.id)).toEqual([laptop.sid]);
    const second = await call('GET', `/sessions?limit=1&cursor=${nextCursor}`, bearer);
    expect(second.json<{ items: ListedSession[] }>().items.map((item) => item.id)).toEqual([
      phone.sid,
    ]);
    const foreign = await call(
      'GET',
      `/sessions?cursor=${Buffer.from('{"l":"account.passkeys"}').toString('base64url')}`,
      bearer
    );
    expect(foreign.statusCode, foreign.body).toBe(400);
    expect(foreign.json()).toMatchObject({ code: 'invalid_cursor' });

    // No `sid` on the token: no session is its own.
    const unnamed = await call('GET', '/sessions', await token(userId, null));
    expect(unnamed.json<{ items: ListedSession[] }>().items.every((item) => !item.current)).toBe(
      true
    );
  });

  it('ends one session: its cookie stops working, its sign-in’s refresh families end, and each app with a back-channel logout URI gets one logout token', async () => {
    const first = await relyingParty('https://rp.egress.test/backchannel/first');
    const second = await relyingParty('https://rp.egress.test/backchannel/second');
    const silent = await relyingParty(null);
    await backChannelLogoutReady();
    const userId = await account();
    const own = await signedIn(userId);
    const laptop = await signedIn(userId);
    await served(laptop.sid, [first, second, silent]);
    await served(own.sid, [first]);
    const laptopFamily = await refreshFamily(userId, first, laptop.authTime);
    const consoleFamily = await refreshFamily(userId, first, own.authTime);
    expect(await accountPageStatus(laptop)).toBe(200);

    const response = await call('DELETE', `/sessions/${laptop.sid}`, await token(userId, own));

    expect(response.statusCode, response.body).toBe(204);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(await accountPageStatus(laptop)).toBe(303);
    expect(await accountPageStatus(own)).toBe(200);
    expect(await liveSessionsOf(userId)).toEqual([own.sid]);
    expect(await revokedReasonOf(laptopFamily)).toBe('session_ended');
    expect(await revokedReasonOf(consoleFamily)).toBeNull();
    await vi.waitFor(() => expect(receiver.requests).toHaveLength(2), {
      timeout: 20_000,
      interval: 200,
    });
    expect(await logoutTokens()).toEqual(
      [`${first.clientId} ${laptop.sid}`, `${second.clientId} ${laptop.sid}`].sort()
    );
    // The app without a URI is sent nothing; nor is any app twice.
    await new Promise((resolve) => setTimeout(resolve, 2_000));
    expect(receiver.requests).toHaveLength(2);
    expect(await signedOutEventsOf(userId)).toEqual([{ sid: laptop.sid }]);

    // Ended, it is no session to end again.
    const again = await call('DELETE', `/sessions/${laptop.sid}`, await token(userId, own));
    expect(again.statusCode, again.body).toBe(404);
    expect(again.json()).toMatchObject({ code: 'not_found' });
  });

  it('answers another user’s session, and a session that does not exist, as not found, and ends nothing', async () => {
    const userId = await account();
    const mine = await signedIn(userId);
    const otherId = await account();
    const theirs = await signedIn(otherId);
    const bearer = await token(userId, mine);

    for (const sid of [theirs.sid, theirs.sid.toUpperCase(), randomUUID()]) {
      const response = await call('DELETE', `/sessions/${sid}`, bearer);
      expect(response.statusCode, response.body).toBe(404);
      expect(response.json()).toMatchObject({ code: 'not_found' });
    }

    expect(await liveSessionsOf(otherId)).toEqual([theirs.sid]);
    expect(await liveSessionsOf(userId)).toEqual([mine.sid]);
    expect(await accountPageStatus(theirs)).toBe(200);
    expect(await signedOutEventsOf(otherId)).toEqual([]);
    // A token that may only read ends nothing.
    const readOnly = await call(
      'DELETE',
      `/sessions/${mine.sid}`,
      await token(userId, mine, { scope: 'qauth:account:read' })
    );
    expect(readOnly.statusCode, readOnly.body).toBe(403);
    expect(await liveSessionsOf(userId)).toEqual([mine.sid]);

    // The path may name the session in capitals; the event names it as its
    // ID tokens' `sid` does, which a Shared Signals receiver matches on.
    const upper = await call('DELETE', `/sessions/${mine.sid.toUpperCase()}`, bearer);
    expect(upper.statusCode, upper.body).toBe(204);
    expect(await liveSessionsOf(userId)).toEqual([]);
    expect(await signedOutEventsOf(userId)).toEqual([{ sid: mine.sid }]);
  });

  it('signs out everywhere: every session ends, every refresh family is revoked, and the apps get back-channel logouts', async () => {
    const rp = await relyingParty('https://rp.egress.test/backchannel/everywhere');
    await backChannelLogoutReady();
    const userId = await account();
    const own = await signedIn(userId);
    const phone = await signedIn(userId);
    await served(own.sid, [rp]);
    await served(phone.sid, [rp]);
    const families = [
      await refreshFamily(userId, rp, own.authTime),
      await refreshFamily(userId, rp, phone.authTime),
      await refreshFamily(userId, rp, Date.now() - 86_400_000),
    ];
    const otherId = await account();
    const theirs = await signedIn(otherId);

    // A delegated token: an agent acting for the person may sign them out.
    const bearer = await token(userId, own, { act: { sub: 'support-agent' } });
    const response = await call('POST', '/sessions/end-all', bearer);

    expect(response.statusCode, response.body).toBe(204);
    expect(await liveSessionsOf(userId)).toEqual([]);
    for (const browser of [own, phone]) {
      expect(await accountPageStatus(browser)).toBe(303);
    }
    for (const family of families) expect(await revokedReasonOf(family)).toBe('logout');
    expect(await liveSessionsOf(otherId)).toEqual([theirs.sid]);
    await vi.waitFor(() => expect(receiver.requests).toHaveLength(2), {
      timeout: 20_000,
      interval: 200,
    });
    expect(await logoutTokens()).toEqual(
      [`${rp.clientId} ${own.sid}`, `${rp.clientId} ${phone.sid}`].sort()
    );
    expect(await signedOutEventsOf(userId)).toEqual([{}]);
    // The event names the acting agent, with the whole chain.
    expect(
      await query(
        `SELECT actor_type, actor_id, actor_delegation_chain FROM events
          WHERE type = 'urn:qauth:event:user.signed_out:v1-rc.0' AND subject_id = $1`,
        [userId]
      )
    ).toEqual([
      {
        actor_type: 'client',
        actor_id: 'support-agent',
        actor_delegation_chain: ['support-agent'],
      },
    ]);
  });

  it('signs out everywhere else when asked: the token’s own session stays, every other ends, and every refresh family is revoked', async () => {
    const rp = await relyingParty('https://rp.egress.test/backchannel/else');
    await backChannelLogoutReady();
    const userId = await account();
    const own = await signedIn(userId);
    const laptop = await signedIn(userId);
    const phone = await signedIn(userId);
    await served(own.sid, [rp]);
    await served(laptop.sid, [rp]);
    const family = await refreshFamily(userId, rp, own.authTime);

    const response = await call('POST', '/sessions/end-all', await token(userId, own), {
      keepCurrent: true,
    });

    expect(response.statusCode, response.body).toBe(204);
    expect(await liveSessionsOf(userId)).toEqual([own.sid]);
    expect(await accountPageStatus(own)).toBe(200);
    expect(await accountPageStatus(laptop)).toBe(303);
    expect(await revokedReasonOf(family)).toBe('logout');
    await vi.waitFor(() => expect(receiver.requests).toHaveLength(1), {
      timeout: 20_000,
      interval: 200,
    });
    expect(await logoutTokens()).toEqual([`${rp.clientId} ${laptop.sid}`]);
    // One sign-out per session it ended: a receiver ends those alone.
    expect((await signedOutEventsOf(userId)).map((data) => String(data['sid'])).sort()).toEqual(
      [laptop.sid, phone.sid].sort()
    );

    // A body that is not the contract's is refused, and ends nothing.
    const refused = await call('POST', '/sessions/end-all', await token(userId, own), {
      keepCurrent: 'yes',
    });
    expect(refused.statusCode, refused.body).toBe(400);
    expect(await liveSessionsOf(userId)).toEqual([own.sid]);
  });
});
