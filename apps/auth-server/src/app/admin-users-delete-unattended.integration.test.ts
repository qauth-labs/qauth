import { randomUUID } from 'node:crypto';

import {
  createFixtureNetwork,
  type EgressTransport,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/fastify-plugin-ssf/src/testing/egress-network';
import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import {
  createLocalJWKSet,
  type CryptoKey,
  exportJWK,
  generateKeyPair,
  type JSONWebKeySet,
  type JWK,
  jwtVerify,
  SignJWT,
} from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  dpopProof,
  dpopTestKey,
  rememberTokenKey,
} from '../testing/admin-dpop';
import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { ageAdminAccount } from '../testing/two-admin';
import { API_FAMILY_AUDIENCES } from './api-conventions/families';

/**
 * A RELYING PARTY DELETES THE ACCOUNT IT CLOSED (#1090), against a real
 * Postgres and Redis, the token endpoint, the admin listener and the
 * delivery role, the apps that receive logout tokens being local HTTPS
 * servers behind the egress client's two network edges, as in the
 * back-channel logout suite.
 *
 * The relying party is a service account (#522) the operator gave the
 * built-in role `account-closer` on the realm, as the host's
 * `service-accounts create --grant account-closer@<realm>` does:
 *
 * - it deletes an account with no approval; a service account without the
 *   grant is answered 403 `approval_required`, and an approval is still
 *   required for every other security operation, `users.verify` here;
 * - after the deletion, an authorization request from the browser that held
 *   the account's session meets the sign-in step, not a silent sign-in;
 * - every client with a back-channel logout URI receives a logout token for
 *   each ended session, verifiable with the realm's keys;
 * - a second deletion of the same `sub` answers as the first and changes
 *   nothing;
 * - the grant stands in for nothing where the realm makes a second admin
 *   mandatory for `users.delete`, nor for a service account whose client
 *   registered itself.
 *
 * The server boots once and the database keeps each test's rows, so every
 * test makes its own accounts, clients and service accounts: a reset would
 * take the realm's keys, which the logout tokens are signed with.
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

const ADMIN = API_FAMILY_AUDIENCES.admin;
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const CLIENT_SESSION_ENDED = 'urn:qauth:event:user.client_session_ended:v1-rc.0';
const SESSION_REVOKED = 'urn:qauth:event:user.session_revoked:v1-rc.0';
const USER_DELETED = 'urn:qauth:event:user.deleted:v1-rc.0';
const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
const REDIRECT_URI = 'https://notes.example/callback';
/** A public address the fixture DNS hands out, served by a local server. */
const RECEIVER_ADDRESS = '93.184.215.14';

/** Settings that make a failed delivery retry within the test's wait. */
const DELIVERY_SETTINGS: Readonly<Record<string, string>> = Object.freeze({
  EVENT_DELIVERY_RETRY_INITIAL_DELAY: '1',
  EVENT_DELIVERY_RETRY_MAX_DELAY: '2',
});

let infra: E2eInfrastructure | undefined;
let jwt: PemKeyPair | undefined;
let net: FixtureNetwork | undefined;
let receiver: FixtureServer;
let dockerUp = false;

beforeAll(async () => {
  dockerUp = await requireDockerOrSkip();
  if (!dockerUp) return;
  infra = await startE2eInfrastructure();
  jwt = await generateJwtPem();
  net = await createFixtureNetwork();
  receiver = await net.serve(RECEIVER_ADDRESS, (_req, _body, res) => {
    res.writeHead(200);
    res.end();
  });
}, 240_000);

afterAll(async () => {
  await net?.close();
  await infra?.teardown();
});

interface EventRow {
  type: string;
  actor_type: string | null;
  actor_id: string | null;
  subject_id: string | null;
  client_id: string | null;
  data: Record<string, unknown>;
}

interface AuditRow {
  actor_kind: string;
  actor_id: string;
  outcome: string;
  approvals: unknown[];
  masked_diff: { before: Record<string, unknown> | null; after: unknown } | null;
}

describe('users.delete by a relying party, unattended (#1090, real containers)', () => {
  let booted: BootedAuthServer | undefined;
  /** The service accounts' key pair: each client's `jwks` holds the public half. */
  let clientKey: { privateKey: CryptoKey; jwk: JWK };

  beforeAll(async () => {
    if (!dockerUp || !infra || !jwt) return;
    booted = await bootAuthServer(
      { ...baseEnvironment(infra, jwt), ...ADMIN_LISTENER_ENVIRONMENT, ...DELIVERY_SETTINGS },
      // The server's own operation registry and admin routes.
      { adminListener: async () => ({}) }
    );
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    clientKey = { privateKey, jwk: { ...(await exportJWK(publicKey)), kid: 'rp-1' } };
    // One person who may approve on the realm, old enough to (#521): a call
    // that needs an approval is then answered `approval_required`, not
    // `approval_unavailable`.
    await humanApprover();
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
  });

  beforeEach((ctx) => {
    if (!dockerUp || !booted || !net) {
      ctx.skip();
      return;
    }
    net.dns.clear();
    net.dns.set('rp.egress.test', [RECEIVER_ADDRESS]);
    receiver.requests.length = 0;
    network.current = net.transport;
  });

  function app(): FastifyInstance {
    if (!booted) throw new Error('server not booted');
    return booted.app;
  }

  function admin(): FastifyInstance {
    if (!booted?.admin) throw new Error('admin listener not booted');
    return booted.admin;
  }

  /** The default realm: the operator realm of a one-realm deployment, where the relying party's users live. */
  async function realmOf(): Promise<{ id: string; issuer: string }> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer || !realm.isOperator) throw new Error('default realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  /** A second realm, with no keys. */
  async function otherRealm(): Promise<string> {
    const host = `other-${randomUUID().slice(0, 8)}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name: `other-${randomUUID()}`, issuer: `https://${host}`, enabled: true },
      host
    );
    return realm.id;
  }

  async function humanApprover(): Promise<void> {
    const realm = await realmOf();
    const userId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: 'security-admin' },
      targetRealmId: realm.id,
      createdBy: null,
    });
    await ageAdminAccount(app().dbPool, userId);
  }

  type Grant = { readonly role: string; readonly realmId: string | null };

  /**
   * A service account with `grants`, as the host's `service-accounts create`
   * makes one, and an admin token of it through `client_credentials`,
   * `private_key_jwt` and a DPoP proof, for `qauth:admin:security`.
   */
  async function relyingPartyAccount(grants: readonly Grant[]) {
    const realm = await realmOf();
    const clientId = `rp-closing-${randomUUID().slice(0, 8)}`;
    const created = await app().repositories.serviceAccounts.create({
      realmId: realm.id,
      name: clientId,
      clientId,
      jwks: { keys: [clientKey.jwk as Record<string, unknown>] },
      createdBy: null,
    });
    for (const grant of grants) {
      await app().repositories.adminGrants.create({
        userId: created.userId,
        role: { kind: 'built-in', name: grant.role },
        targetRealmId: grant.realmId,
        createdBy: null,
      });
    }
    return { userId: created.userId, clientId, clientRowId: created.client.id };
  }

  async function tokenOf(clientId: string, scope = 'qauth:admin:security'): Promise<string> {
    const realm = await realmOf();
    const now = Math.floor(Date.now() / 1000);
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: 'rp-1' })
      .setIssuer(clientId)
      .setSubject(clientId)
      .setAudience(realm.issuer)
      .setJti(randomUUID())
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .sign(clientKey.privateKey);
    const key = await dpopTestKey();
    const issued = await app().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        dpop: await dpopProof(key, { method: 'POST', url: `${realm.issuer}/oauth/token` }),
      },
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: assertion,
        scope,
        resource: ADMIN,
      }).toString(),
    });
    expect(issued.statusCode, issued.body).toBe(200);
    const { access_token: token, scope: granted } = issued.json<{
      access_token: string;
      scope: string;
    }>();
    expect(granted.split(' ')).toContain('qauth:admin:security');
    rememberTokenKey(token, key);
    return token;
  }

  async function send(
    method: 'POST' | 'DELETE',
    url: string,
    token: string,
    payload?: unknown,
    headers: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    return admin().inject({
      method,
      url,
      headers: { ...(await adminCallHeaders(token, method, url)), ...headers },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });
  }

  /** The relying party's deletion: by `sub`, `If-Match: *`, no approval and no body. */
  const remove = (realmId: string, sub: string, token: string) =>
    send('DELETE', `/admin/v1-rc.0/realms/${realmId}/users/${sub}`, token, undefined, {
      'if-match': '*',
    });

  /** An account the relying party's users would hold, with no session. */
  async function bareAccount(realmId: string): Promise<string> {
    return (await app().repositories.users.create({ realmId }, testPrimaryCredential())).id;
  }

  /** A client of the realm with the back-channel logout URI given, if any. */
  async function relyingPartyClient(realmId: string, uri: string | null) {
    const clientId = `app-${randomUUID()}`;
    const { rows } = await app().dbPool.query<{ id: string }>(
      `INSERT INTO oauth_clients
         (realm_id, client_id, client_secret_hash, name, redirect_uris,
          backchannel_logout_uri, backchannel_logout_uri_source,
          backchannel_logout_session_required)
       VALUES ($1, $2, 'h', 'Relying party', '["https://rp.example/cb"]', $3, $4, $5)
       RETURNING id::text AS id`,
      [realmId, clientId, uri, uri === null ? null : 'client', uri !== null]
    );
    return { id: rows[0].id, clientId };
  }

  /** Record that the session signed in to `clients`, as the code mint records it. */
  async function served(sid: string, clients: ReadonlyArray<{ id: string }>) {
    for (const client of clients) {
      await app().dbPool.query(
        'INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2)',
        [sid, client.id]
      );
    }
  }

  /** The app the browser signs in to, by the code flow with PKCE. */
  async function notesApp(realmId: string): Promise<string> {
    const clientId = `notes-${randomUUID()}`;
    await app().repositories.oauthClients.create({
      realmId,
      clientId,
      clientSecretHash: await app().passwordHasher.hashPassword('notes-secret'),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Notes',
      redirectUris: [REDIRECT_URI],
      scopes: ['openid'],
      grantTypes: ['authorization_code'],
      enabled: true,
      requirePkce: true,
    } as Parameters<FastifyInstance['repositories']['oauthClients']['create']>[0]);
    return clientId;
  }

  /** Where an authorization request from the browser that holds `cookie` goes. */
  async function authorize(clientId: string, cookie: string): Promise<string> {
    const pkce = pkcePair();
    const response = await app().inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        scope: 'openid',
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'closing-state',
      }).toString()}`,
      headers: { cookie },
    });
    expect(response.statusCode, response.body).toBe(302);
    return String(response.headers['location']);
  }

  /**
   * Wait until the fan-out has a back-channel logout position in the realm:
   * the first fan-out that sees a destination of a kind starts at the
   * horizon, so a test ends sessions only once the position exists.
   */
  async function fanOutStarted(realmId: string): Promise<void> {
    await vi.waitFor(
      async () => {
        const { rows } = await app().dbPool.query(
          `SELECT 1 FROM event_delivery_positions
            WHERE realm_id = $1 AND destination_kind = 'backchannel_logout'`,
          [realmId]
        );
        expect(rows).toHaveLength(1);
      },
      { timeout: 15_000, interval: 100 }
    );
  }

  /** The logout tokens the receiver got, each verified with the realm's published keys. */
  async function logoutTokens(issuer: string) {
    const jwks = await app().inject({ method: 'GET', url: '/.well-known/jwks.json' });
    const keys = createLocalJWKSet(jwks.json<JSONWebKeySet>());
    const tokens = [];
    for (const request of receiver.requests) {
      expect(request.method).toBe('POST');
      const token = new URLSearchParams(request.body.toString('utf8')).get('logout_token');
      expect(token).toEqual(expect.any(String));
      const { payload } = await jwtVerify(token as string, keys, {
        issuer,
        typ: 'logout+jwt',
        requiredClaims: ['iss', 'aud', 'iat', 'exp', 'jti', 'events', 'sid'],
      });
      expect(payload['events']).toEqual({ [BACKCHANNEL_LOGOUT_EVENT]: {} });
      tokens.push({ url: request.url, payload });
    }
    return tokens;
  }

  async function eventsOf(realmId: string, types: readonly string[], subject: string) {
    const { rows } = await app().dbPool.query<EventRow>(
      `SELECT type, actor_type, actor_id, subject_id, client_id, data
         FROM events WHERE realm_id = $1 AND type = ANY($2) AND subject_id = $3 ORDER BY seq`,
      [realmId, types, subject]
    );
    return rows;
  }

  async function auditRowsOf(realmId: string, actorId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT actor_kind::text AS actor_kind, actor_id, outcome::text AS outcome, approvals, masked_diff
         FROM admin_audit_log
        WHERE realm_id = $1 AND operation_id = 'users.delete' AND actor_id = $2 ORDER BY seq`,
      [realmId, actorId]
    );
    return rows;
  }

  async function liveSessionsOf(userId: string): Promise<string[]> {
    const { rows } = await app().dbPool.query<{ id: string }>(
      'SELECT id::text AS id FROM sessions WHERE user_id = $1 AND revoked_at IS NULL ORDER BY id',
      [userId]
    );
    return rows.map((row) => row.id);
  }

  // Acceptance criteria 1 to 3: no approval with the grant, every session
  // ended, every client with a URI sent a logout token per session, and the
  // browser signs in again.
  it('deletes with no approval: every session ends, each client with a logout URI receives a token per session, and the browser meets the sign-in step', async () => {
    const realm = await realmOf();
    const email = `closing-${randomUUID()}@example.com`;
    const userId = await registerPasswordAccount(app(), email);

    // The browser's session, signed in silently at the app, and a second
    // session of the same account on another device.
    const jar = await signInWithPassword(app(), email);
    const cookie = jar.header() as string;
    const notes = await notesApp(realm.id);
    expect(await authorize(notes, cookie)).not.toContain('/ui/login');
    const { sid: otherDevice } = await app().sessionService.create({
      realmId: realm.id,
      userId,
      authTime: Date.now(),
      amr: ['pwd'],
      ipAddress: '192.0.2.10',
      userAgent: 'Phone/1',
    });
    // Every live session of the account, the browser's and the other
    // device's among them.
    const sessions = await liveSessionsOf(userId);
    expect(sessions.length).toBeGreaterThanOrEqual(2);
    expect(sessions).toContain(otherDevice);

    // The relying party that closes the account, another app, both with a
    // back-channel logout URI, and an app without one.
    const closer = await relyingPartyClient(realm.id, 'https://rp.egress.test/closer/logout');
    const other = await relyingPartyClient(realm.id, 'https://rp.egress.test/other/logout');
    const silent = await relyingPartyClient(realm.id, null);
    for (const sid of sessions) await served(sid, [closer, other, silent]);
    await fanOutStarted(realm.id);

    const rp = await relyingPartyAccount([{ role: 'account-closer', realmId: realm.id }]);
    const token = await tokenOf(rp.clientId);
    const done = await remove(realm.id, userId, token);
    expect(done.statusCode, done.body).toBe(204);
    expect(done.body).toBe('');

    // The account and its sessions are gone, at once.
    expect(await app().repositories.users.findById(realm.id, userId)).toBeUndefined();
    expect(await liveSessionsOf(userId)).toEqual([]);

    // Each client with a URI receives one logout token per ended session,
    // for the account's sub and the session's sid; the app without one
    // receives nothing.
    await vi.waitFor(() => expect(receiver.requests).toHaveLength(sessions.length * 2), {
      timeout: 20_000,
      interval: 200,
    });
    const tokens = await logoutTokens(realm.issuer);
    expect(
      tokens.map(({ url, payload }) => `${url} ${String(payload.aud)} ${String(payload['sid'])}`)
    ).toEqual(
      expect.arrayContaining(
        sessions.flatMap((sid) => [
          `/closer/logout ${closer.clientId} ${sid}`,
          `/other/logout ${other.clientId} ${sid}`,
        ])
      )
    );
    // Once per session and client: nothing more arrives.
    await new Promise((resolve) => setTimeout(resolve, 2_000));
    expect(receiver.requests).toHaveLength(sessions.length * 2);
    for (const { payload } of tokens) expect(payload.sub).toBe(userId);
    const notices = await eventsOf(realm.id, [CLIENT_SESSION_ENDED], userId);
    expect(notices.map((notice) => notice.client_id)).not.toContain(silent.clientId);

    // The admin events name the service account's client as the actor; the
    // audit row names the service account and lists no approval.
    const adminEvents = await eventsOf(realm.id, [SESSION_REVOKED, USER_DELETED], userId);
    expect(
      adminEvents
        .filter((event) => event.type === SESSION_REVOKED)
        .map((event) => String(event.data['sid']))
        .sort()
    ).toEqual(sessions);
    expect(adminEvents.at(-1)?.type).toBe(USER_DELETED);
    for (const event of adminEvents) {
      expect(event).toMatchObject({ actor_type: 'client', actor_id: rp.clientId });
    }
    const audited = await auditRowsOf(realm.id, rp.userId);
    expect(audited).toHaveLength(1);
    expect(audited[0]).toMatchObject({
      actor_kind: 'service_account',
      outcome: 'succeeded',
      approvals: [],
    });
    expect(audited[0].masked_diff?.before).toMatchObject({
      userId,
      endedSessions: sessions.length,
    });

    // The browser that held the session meets the sign-in step.
    expect(await authorize(notes, cookie)).toContain('/ui/login?return_to=');
  });

  // Acceptance criterion 4: a retry answers as the first call.
  it('answers a second deletion of the same sub as the first, and changes nothing', async () => {
    const realm = await realmOf();
    const rp = await relyingPartyAccount([{ role: 'account-closer', realmId: realm.id }]);
    const token = await tokenOf(rp.clientId);
    const userId = await bareAccount(realm.id);

    const first = await remove(realm.id, userId, token);
    expect(first.statusCode, first.body).toBe(204);
    const eventsAfterFirst = await eventsOf(realm.id, [USER_DELETED, SESSION_REVOKED], userId);
    expect(eventsAfterFirst.filter((event) => event.type === USER_DELETED)).toHaveLength(1);

    const again = await remove(realm.id, userId, token);
    expect({ status: again.statusCode, body: again.body }).toEqual({
      status: first.statusCode,
      body: first.body,
    });
    expect(await eventsOf(realm.id, [USER_DELETED, SESSION_REVOKED], userId)).toEqual(
      eventsAfterFirst
    );

    // An unknown sub, and another realm's account by its id, answer alike
    // and change nothing.
    const elsewhereRealm = await otherRealm();
    const elsewhere = await bareAccount(elsewhereRealm);
    for (const sub of [randomUUID(), elsewhere]) {
      const answer = await remove(realm.id, sub, token);
      expect(answer.statusCode, answer.body).toBe(204);
      expect(answer.body).toBe('');
    }
    expect(await app().repositories.users.findById(elsewhereRealm, elsewhere)).toBeDefined();

    // Each call has its audit row; only the first recorded a change.
    const audited = await auditRowsOf(realm.id, rp.userId);
    expect(audited.map((row) => row.outcome)).toEqual([
      'succeeded',
      'succeeded',
      'succeeded',
      'succeeded',
    ]);
    expect(audited.slice(1).map((row) => row.masked_diff)).toEqual([null, null, null]);
  });

  // Acceptance criterion 1: one without the grant gets 403, and the grant
  // covers users.delete on its realm only.
  it('answers 403 approval_required to a service account without the grant, and to every other security operation of one with it', async () => {
    const realm = await realmOf();
    const userId = await bareAccount(realm.id);

    // security-admin holds users.delete, but no unattended deletion.
    const withoutGrant = await relyingPartyAccount([{ role: 'security-admin', realmId: realm.id }]);
    const refused = await remove(realm.id, userId, await tokenOf(withoutGrant.clientId));
    expect(refused.statusCode, refused.body).toBe(403);
    expect(refused.json()).toMatchObject({ code: 'approval_required' });

    // account-closer on another realm lets nothing run unattended here.
    const elsewhere = await relyingPartyAccount([
      { role: 'account-closer', realmId: await otherRealm() },
      { role: 'security-admin', realmId: realm.id },
    ]);
    const crossed = await remove(realm.id, userId, await tokenOf(elsewhere.clientId));
    expect(crossed.statusCode, crossed.body).toBe(403);
    expect(crossed.json()).toMatchObject({ code: 'approval_required' });
    expect(await app().repositories.users.findById(realm.id, userId)).toBeDefined();

    // With the grant beside security-admin, every other security operation
    // still needs its approval.
    const closer = await relyingPartyAccount([
      { role: 'account-closer', realmId: realm.id },
      { role: 'security-admin', realmId: realm.id },
    ]);
    const closerToken = await tokenOf(closer.clientId);
    const verify = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realm.id}/users/${userId}/verification`,
      closerToken,
      {},
      { 'if-match': '*' }
    );
    expect(verify.statusCode, verify.body).toBe(403);
    expect(verify.json()).toMatchObject({ code: 'approval_required' });
    const { operatorVerifiedAt } = (await app().repositories.users.findById(realm.id, userId)) as {
      operatorVerifiedAt: number | null;
    };
    expect(operatorVerifiedAt).toBeNull();

    // The deletion itself runs.
    expect((await remove(realm.id, userId, closerToken)).statusCode).toBe(204);
    expect(await app().repositories.users.findById(realm.id, userId)).toBeUndefined();
  });

  it("refuses a service account's account, its own included, with 409, as for any caller", async () => {
    const realm = await realmOf();
    const rp = await relyingPartyAccount([{ role: 'account-closer', realmId: realm.id }]);
    const token = await tokenOf(rp.clientId);
    const anotherRobot = await relyingPartyAccount([]);
    for (const userId of [rp.userId, anotherRobot.userId]) {
      const refused = await remove(realm.id, userId, token);
      expect(refused.statusCode, refused.body).toBe(409);
      expect(refused.json()).toMatchObject({ code: 'conflict' });
      expect(await app().repositories.users.findById(realm.id, userId)).toBeDefined();
    }
  });

  it('runs nothing unattended for a service account whose client registered itself', async () => {
    const realm = await realmOf();
    const rp = await relyingPartyAccount([{ role: 'account-closer', realmId: realm.id }]);
    // The token endpoint refuses such a client the admin audience, so the
    // token is minted first, and the client marked as registered at
    // /oauth/register afterwards: the admin API reads the client on every
    // call.
    const token = await tokenOf(rp.clientId);
    await app().dbPool.query('UPDATE oauth_clients SET dynamic_registered_at = $2 WHERE id = $1', [
      rp.clientRowId,
      Date.now(),
    ]);
    const userId = await bareAccount(realm.id);
    const refused = await remove(realm.id, userId, token);
    expect(refused.statusCode, refused.body).toBe(403);
    expect(refused.json()).toMatchObject({ code: 'approval_required' });
    expect(await app().repositories.users.findById(realm.id, userId)).toBeDefined();
  });

  // The two-admin rule (#521): a realm that makes a second admin mandatory
  // for users.delete switches the unattended deletion off.
  it('stands in for nothing where the realm makes a second admin mandatory for users.delete', async () => {
    const realm = await realmOf();
    const rp = await relyingPartyAccount([{ role: 'account-closer', realmId: realm.id }]);
    const token = await tokenOf(rp.clientId);
    const userId = await bareAccount(realm.id);

    const setMandatory = async (operations: string[]) => {
      const current = await app().policyStore.get(realm.id);
      if (current === undefined) throw new Error('the realm has no policies');
      await app().policyStore.update(
        realm.id,
        { admin: { twoAdminMandatoryOperations: operations } },
        { expectedVersion: current.version }
      );
      app().realmHostCache.clear();
    };
    // A second person who may approve: two approvals could then be given,
    // and the call is answered for the approvals it lacks.
    await humanApprover();
    await setMandatory(['users.delete']);
    try {
      const refused = await remove(realm.id, userId, token);
      expect(refused.statusCode, refused.body).toBe(403);
      expect(refused.json()).toMatchObject({ code: 'approval_required' });
      expect(await app().repositories.users.findById(realm.id, userId)).toBeDefined();
    } finally {
      await setMandatory([]);
    }
    expect((await remove(realm.id, userId, token)).statusCode).toBe(204);
  });
});
