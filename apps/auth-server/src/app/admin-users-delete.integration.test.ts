import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  signBoundAccessToken,
} from '../testing/admin-dpop';
import type { TestApprovalFactor } from '../testing/approval-factor';
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
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { API_FAMILY_AUDIENCES } from './api-conventions/families';
import { ADMIN_SCOPE_LIST } from './helpers/admin-scopes';

/**
 * AN ADMIN DELETES AN ACCOUNT (#681; the idempotence of #1090), against a
 * real Postgres and Redis: `users.delete` on the admin listener, filed,
 * approved and run.
 *
 * - The deletion removes the account's credentials, sessions, consents and
 *   refresh tokens, and writes its admin events: one `user.session_revoked`
 *   per ended session, `user.deleted`, and the call's audit row.
 * - Every session ends first, a browser session and a sign-up's logout-only
 *   session alike, and each client a session signed in to with a
 *   back-channel logout URI gets one `user.client_session_ended` notice per
 *   ended session: the outbox the delivery role sends each logout token from
 *   (its delivery is `backchannel-logout.integration.test.ts`'s). A client
 *   without a URI gets none.
 * - The browser that held the account's session meets the sign-in step at
 *   the next authorization request, not a silent sign-in.
 * - A second deletion of the same id, and a deletion of another realm's
 *   account by its id, answer as a deletion does and change nothing.
 * - A service account's account, and an admin's, are refused with 409; a
 *   person's call runs only with its approval.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const SECURITY_SCOPES = 'qauth:admin:read qauth:admin:security';
const CLIENT_SESSION_ENDED = 'urn:qauth:event:user.client_session_ended:v1-rc.0';
const SESSION_REVOKED = 'urn:qauth:event:user.session_revoked:v1-rc.0';
const USER_DELETED = 'urn:qauth:event:user.deleted:v1-rc.0';
const REDIRECT_URI = 'https://notes.example/callback';

let infra: E2eInfrastructure | undefined;
let jwt: PemKeyPair | undefined;
let dockerUp = false;

beforeAll(async () => {
  dockerUp = await requireDockerOrSkip();
  if (!dockerUp) return;
  infra = await startE2eInfrastructure();
  jwt = await generateJwtPem();
}, 240_000);

afterAll(async () => {
  await infra?.teardown();
});

interface AuditRow {
  outcome: string;
  masked_diff: { before: Record<string, unknown> | null; after: unknown } | null;
}

interface EventRow {
  type: string;
  category: string;
  actor_type: string | null;
  actor_id: string | null;
  subject_id: string | null;
  client_id: string | null;
  data: Record<string, unknown>;
}

describe('users.delete (#681, real containers)', () => {
  let booted: BootedAuthServer | undefined;
  let test: TestApprovalFactor;

  beforeAll(async () => {
    if (!dockerUp || !infra || !jwt) return;
    booted = await bootAuthServer(
      { ...baseEnvironment(infra, jwt), ...ADMIN_LISTENER_ENVIRONMENT },
      // The server's own operation registry and admin routes.
      { adminListener: async () => ({}) }
    );
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || !booted) {
      ctx.skip();
      return;
    }
    await resetE2eState(booted.app);
    // Imported once the boot reset the modules, as the engine is.
    const { createTestApprovalFactor } = await import('../testing/approval-factor');
    test = createTestApprovalFactor();
  });

  function app(): FastifyInstance {
    if (!booted) throw new Error('server not booted');
    return booted.app;
  }

  function admin(): FastifyInstance {
    if (!booted?.admin) throw new Error('admin listener not booted');
    return booted.admin;
  }

  async function defaultRealm(): Promise<{ id: string; issuer: string }> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer) throw new Error('default realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  /** A second realm, which the admins of the default realm hold nothing on. */
  async function otherRealm(): Promise<string> {
    const host = `other-${randomUUID().slice(0, 8)}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name: `other-${randomUUID()}`, issuer: `https://${host}`, enabled: true },
      host
    );
    return realm.id;
  }

  type Admin = Awaited<ReturnType<typeof adminWith>>;

  /** An admin of the default realm with `role` on it: its token and its account as an approver. */
  async function adminWith(
    role: 'viewer' | 'editor' | 'security-admin',
    scope = ADMIN_SCOPE_LIST.join(' ')
  ) {
    const realm = await defaultRealm();
    const userId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: role },
      targetRealmId: realm.id,
      createdBy: null,
    });
    const token = await signBoundAccessToken(app(), realm, {
      sub: userId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope,
    });
    return { userId, token, approver: { realmId: realm.id, accountId: userId } };
  }

  const accountPath = (realmId: string, userId: string) =>
    `/admin/v1-rc.0/realms/${realmId}/users/${userId}`;

  /** A call with `token` under the `DPoP` scheme and a fresh proof of its key (#520). */
  async function send(
    method: 'GET' | 'POST' | 'DELETE',
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

  /** The deletion, with no body, naming the account's current state. */
  const remove = (
    realmId: string,
    userId: string,
    by: Admin,
    headers: Record<string, string> = {}
  ) =>
    send('DELETE', accountPath(realmId, userId), by.token, undefined, {
      'if-match': '*',
      ...headers,
    });

  /** File an approval for the deletion of `userId` and approve it with the test factor. */
  async function fileAndApprove(realmId: string, userId: string, requester: Admin) {
    const filed = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realmId}/approvals`,
      requester.token,
      {
        operation: 'users.delete',
        params: { userId },
        reason: 'The relying party closed the account in ticket OPS-681.',
      }
    );
    expect(filed.statusCode, filed.body).toBe(201);
    const approvalId = filed.json<{ id: string }>().id;

    const engine = await import('./admin/approvals/engine');
    const decision = {
      realmId,
      approvalId,
      approver: requester.approver,
      sessionIssuedAtMs: Date.now(),
    };
    const { challenge } = await engine.startApproval(app(), test.factor, decision);
    await engine.completeApproval(app(), test.factor, {
      ...decision,
      response: test.answer(challenge, requester.approver),
    });
    return approvalId;
  }

  /** Delete `userId` of `realmId` with a fresh approval, as a person's call runs. */
  async function approvedDelete(realmId: string, userId: string, by: Admin) {
    const approvalId = await fileAndApprove(realmId, userId, by);
    return remove(realmId, userId, by, { 'qauth-approval': approvalId });
  }

  /** A client of the realm, with the back-channel logout URI given, if any. */
  async function relyingParty(realmId: string, uri: string | null) {
    const clientId = `rp-${randomUUID()}`;
    const { rows } = await app().dbPool.query<{ id: string }>(
      `INSERT INTO oauth_clients
         (realm_id, client_id, client_secret_hash, name, redirect_uris,
          backchannel_logout_uri, backchannel_logout_uri_source)
       VALUES ($1, $2, 'h', 'Relying party', '["https://rp.example/cb"]', $3, $4)
       RETURNING id::text AS id`,
      [realmId, clientId, uri, uri === null ? null : 'client']
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

  async function countOf(table: string, userId: string): Promise<number> {
    const { rows } = await app().dbPool.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM ${table} WHERE user_id = $1`,
      [userId]
    );
    return rows[0]?.count ?? 0;
  }

  async function eventsOf(realmId: string, types: readonly string[]): Promise<EventRow[]> {
    const { rows } = await app().dbPool.query<EventRow>(
      `SELECT type, category, actor_type, actor_id, subject_id, client_id, data
         FROM events WHERE realm_id = $1 AND type = ANY($2) ORDER BY seq`,
      [realmId, types]
    );
    return rows;
  }

  async function auditRows(realmId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT outcome::text AS outcome, masked_diff
         FROM admin_audit_log WHERE realm_id = $1 AND operation_id = 'users.delete' ORDER BY seq`,
      [realmId]
    );
    return rows;
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
        state: 'delete-state',
      }).toString()}`,
      headers: { cookie },
    });
    expect(response.statusCode, response.body).toBe(302);
    return String(response.headers['location']);
  }

  it('deletes an approved account at once: its credentials, sessions and consents go, each client with a logout URI gets a notice per ended session, and the admin events name the admin', async () => {
    const realm = await defaultRealm();
    const email = `delete-${randomUUID()}@example.com`;
    const userId = await registerPasswordAccount(app(), email);
    const requester = await adminWith('security-admin', SECURITY_SCOPES);

    // The browser's session, and the logout-only session a sign-up that
    // finished an authorization interaction leaves (#1144).
    const jar = await signInWithPassword(app(), email);
    const cookie = jar.header() as string;
    const notes = await notesApp(realm.id);
    expect(await authorize(notes, cookie)).not.toContain('/ui/login');
    const {
      rows: [browser],
    } = await app().dbPool.query<{ id: string }>(
      `SELECT id::text AS id FROM sessions WHERE user_id = $1 AND kind = 'browser'
        ORDER BY created_at DESC, id DESC LIMIT 1`,
      [userId]
    );
    const {
      rows: [signUp],
    } = await app().dbPool.query<{ id: string }>(
      `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at, kind)
       VALUES ($1, $2, $3, $4, 'registration') RETURNING id::text AS id`,
      [realm.id, userId, Date.now(), Date.now() + 3_600_000]
    );
    const withUriA = await relyingParty(realm.id, 'https://rp-a.example/logout');
    const withUriB = await relyingParty(realm.id, 'https://rp-b.example/logout');
    const withoutUri = await relyingParty(realm.id, null);
    await served(browser.id, [withUriA, withUriB, withoutUri]);
    await served(signUp.id, [withUriA]);
    await app().dbPool.query(
      `INSERT INTO oauth_consents (user_id, oauth_client_id, realm_id, scopes)
       VALUES ($1, $2, $3, '["openid"]')`,
      [userId, withUriA.id, realm.id]
    );
    await app().dbPool.query(
      `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, expires_at)
       VALUES (md5(random()::text) || md5(random()::text), $1, $2, $3)`,
      [userId, withUriA.id, Date.now() + 3_600_000]
    );
    // Every live session of the account, the two above among them.
    const { rows: live } = await app().dbPool.query<{ id: string }>(
      'SELECT id::text AS id FROM sessions WHERE user_id = $1 AND revoked_at IS NULL',
      [userId]
    );
    const liveSessions = live.map((row) => row.id).sort();
    expect(liveSessions).toEqual(expect.arrayContaining([browser.id, signUp.id]));

    // Without its approval, a person's call changes nothing.
    const unapproved = await remove(realm.id, userId, requester);
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });
    // Without If-Match it does not run either.
    const unconditional = await send('DELETE', accountPath(realm.id, userId), requester.token);
    expect(unconditional.statusCode).toBe(428);
    expect(await app().repositories.users.findById(realm.id, userId)).toBeDefined();

    const approvalId = await fileAndApprove(realm.id, userId, requester);
    // The approver was shown the account, its password credential and what
    // the deletion ends.
    const shown = await send(
      'GET',
      `/admin/v1-rc.0/realms/${realm.id}/approvals/${approvalId}`,
      requester.token
    );
    expect(shown.statusCode, shown.body).toBe(200);
    expect(shown.json()).toMatchObject({
      display: {
        title: 'Delete an account',
        fields: expect.arrayContaining([
          { label: 'account', value: userId },
          { label: 'now', value: 'enabled' },
          {
            label: 'credential password (primary)',
            value: `address ${email} confirmed by its mailbox code`,
          },
        ]),
      },
    });

    const done = await remove(realm.id, userId, requester, { 'qauth-approval': approvalId });
    expect(done.statusCode, done.body).toBe(204);
    expect(done.body).toBe('');

    // The account and what hung off it are gone.
    expect(await app().repositories.users.findById(realm.id, userId)).toBeUndefined();
    for (const table of ['user_credentials', 'sessions', 'oauth_consents', 'refresh_tokens']) {
      expect(await countOf(table, userId), table).toBe(0);
    }
    const { rows: registry } = await app().dbPool.query(
      'SELECT 1 FROM session_clients WHERE session_id = ANY($1)',
      [[browser.id, signUp.id]]
    );
    expect(registry).toEqual([]);

    // One logout notice per ended session and client with a URI, none for
    // the client without one.
    const notices = await eventsOf(realm.id, [CLIENT_SESSION_ENDED]);
    expect(
      notices.map((event) => `${String(event.data['sid'])} ${String(event.client_id)}`).sort()
    ).toEqual(
      [
        `${browser.id} ${withUriA.clientId}`,
        `${browser.id} ${withUriB.clientId}`,
        `${signUp.id} ${withUriA.clientId}`,
      ].sort()
    );
    for (const notice of notices) {
      expect(notice).toMatchObject({ subject_id: userId, data: { reason: 'admin' } });
    }

    // The admin events: each ended session, then the deletion, the admin as
    // their actor.
    const adminEvents = await eventsOf(realm.id, [SESSION_REVOKED, USER_DELETED]);
    expect(
      adminEvents
        .filter((event) => event.type === SESSION_REVOKED)
        .map((event) => String(event.data['sid']))
        .sort()
    ).toEqual(liveSessions);
    expect(adminEvents.filter((event) => event.type === USER_DELETED)).toHaveLength(1);
    expect(adminEvents.at(-1)?.type).toBe(USER_DELETED);
    for (const event of adminEvents) {
      expect(event).toMatchObject({
        category: 'admin',
        actor_type: 'user',
        actor_id: requester.userId,
        subject_id: userId,
      });
      if (event.type === SESSION_REVOKED) expect(event.data['reason']).toBe('account_deleted');
    }

    const audited = (await auditRows(realm.id)).filter((row) => row.outcome === 'succeeded');
    expect(audited).toHaveLength(1);
    expect(audited[0].masked_diff?.before).toMatchObject({
      userId,
      enabled: true,
      endedSessions: liveSessions.length,
    });
    expect(JSON.stringify(audited[0].masked_diff)).not.toContain(email);

    // The browser that held the session signs in again at the next request.
    expect(await authorize(notes, cookie)).toContain('/ui/login?return_to=');
  });

  it("answers a second deletion of the same id, and one of another realm's account, as a deletion, and changes nothing", async () => {
    const realm = await defaultRealm();
    const requester = await adminWith('security-admin', SECURITY_SCOPES);
    const userId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    expect((await approvedDelete(realm.id, userId, requester)).statusCode).toBe(204);
    const eventsAfterFirst = await eventsOf(realm.id, [USER_DELETED, SESSION_REVOKED]);
    expect(eventsAfterFirst.filter((event) => event.type === USER_DELETED)).toHaveLength(1);

    // The same id again: the approver is shown that nothing is deleted, and
    // the call answers as the first did.
    const againApproval = await fileAndApprove(realm.id, userId, requester);
    const shown = await send(
      'GET',
      `/admin/v1-rc.0/realms/${realm.id}/approvals/${againApproval}`,
      requester.token
    );
    expect(JSON.stringify(shown.json())).toContain('The realm holds no account with this id');
    const again = await remove(realm.id, userId, requester, { 'qauth-approval': againApproval });
    expect(again.statusCode, again.body).toBe(204);
    expect(again.body).toBe('');

    // Another realm's account, by its id, and an id no realm holds.
    const elsewhereRealm = await otherRealm();
    const elsewhere = (
      await app().repositories.users.create({ realmId: elsewhereRealm }, testPrimaryCredential())
    ).id;
    const cross = await approvedDelete(realm.id, elsewhere, requester);
    expect(cross.statusCode, cross.body).toBe(204);
    expect(cross.body).toBe('');
    expect(await app().repositories.users.findById(elsewhereRealm, elsewhere)).toBeDefined();
    expect(await countOf('user_credentials', elsewhere)).toBe(1);
    const unknown = await approvedDelete(realm.id, randomUUID(), requester);
    expect(unknown.statusCode, unknown.body).toBe(204);

    // No event about any of them; each call has its audit row, with no change.
    expect(await eventsOf(realm.id, [USER_DELETED, SESSION_REVOKED])).toEqual(eventsAfterFirst);
    expect(await eventsOf(elsewhereRealm, [USER_DELETED, SESSION_REVOKED])).toEqual([]);
    const succeeded = (await auditRows(realm.id)).filter((row) => row.outcome === 'succeeded');
    expect(succeeded).toHaveLength(4);
    expect(succeeded.slice(1).map((row) => row.masked_diff)).toEqual([null, null, null]);
  });

  it("refuses a service account's account and an admin's with 409, before anything is filed", async () => {
    const realm = await defaultRealm();
    const requester = await adminWith('security-admin', SECURITY_SCOPES);
    const serviceAccount = await app().repositories.serviceAccounts.create({
      realmId: realm.id,
      name: 'rp-account-closing',
      clientId: 'rp-account-closing',
      jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', kid: 'k1' }] },
      createdBy: null,
    });
    const otherAdmin = await adminWith('viewer');

    // A service account's account, another admin's, and the caller's own,
    // which is an admin's too.
    for (const userId of [serviceAccount.userId, otherAdmin.userId, requester.userId]) {
      const filed = await send(
        'POST',
        `/admin/v1-rc.0/realms/${realm.id}/approvals`,
        requester.token,
        { operation: 'users.delete', params: { userId } }
      );
      expect(filed.statusCode, filed.body).toBe(409);
      const run = await remove(realm.id, userId, requester);
      expect(run.statusCode, run.body).toBe(409);
      expect(run.json()).toMatchObject({ code: 'conflict' });
      expect(await app().repositories.users.findById(realm.id, userId)).toBeDefined();
    }
    expect(await eventsOf(realm.id, [USER_DELETED])).toEqual([]);
  });

  it('is out of reach of a write scope, and of an admin without users.delete', async () => {
    const realm = await defaultRealm();
    const userId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    const editor = await adminWith('editor', 'qauth:admin:read qauth:admin:write');
    const byEditor = await remove(realm.id, userId, editor);
    expect(byEditor.statusCode).toBe(403);
    expect(byEditor.json()).toMatchObject({ code: 'forbidden' });
    expect(await app().repositories.users.findById(realm.id, userId)).toBeDefined();
  });
});
