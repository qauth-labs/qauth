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
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { API_FAMILY_AUDIENCES } from './api-conventions/families';
import { ADMIN_SCOPE_LIST } from './helpers/admin-scopes';

/**
 * THE CLIENT OPERATIONS OF THE ADMIN API (#632, ADR-020 §3, ADR-019 Decision
 * 7, ADR-012), against a real Postgres and Redis: every client of a realm
 * listed and read, whoever owns it, while the developer API still lists a
 * developer's own; the write scope refused every security field; a client
 * lifetime longer than the realm's refused; a CIMD client read-only, its
 * refusal naming the document; no answer carrying a secret hash; a client
 * of another realm not found; and a registration, a security change, a
 * suspension and a deletion filed, approved and run.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const MERGE_PATCH = 'application/merge-patch+json';
const DEVELOPER_AUDIENCE = 'urn:qauth:aud:developer:v1-rc.0';

/** The hash the stored clients carry: it must never come back, in any form. */
const SECRET_HASH = `$argon2id$v=19$m=19456,t=2,p=1$${'c2FsdC1vZi10aGUtdGVzdA'}$never-returned-${randomUUID()}`;

/** The access token lifetime of the default realm (`ACCESS_TOKEN_LIFESPAN`'s default). */
const REALM_ACCESS_LIFETIME = 900;
/** Its refresh token lifetime (`REFRESH_TOKEN_LIFESPAN`'s default). */
const REALM_REFRESH_LIFETIME = 604_800;

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

interface EventRow {
  type: string;
  actor_type: string;
  actor_id: string | null;
  subject_id: string;
  data: Record<string, unknown>;
}

interface ClientBody {
  id: string;
  client_id: string;
  name: string;
  developerId: string | null;
  metadataDocument: string | null;
  redirectUris: string[];
  tokenEndpointAuthMethod: string;
  suspended: boolean;
  enabled: boolean;
  firstPartyProfile: string | null;
  accessTokenLifespanSeconds: number | null;
  clientSecret?: string;
}

describe('the admin client operations (#632, real containers)', () => {
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
  async function adminWith(role: 'viewer' | 'editor' | 'security-admin', scope = ALL_ADMIN_SCOPES) {
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

  /** A client stored as another path stores it: a developer's, an operator's, a CIMD one. */
  async function storedClient(realmId: string, overrides: Record<string, unknown> = {}) {
    const row = await app().repositories.oauthClients.create({
      realmId,
      clientId: `client-${randomUUID()}`,
      clientSecretHash: SECRET_HASH,
      name: 'Stored client',
      redirectUris: ['https://stored.example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      scopes: ['openid'],
      tokenEndpointAuthMethod: 'client_secret_basic',
      ...overrides,
    } as Parameters<FastifyInstance['repositories']['oauthClients']['create']>[0]);
    return row;
  }

  const clientsPath = (realmId: string) => `/admin/v1-rc.0/realms/${realmId}/clients`;
  const clientPath = (realmId: string, id: string) => `${clientsPath(realmId)}/${id}`;

  /** A call with `token` under the `DPoP` scheme and a fresh proof of its key (#520). */
  async function send(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    token: string,
    payload?: unknown,
    headers: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    const path = url.split('?')[0];
    return admin().inject({
      method,
      url,
      headers: { ...(await adminCallHeaders(token, method, path)), ...headers },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });
  }

  /** A merge patch of the client, naming `etag` in If-Match. */
  const patchClient = (
    realmId: string,
    id: string,
    by: Admin,
    body: Record<string, unknown>,
    etag: string,
    headers: Record<string, string> = {}
  ) =>
    send('PATCH', clientPath(realmId, id), by.token, JSON.stringify(body), {
      'content-type': MERGE_PATCH,
      'if-match': etag,
      ...headers,
    });

  /** The client's ETag, as clients.get answers it. */
  async function etagOf(realmId: string, id: string, by: Admin): Promise<string> {
    const read = await send('GET', clientPath(realmId, id), by.token);
    expect(read.statusCode, read.body).toBe(200);
    const etag = read.headers['etag'];
    if (typeof etag !== 'string') throw new Error('clients.get answered no ETag');
    return etag;
  }

  /** File an approval for `operation` and approve it with the test factor. */
  async function fileAndApprove(
    realmId: string,
    requester: Admin,
    operation: string,
    params: Record<string, string>,
    body?: unknown
  ): Promise<string> {
    const filed = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realmId}/approvals`,
      requester.token,
      {
        operation,
        params,
        ...(body === undefined ? {} : { body }),
        reason: 'The operator asked for it in ticket OPS-632.',
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

  async function clientEvents(realmId: string, subject: string): Promise<EventRow[]> {
    const { rows } = await app().dbPool.query<EventRow>(
      `SELECT type, actor_type, actor_id, subject_id, data
         FROM events WHERE realm_id = $1 AND subject_id = $2 ORDER BY seq`,
      [realmId, subject]
    );
    return rows;
  }

  async function storedRow(id: string) {
    const { rows } = await app().dbPool.query<{
      name: string;
      redirect_uris: string[];
      client_secret_hash: string;
      suspended: boolean;
      access_token_lifespan_seconds: number | null;
    }>(
      `SELECT name, redirect_uris, client_secret_hash, suspended, access_token_lifespan_seconds
         FROM oauth_clients WHERE id = $1`,
      [id]
    );
    return rows[0];
  }

  /** Whether `response` carries a secret hash, the stored one or any member named so. */
  const carriesSecretHash = (response: LightMyRequestResponse): boolean =>
    response.body.includes(SECRET_HASH) ||
    /secret_?hash/i.test(response.body) ||
    response.body.includes('$argon2');

  it("lists every client of the realm, with and without a developer, and the developer's own list is unchanged", async () => {
    const realm = await defaultRealm();
    const developerId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    const owned = await storedClient(realm.id, { name: 'Owned by a developer', developerId });
    const operated = await storedClient(realm.id, {
      name: 'Run by the operator',
      provisionedByOperator: true,
    });
    const elsewhere = await storedClient(await otherRealm(), { name: 'Of another realm' });
    const viewer = await adminWith('viewer', 'qauth:admin:read');

    const listed = await send('GET', `${clientsPath(realm.id)}?limit=100`, viewer.token);
    expect(listed.statusCode, listed.body).toBe(200);
    expect(listed.headers['cache-control']).toBe('no-store');
    const items = listed.json<{ items: ClientBody[]; nextCursor: string | null }>().items;
    const ids = items.map((item) => item.id);
    expect(ids).toEqual(expect.arrayContaining([owned.id, operated.id]));
    expect(ids).not.toContain(elsewhere.id);
    expect(items.find((item) => item.id === owned.id)).toMatchObject({ developerId });
    expect(items.find((item) => item.id === operated.id)).toMatchObject({ developerId: null });
    expect(carriesSecretHash(listed)).toBe(false);

    // The search keeps the clients whose name or client_id holds the text.
    const searched = await send(
      'GET',
      `${clientsPath(realm.id)}?q=${encodeURIComponent('by the operator')}`,
      viewer.token
    );
    expect(searched.statusCode, searched.body).toBe(200);
    expect(searched.json<{ items: ClientBody[] }>().items.map((item) => item.id)).toEqual([
      operated.id,
    ]);

    // The developer API lists the developer's own client, and only it.
    const developerToken = await app().jwtUtils.signAccessToken(
      { id: realm.id },
      {
        sub: developerId,
        clientId: 'developer-portal',
        aud: DEVELOPER_AUDIENCE,
        scope: 'qauth:developer:read',
      }
    );
    const own = await app().inject({
      method: 'GET',
      url: '/developer/v1-rc.0/clients',
      headers: { authorization: `Bearer ${developerToken}` },
    });
    expect(own.statusCode, own.body).toBe(200);
    expect(own.json<{ items: { id: string }[] }>().items.map((item) => item.id)).toEqual([
      owned.id,
    ]);
  });

  it('refuses qauth:admin:write a change of the redirect URIs, the authentication method or first-party trust', async () => {
    const realm = await defaultRealm();
    const client = await storedClient(realm.id, { provisionedByOperator: true });
    // A security admin's role holds every permission; its token's scopes stop at write.
    const writer = await adminWith('security-admin', 'qauth:admin:read qauth:admin:write');
    const etag = await etagOf(realm.id, client.id, writer);

    for (const body of [
      { redirectUris: ['https://attacker.example/callback'] },
      { tokenEndpointAuthMethod: 'none' },
      {
        tokenEndpointAuthMethod: 'private_key_jwt',
        jwksUri: 'https://stored.example.com/jwks.json',
        firstPartyProfile: 'web_redirect',
        firstPartyReason: 'The operator runs it.',
      },
      // Mixed with a general field, the patch needs both scopes.
      { name: 'Renamed', redirectUris: ['https://attacker.example/callback'] },
    ]) {
      const refused = await patchClient(realm.id, client.id, writer, body, etag);
      expect(refused.statusCode, JSON.stringify(body)).toBe(403);
      expect(refused.headers['www-authenticate']).toContain('error="insufficient_scope"');
      expect(refused.headers['www-authenticate']).toContain('qauth:admin:security');
    }
    expect(await storedRow(client.id)).toMatchObject({
      name: 'Stored client',
      redirect_uris: ['https://stored.example.com/callback'],
    });

    // A general field is the write scope's.
    const renamed = await patchClient(realm.id, client.id, writer, { name: 'Renamed' }, etag);
    expect(renamed.statusCode, renamed.body).toBe(200);
    expect(renamed.json<ClientBody>().name).toBe('Renamed');
    expect(renamed.headers['etag']).not.toBe(etag);
    expect(carriesSecretHash(renamed)).toBe(false);
    expect(await clientEvents(realm.id, client.clientId)).toEqual([
      expect.objectContaining({
        type: 'urn:qauth:event:client.updated:v1-rc.0',
        actor_type: 'user',
        actor_id: writer.userId,
        data: { fields: ['name'] },
      }),
    ]);
  });

  it('changes the redirect URIs once a security admin’s change is approved, and only then', async () => {
    const realm = await defaultRealm();
    const client = await storedClient(realm.id, { provisionedByOperator: true });
    const securityAdmin = await adminWith('security-admin');
    const etag = await etagOf(realm.id, client.id, securityAdmin);
    const body = { redirectUris: ['https://stored.example.com/new-callback'] };

    const unapproved = await patchClient(realm.id, client.id, securityAdmin, body, etag);
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });

    // The preview says what the save would need, and writes nothing.
    const preview = await send(
      'POST',
      `${clientPath(realm.id, client.id)}/preview`,
      securityAdmin.token,
      JSON.stringify(body),
      { 'content-type': MERGE_PATCH }
    );
    expect(preview.statusCode, preview.body).toBe(200);
    expect(preview.json()).toMatchObject({
      etag,
      class: 'security',
      approvalRequired: true,
      changes: [{ path: 'redirectUris', direction: 'loosening' }],
    });

    const approvalId = await fileAndApprove(
      realm.id,
      securityAdmin,
      'clients.update',
      { clientId: client.id },
      body
    );
    const done = await patchClient(realm.id, client.id, securityAdmin, body, etag, {
      'qauth-approval': approvalId,
    });
    expect(done.statusCode, done.body).toBe(200);
    expect(done.json<ClientBody>().redirectUris).toEqual([
      'https://stored.example.com/new-callback',
    ]);
    expect(await storedRow(client.id)).toMatchObject({
      redirect_uris: ['https://stored.example.com/new-callback'],
    });
  });

  it("refuses a client token lifetime longer than the realm's, and takes a shorter one as a write", async () => {
    const realm = await defaultRealm();
    const client = await storedClient(realm.id);
    const writer = await adminWith('editor', 'qauth:admin:read qauth:admin:write');
    const etag = await etagOf(realm.id, client.id, writer);

    const longer = await patchClient(
      realm.id,
      client.id,
      writer,
      { accessTokenLifespanSeconds: REALM_ACCESS_LIFETIME + 1 },
      etag
    );
    expect(longer.statusCode, longer.body).toBe(422);
    expect(longer.json()).toMatchObject({
      code: 'unprocessable_content',
      errors: [expect.objectContaining({ pointer: '/accessTokenLifespanSeconds' })],
    });
    const longerRefresh = await patchClient(
      realm.id,
      client.id,
      writer,
      { refreshTokenLifespanSeconds: REALM_REFRESH_LIFETIME + 1 },
      etag
    );
    expect(longerRefresh.statusCode, longerRefresh.body).toBe(422);
    expect(await storedRow(client.id)).toMatchObject({ access_token_lifespan_seconds: null });

    const shorter = await patchClient(
      realm.id,
      client.id,
      writer,
      { accessTokenLifespanSeconds: 300 },
      etag
    );
    expect(shorter.statusCode, shorter.body).toBe(200);
    expect(shorter.json<ClientBody>().accessTokenLifespanSeconds).toBe(300);
    expect(await storedRow(client.id)).toMatchObject({ access_token_lifespan_seconds: 300 });
  });

  it('keeps a CIMD client read-only, and names its document in the refusal', async () => {
    const realm = await defaultRealm();
    const document = `https://app-${randomUUID().slice(0, 8)}.example.com/oauth/client.json`;
    const client = await storedClient(realm.id, {
      clientId: document,
      metadata: { registrationType: 'cimd' },
      tokenEndpointAuthMethod: 'none',
    });
    const securityAdmin = await adminWith('security-admin');

    const read = await send('GET', clientPath(realm.id, client.id), securityAdmin.token);
    expect(read.statusCode, read.body).toBe(200);
    expect(read.json<ClientBody>()).toMatchObject({
      client_id: document,
      metadataDocument: document,
    });
    const etag = String(read.headers['etag']);

    const changed = await patchClient(
      realm.id,
      client.id,
      securityAdmin,
      { name: 'Renamed' },
      etag
    );
    expect(changed.statusCode, changed.body).toBe(409);
    expect(changed.json()).toMatchObject({ code: 'conflict' });
    expect(changed.json<{ detail: string }>().detail).toContain(document);

    const preview = await send(
      'POST',
      `${clientPath(realm.id, client.id)}/preview`,
      securityAdmin.token,
      JSON.stringify({ name: 'Renamed' }),
      { 'content-type': MERGE_PATCH }
    );
    expect(preview.statusCode).toBe(409);
    expect(preview.json<{ detail: string }>().detail).toContain(document);

    const deleted = await send(
      'DELETE',
      clientPath(realm.id, client.id),
      securityAdmin.token,
      undefined,
      {
        'if-match': etag,
      }
    );
    expect(deleted.statusCode).toBe(409);

    // Nor is a change of one filed for an approval.
    const filed = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realm.id}/approvals`,
      securityAdmin.token,
      {
        operation: 'clients.update',
        params: { clientId: client.id },
        body: { redirectUris: ['https://attacker.example/callback'] },
      }
    );
    expect(filed.statusCode).toBe(409);
    expect(filed.json<{ detail: string }>().detail).toContain(document);
    expect(await storedRow(client.id)).toMatchObject({ name: 'Stored client' });
  });

  it('answers 404 for a client of another realm, on every route', async () => {
    const realm = await defaultRealm();
    const elsewhere = await storedClient(await otherRealm());
    const securityAdmin = await adminWith('security-admin');
    const path = clientPath(realm.id, elsewhere.id);

    const responses = [
      await send('GET', path, securityAdmin.token),
      await patchClient(realm.id, elsewhere.id, securityAdmin, { name: 'Taken' }, '*'),
      await send('POST', `${path}/preview`, securityAdmin.token, JSON.stringify({ name: 'x' }), {
        'content-type': MERGE_PATCH,
      }),
      await send('DELETE', path, securityAdmin.token, undefined, { 'if-match': '*' }),
      await send('POST', `${path}/enable`, securityAdmin.token, {}, { 'if-match': '*' }),
      await send('POST', `${path}/disable`, securityAdmin.token, {}, { 'if-match': '*' }),
    ];
    expect(responses.map((response) => response.statusCode)).toEqual([
      404, 404, 404, 404, 404, 404,
    ]);
    expect(await storedRow(elsewhere.id)).toMatchObject({
      name: 'Stored client',
      suspended: false,
    });
  });

  it('registers a client for no developer once approved, answering its secret once and never its hash', async () => {
    const realm = await defaultRealm();
    const securityAdmin = await adminWith('security-admin');
    const body = {
      name: 'Batch reports',
      tokenEndpointAuthMethod: 'client_secret_basic',
      grantTypes: ['client_credentials'],
      scopes: ['reports:read'],
    };

    const unapproved = await send('POST', clientsPath(realm.id), securityAdmin.token, body);
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });

    const approvalId = await fileAndApprove(realm.id, securityAdmin, 'clients.create', {}, body);
    const created = await send('POST', clientsPath(realm.id), securityAdmin.token, body, {
      'qauth-approval': approvalId,
    });
    expect(created.statusCode, created.body).toBe(201);
    const shown = created.json<ClientBody>();
    expect(shown).toMatchObject({
      name: 'Batch reports',
      developerId: null,
      tokenEndpointAuthMethod: 'client_secret_basic',
      suspended: false,
      enabled: true,
    });
    expect(shown.clientSecret).toMatch(/^[0-9a-f]{64}$/);
    expect(created.headers['location']).toBe(clientPath(realm.id, shown.id));
    expect(carriesSecretHash(created)).toBe(false);
    const stored = await storedRow(shown.id);
    expect(created.body).not.toContain(stored?.client_secret_hash);

    // Read again, it carries neither the secret nor its hash.
    const read = await send('GET', clientPath(realm.id, shown.id), securityAdmin.token);
    expect(read.statusCode).toBe(200);
    expect(read.body).not.toContain(String(shown.clientSecret));
    expect(read.body).not.toContain(stored?.client_secret_hash);
    expect(carriesSecretHash(read)).toBe(false);

    expect(await clientEvents(realm.id, shown.client_id)).toEqual([
      expect.objectContaining({
        type: 'urn:qauth:event:client.created:v1-rc.0',
        actor_id: securityAdmin.userId,
        data: expect.objectContaining({ registration: 'admin_api', isPublic: false }),
      }),
    ]);
  });

  it('suspends a client as a write, lifts the suspension only once approved, and deletes it once approved', async () => {
    const realm = await defaultRealm();
    const client = await storedClient(realm.id);
    const editor = await adminWith('editor', 'qauth:admin:read qauth:admin:write');
    const securityAdmin = await adminWith('security-admin');

    const unnamed = await send(
      'POST',
      `${clientPath(realm.id, client.id)}/disable`,
      editor.token,
      {}
    );
    expect(unnamed.statusCode).toBe(428);
    const suspended = await send(
      'POST',
      `${clientPath(realm.id, client.id)}/disable`,
      editor.token,
      {},
      { 'if-match': await etagOf(realm.id, client.id, editor) }
    );
    expect(suspended.statusCode, suspended.body).toBe(200);
    expect(suspended.json<ClientBody>().suspended).toBe(true);
    expect(await storedRow(client.id)).toMatchObject({ suspended: true });

    const etag = String(suspended.headers['etag']);
    const byEditor = await send(
      'POST',
      `${clientPath(realm.id, client.id)}/enable`,
      editor.token,
      {},
      {
        'if-match': etag,
      }
    );
    expect(byEditor.statusCode).toBe(403);
    const enableApproval = await fileAndApprove(
      realm.id,
      securityAdmin,
      'clients.enable',
      { clientId: client.id },
      {}
    );
    const enabled = await send(
      'POST',
      `${clientPath(realm.id, client.id)}/enable`,
      securityAdmin.token,
      {},
      { 'if-match': etag, 'qauth-approval': enableApproval }
    );
    expect(enabled.statusCode, enabled.body).toBe(200);
    expect(enabled.json<ClientBody>().suspended).toBe(false);

    const current = String(enabled.headers['etag']);
    const deleteApproval = await fileAndApprove(realm.id, securityAdmin, 'clients.delete', {
      clientId: client.id,
    });
    const deleted = await send(
      'DELETE',
      clientPath(realm.id, client.id),
      securityAdmin.token,
      undefined,
      {
        'if-match': current,
        'qauth-approval': deleteApproval,
      }
    );
    expect(deleted.statusCode, deleted.body).toBe(204);
    expect(await storedRow(client.id)).toBeUndefined();
    expect(
      (await send('GET', clientPath(realm.id, client.id), securityAdmin.token)).statusCode
    ).toBe(404);
    expect((await clientEvents(realm.id, client.clientId)).map((event) => event.type)).toEqual([
      'urn:qauth:event:client.suspended:v1-rc.0',
      'urn:qauth:event:client.suspension_lifted:v1-rc.0',
      'urn:qauth:event:client.deleted:v1-rc.0',
    ]);
  });

  it('treats every change of a client that obtains admin tokens as a security change', async () => {
    const realm = await defaultRealm();
    const console = await storedClient(realm.id, {
      scopes: ['openid', 'qauth:admin:read', 'qauth:admin:security'],
    });
    const editor = await adminWith('editor', 'qauth:admin:read qauth:admin:write');
    const etag = await etagOf(realm.id, console.id, editor);

    const renamed = await patchClient(realm.id, console.id, editor, { name: 'Console' }, etag);
    expect(renamed.statusCode).toBe(403);
    const suspended = await send(
      'POST',
      `${clientPath(realm.id, console.id)}/disable`,
      editor.token,
      {},
      { 'if-match': etag }
    );
    expect(suspended.statusCode).toBe(403);
    expect(await storedRow(console.id)).toMatchObject({ name: 'Stored client', suspended: false });
  });
});
