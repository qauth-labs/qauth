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
 * THE RESOURCE SERVER OPERATIONS OF THE ADMIN API (#1087, ADR-019 Decision 7),
 * against a real Postgres and Redis: a realm's resource servers listed and
 * read, never another realm's; the write scope refused every one of their
 * writes; a registration, a change and a deletion run only once approved, each
 * against the version its If-Match names, and each recorded in the realm's
 * admin audit chain; a second registration of one indicator refused with 409;
 * a change of the indicator refused with 422, as its preview is.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const MERGE_PATCH = 'application/merge-patch+json';

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

interface ResourceServerBody {
  id: string;
  resource: string;
  scopes: { scope: string; text: Record<string, string>; sensitive: boolean }[];
  clients: 'any_client' | string[];
  version: number;
}

interface AuditRow {
  operation_id: string;
  operation_class: string;
  outcome: string;
  masked_diff: unknown;
}

const NOTES_READ = { scope: 'notes:read', text: { en: 'Read your notes', de: 'Notizen lesen' } };
const NOTES_DELETE = { scope: 'notes:delete', text: { en: 'Delete your notes' }, sensitive: true };

describe('the admin resource server operations (#1087, real containers)', () => {
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

  /** A resource server stored as the seed manifest stores one. */
  async function storedResourceServer(
    realmId: string,
    resource = `https://${randomUUID()}.example.com/mcp`
  ) {
    const row = await app().repositories.protectedResources.create(realmId, resource, {
      scopes: [{ ...NOTES_READ, sensitive: false }],
      anyClient: false,
      clientIds: ['notes-app'],
    });
    if (row === undefined) throw new Error('the resource server was not stored');
    return row;
  }

  const serversPath = (realmId: string) => `/admin/v1-rc.0/realms/${realmId}/resource-servers`;
  const serverPath = (realmId: string, id: string) => `${serversPath(realmId)}/${id}`;

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

  /** A merge patch of the resource server, naming `etag` in If-Match. */
  const patchServer = (
    realmId: string,
    id: string,
    by: Admin,
    body: Record<string, unknown>,
    etag: string,
    headers: Record<string, string> = {}
  ) =>
    send('PATCH', serverPath(realmId, id), by.token, JSON.stringify(body), {
      'content-type': MERGE_PATCH,
      'if-match': etag,
      ...headers,
    });

  /** The resource server's ETag, as resourceServers.get answers it. */
  async function etagOf(realmId: string, id: string, by: Admin): Promise<string> {
    const read = await send('GET', serverPath(realmId, id), by.token);
    expect(read.statusCode, read.body).toBe(200);
    const etag = read.headers['etag'];
    if (typeof etag !== 'string') throw new Error('resourceServers.get answered no ETag');
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
        reason: 'The operator asked for it in ticket OPS-1087.',
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

  async function auditRows(realmId: string, operationId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT operation_id, operation_class, outcome, masked_diff
         FROM admin_audit_log WHERE realm_id = $1 AND operation_id = $2 ORDER BY seq`,
      [realmId, operationId]
    );
    return rows;
  }

  it("lists and reads the realm's resource servers, never another realm's, and answers 404 for one of another realm on every route", async () => {
    const realm = await defaultRealm();
    const own = await storedResourceServer(realm.id);
    const elsewhere = await storedResourceServer(await otherRealm());
    const viewer = await adminWith('viewer', 'qauth:admin:read');

    const listed = await send('GET', `${serversPath(realm.id)}?limit=100`, viewer.token);
    expect(listed.statusCode, listed.body).toBe(200);
    expect(listed.headers['cache-control']).toBe('no-store');
    const ids = listed.json<{ items: ResourceServerBody[] }>().items.map((item) => item.id);
    expect(ids).toContain(own.id);
    expect(ids).not.toContain(elsewhere.id);

    const read = await send('GET', serverPath(realm.id, own.id), viewer.token);
    expect(read.statusCode, read.body).toBe(200);
    expect(read.headers['etag']).toBe('"1"');
    expect(read.json<ResourceServerBody>()).toMatchObject({
      resource: own.resource,
      scopes: [{ ...NOTES_READ, sensitive: false }],
      clients: ['notes-app'],
      version: 1,
    });

    const securityAdmin = await adminWith('security-admin');
    const path = serverPath(realm.id, elsewhere.id);
    const responses = [
      await send('GET', path, securityAdmin.token),
      await patchServer(realm.id, elsewhere.id, securityAdmin, { clients: 'any_client' }, '*'),
      await send('POST', `${path}/preview`, securityAdmin.token, JSON.stringify({}), {
        'content-type': MERGE_PATCH,
      }),
      await send('DELETE', path, securityAdmin.token, undefined, { 'if-match': '*' }),
    ];
    expect(responses.map((response) => response.statusCode)).toEqual([404, 404, 404, 404]);
    expect(
      (await app().repositories.protectedResources.findById(elsewhere.realmId, elsewhere.id))
        ?.version
    ).toBe(1);
  });

  it('refuses qauth:admin:write every write of a resource server', async () => {
    const realm = await defaultRealm();
    const stored = await storedResourceServer(realm.id);
    // A security admin's role holds every permission; its token's scopes stop at write.
    const writer = await adminWith('security-admin', 'qauth:admin:read qauth:admin:write');
    const etag = await etagOf(realm.id, stored.id, writer);

    const refused = [
      await send('POST', serversPath(realm.id), writer.token, {
        resource: 'https://writer.example.com/mcp',
        scopes: [NOTES_READ],
        clients: 'any_client',
      }),
      await patchServer(realm.id, stored.id, writer, { clients: 'any_client' }, etag),
      await send('DELETE', serverPath(realm.id, stored.id), writer.token, undefined, {
        'if-match': etag,
      }),
    ];
    for (const response of refused) {
      expect(response.statusCode, response.body).toBe(403);
      expect(response.headers['www-authenticate']).toContain('error="insufficient_scope"');
      expect(response.headers['www-authenticate']).toContain('qauth:admin:security');
    }
    expect(
      (await app().repositories.protectedResources.findById(realm.id, stored.id))?.version
    ).toBe(1);
  });

  it('registers a resource server once approved, and refuses a second one for the same indicator with 409', async () => {
    const realm = await defaultRealm();
    const securityAdmin = await adminWith('security-admin');
    const body = {
      resource: `https://${randomUUID()}.example.com/mcp`,
      scopes: [NOTES_READ, NOTES_DELETE],
      clients: ['notes-app', 'https://agent.example.com/client.json'],
    };

    const unapproved = await send('POST', serversPath(realm.id), securityAdmin.token, body);
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });

    // What the approver is shown: every scope, text and client, each whole.
    const approvalId = await fileAndApprove(
      realm.id,
      securityAdmin,
      'resourceServers.create',
      {},
      body
    );
    const shown = await send(
      'GET',
      `/admin/v1-rc.0/realms/${realm.id}/approvals/${approvalId}`,
      securityAdmin.token
    );
    expect(shown.statusCode, shown.body).toBe(200);
    for (const value of [
      body.resource,
      'notes:read — Notizen lesen',
      'notes:delete — Delete your notes',
      'https://agent.example.com/client.json',
    ]) {
      expect(shown.body).toContain(value);
    }

    const created = await send('POST', serversPath(realm.id), securityAdmin.token, body, {
      'qauth-approval': approvalId,
    });
    expect(created.statusCode, created.body).toBe(201);
    const server = created.json<ResourceServerBody>();
    expect(server).toMatchObject({
      resource: body.resource,
      scopes: [
        { ...NOTES_READ, sensitive: false },
        { ...NOTES_DELETE, sensitive: true },
      ],
      clients: body.clients,
      version: 1,
    });
    expect(created.headers['location']).toBe(serverPath(realm.id, server.id));
    expect(created.headers['etag']).toBe('"1"');
    // The refused call is audited too, as denied; the applied one as succeeded.
    const createRows = await auditRows(realm.id, 'resourceServers.create');
    expect(createRows.map((row) => row.outcome)).toEqual(['denied', 'succeeded']);
    expect(createRows.at(-1)).toMatchObject({ operation_class: 'security' });

    const again = await fileAndApprove(realm.id, securityAdmin, 'resourceServers.create', {}, body);
    const duplicate = await send('POST', serversPath(realm.id), securityAdmin.token, body, {
      'qauth-approval': again,
    });
    expect(duplicate.statusCode, duplicate.body).toBe(409);
    expect(duplicate.json()).toMatchObject({ code: 'already_exists' });
    expect(await app().repositories.protectedResources.listByRealm(realm.id)).toHaveLength(1);
  });

  it('previews a change, refuses one of the indicator, and changes the scopes once approved against the version it names', async () => {
    const realm = await defaultRealm();
    const stored = await storedResourceServer(realm.id);
    const securityAdmin = await adminWith('security-admin');
    const etag = await etagOf(realm.id, stored.id, securityAdmin);
    const body = { scopes: [NOTES_READ, NOTES_DELETE], clients: 'any_client' };

    const preview = await send(
      'POST',
      `${serverPath(realm.id, stored.id)}/preview`,
      securityAdmin.token,
      JSON.stringify(body),
      { 'content-type': MERGE_PATCH }
    );
    expect(preview.statusCode, preview.body).toBe(200);
    expect(preview.json()).toMatchObject({
      etag,
      class: 'security',
      effects: ['token-content'],
      approvalRequired: true,
      changes: [
        { path: 'scopes', direction: 'loosening' },
        { path: 'clients', direction: 'loosening', before: ['notes-app'], after: 'any_client' },
      ],
    });

    // The indicator never changes: neither the save nor its preview nor a
    // filing takes it.
    const moved = { resource: 'https://moved.example.com/mcp' };
    const refused = [
      await patchServer(realm.id, stored.id, securityAdmin, moved, etag),
      await send(
        'POST',
        `${serverPath(realm.id, stored.id)}/preview`,
        securityAdmin.token,
        JSON.stringify(moved),
        { 'content-type': MERGE_PATCH }
      ),
      await send('POST', `/admin/v1-rc.0/realms/${realm.id}/approvals`, securityAdmin.token, {
        operation: 'resourceServers.update',
        params: { resourceServerId: stored.id },
        body: moved,
      }),
    ];
    for (const response of refused) {
      expect(response.statusCode, response.body).toBe(422);
      expect(response.json()).toMatchObject({
        code: 'unprocessable_content',
        errors: [expect.objectContaining({ pointer: '/resource' })],
      });
    }

    const unapproved = await patchServer(realm.id, stored.id, securityAdmin, body, etag);
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });
    const noVersion = await send(
      'PATCH',
      serverPath(realm.id, stored.id),
      securityAdmin.token,
      JSON.stringify(body),
      { 'content-type': MERGE_PATCH }
    );
    expect(noVersion.statusCode).toBe(428);

    const approvalId = await fileAndApprove(
      realm.id,
      securityAdmin,
      'resourceServers.update',
      { resourceServerId: stored.id },
      body
    );
    const done = await patchServer(realm.id, stored.id, securityAdmin, body, etag, {
      'qauth-approval': approvalId,
    });
    expect(done.statusCode, done.body).toBe(200);
    expect(done.headers['etag']).toBe('"2"');
    expect(done.json<ResourceServerBody>()).toMatchObject({
      clients: 'any_client',
      version: 2,
      scopes: [
        { ...NOTES_READ, sensitive: false },
        { ...NOTES_DELETE, sensitive: true },
      ],
    });
    const row = await app().repositories.protectedResources.findById(realm.id, stored.id);
    expect(row).toMatchObject({ anyClient: true, clientIds: [], version: 2 });
    // The moved indicator (422), the call with no approval (403) and the one
    // with no If-Match (428) are audited as denied; the applied one as
    // succeeded. Neither the previews nor the filing is an update call.
    const updateRows = await auditRows(realm.id, 'resourceServers.update');
    expect(updateRows.map((row) => row.outcome)).toEqual([
      'denied',
      'denied',
      'denied',
      'succeeded',
    ]);
    expect(updateRows.at(-1)).toMatchObject({ operation_class: 'security' });

    // The old version is gone: a save against it is 412.
    const stale = await patchServer(realm.id, stored.id, securityAdmin, { clients: ['a'] }, etag);
    expect(stale.statusCode).toBe(412);
  });

  it('deletes a resource server once approved, and only then', async () => {
    const realm = await defaultRealm();
    const stored = await storedResourceServer(realm.id);
    const securityAdmin = await adminWith('security-admin');
    const etag = await etagOf(realm.id, stored.id, securityAdmin);

    const unapproved = await send(
      'DELETE',
      serverPath(realm.id, stored.id),
      securityAdmin.token,
      undefined,
      { 'if-match': etag }
    );
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });

    const approvalId = await fileAndApprove(realm.id, securityAdmin, 'resourceServers.delete', {
      resourceServerId: stored.id,
    });
    const deleted = await send(
      'DELETE',
      serverPath(realm.id, stored.id),
      securityAdmin.token,
      undefined,
      { 'if-match': etag, 'qauth-approval': approvalId }
    );
    expect(deleted.statusCode, deleted.body).toBe(204);
    expect(await app().repositories.protectedResources.findById(realm.id, stored.id)).toBe(
      undefined
    );
    expect(
      (await send('GET', serverPath(realm.id, stored.id), securityAdmin.token)).statusCode
    ).toBe(404);
    // The call with no approval is audited as denied; the applied one as succeeded.
    const deleteRows = await auditRows(realm.id, 'resourceServers.delete');
    expect(deleteRows.map((row) => row.outcome)).toEqual(['denied', 'succeeded']);
    expect(deleteRows.at(-1)).toMatchObject({ operation_class: 'security' });
  });
});
