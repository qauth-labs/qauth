import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

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
 * APPROVALS FOR SECURITY OPERATIONS (#512, ADR-019 Decision 7), against a
 * real Postgres and Redis.
 *
 * The suite boots the real app with the admin listener beside it and puts a
 * fixture security operation behind the real pipeline: it rotates a "key" by
 * creating an account in its realm, the change it can be seen to make, and
 * can be held open or made to fail after its change. The approval page and
 * the passkey factor do not exist yet (#617, #623), so approvals are given by
 * calling the approval engine with the test factor, as the page will.
 *
 * Each test acts on realms of its own: the audit log refuses `TRUNCATE`, so
 * its rows stay, and are read per realm.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');

/** What the fixture handler saw, and how the test steers it. */
const runs: string[] = [];
const steer: {
  failAfterChange: boolean;
  entered?: () => void;
  release?: Promise<void>;
} = { failAfterChange: false };

/**
 * The registry the last boot's admin listener classifies against: the engine
 * renders an approval's operation from it, as the approval page will from the
 * server's own.
 */
const fixture: { registry?: Awaited<ReturnType<typeof fixtureAdminApi>>['registry'] } = {};

/** The fixture operations and routes, imported once the boot reset the modules. */
async function fixtureAdminApi(options: { renderer: boolean } = { renderer: true }) {
  const operations = await import('./helpers/admin-operations');
  const { adminTransaction, recordAdminChange, requestAdminCaller } =
    await import('./admin/pipeline');

  const rotate = operations.defineOperation({
    id: 'fixtureKeys.rotate',
    class: 'security',
    effects: ['key-custody'],
    permissions: ['realms.policies.security'],
    description: 'Rotate a key of the realm (fixture).',
    ...(options.renderer
      ? {
          render: (request: { params: unknown; body: unknown }) => {
            const { keyId } = request.params as { keyId: string };
            const { retireAfterDays } = request.body as { retireAfterDays: number };
            return {
              title: `Rotate the signing key ${keyId}`,
              fields: [{ label: 'Retire the old key after', value: `${retireAfterDays} days` }],
            };
          },
        }
      : {}),
  });
  // A security operation whose route has no query or body schema: Fastify
  // hands its handler the router's and the query parser's own objects.
  const retire = operations.defineOperation({
    id: 'fixtureKeys.retire',
    class: 'security',
    effects: ['key-custody'],
    permissions: ['realms.policies.security'],
    description: 'Retire a key of the realm (fixture).',
    render: (request: { params: unknown }) => ({
      title: `Retire the signing key ${(request.params as { keyId: string }).keyId}`,
    }),
  });
  const registry = operations.createAdminOperationRegistry([rotate, retire], { reserved: [] });
  fixture.registry = registry;

  return {
    registry,
    routes: (scope: FastifyInstance) => {
      scope.post(
        '/admin/v1-rc.0/realms/:realmId/fixture-keys/:keyId/rotate',
        {
          config: { operation: rotate.id },
          schema: {
            ...operations.operationSchemaExtensions(rotate),
            'x-qauth-stability': 'experimental',
            'x-qauth-errors': [400, 401, 403, 404],
            security: [{ bearerAuth: [] }],
            params: z.object({ realmId: z.uuid(), keyId: z.string().min(1).max(64) }),
            querystring: z.strictObject({ dryRun: z.enum(['true', 'false']).optional() }),
            body: z.strictObject({ retireAfterDays: z.int().min(1).max(30) }),
          },
        },
        async (request) => {
          runs.push(rotate.id);
          steer.entered?.();
          await steer.release;
          const realmId = requestAdminCaller(request).targetRealm.id;
          const account = await request.server.repositories.users.create(
            { realmId },
            adminTransaction(request)
          );
          if (steer.failAfterChange) throw new Error('the fixture failed after its change');
          recordAdminChange(request, {
            change: { before: null, after: { id: account.id } },
            annotations: {},
          });
          return { rotated: true };
        }
      );
      // A second route that names the engine's own filing operation: only the
      // approvals route itself passes the gate without an approval.
      scope.route({
        method: 'HEAD',
        url: '/admin/v1-rc.0/realms/:realmId/fixture-approvals',
        config: { operation: 'approvals.create' },
        schema: {
          ...operations.operationSchemaExtensions(
            registry.get('approvals.create') as Parameters<
              typeof operations.operationSchemaExtensions
            >[0]
          ),
          hide: true,
          params: z.object({ realmId: z.uuid() }),
        },
        handler: async () => {
          runs.push('approvals.create:head');
          return {};
        },
      });
      scope.post(
        '/admin/v1-rc.0/realms/:realmId/fixture-keys/:keyId/retire',
        {
          config: { operation: retire.id },
          schema: {
            ...operations.operationSchemaExtensions(retire),
            'x-qauth-stability': 'experimental',
            'x-qauth-errors': [400, 401, 403, 404],
            security: [{ bearerAuth: [] }],
            params: z.object({ realmId: z.uuid(), keyId: z.string().min(1).max(64) }),
          },
        },
        async (request) => {
          runs.push(retire.id);
          return { retired: (request.query as { note?: string }).note ?? null };
        }
      );
    },
  };
}

interface AuditRow {
  seq: string;
  actor_id: string;
  operation_id: string;
  operation_class: string;
  effects: string[];
  outcome: string;
  approvals: Array<{ approverId: string; credentialId: string; approvedAt: number }>;
  request_digest: Buffer | null;
}

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

function bootWithAdminListener(
  adminListener: () => ReturnType<typeof fixtureAdminApi> = fixtureAdminApi
): Promise<BootedAuthServer> {
  if (!infra || !jwt) throw new Error('no infrastructure');
  return bootAuthServer(
    { ...baseEnvironment(infra, jwt), ADMIN_API_ENABLED: 'true' },
    { adminListener }
  );
}

describe('approvals for security operations (#512, real containers)', () => {
  let booted: BootedAuthServer | undefined;
  let test: TestApprovalFactor;

  beforeAll(async () => {
    if (!dockerUp) return;
    booted = await bootWithAdminListener();
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
    runs.length = 0;
    steer.failAfterChange = false;
    steer.entered = undefined;
    steer.release = undefined;
    // Imported once the boot reset the modules, as the engine is: the factor's
    // refusal is then the class the engine knows.
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

  async function operatorRealm(): Promise<{ id: string; issuer: string }> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer) throw new Error('default realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  async function tenant(name: string): Promise<string> {
    const host = `${name}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    return realm.id;
  }

  /** An operator-realm admin with `role` on `realmId`: its token and its account as an approver. */
  async function adminWith(
    realmId: string,
    role: 'viewer' | 'editor' | 'security-admin',
    scope = ALL_ADMIN_SCOPES
  ) {
    const operator = await operatorRealm();
    const userId = (await app().repositories.users.create({ realmId: operator.id })).id;
    await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: role },
      targetRealmId: realmId,
      createdBy: null,
    });
    const token = await app().jwtUtils.signAccessToken(operator, {
      sub: userId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope,
    });
    return { userId, token, approver: { realmId: operator.id, accountId: userId } };
  }

  function post(
    url: string,
    token: string,
    payload?: unknown,
    headers: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    return admin().inject({
      method: 'POST',
      url,
      headers: { authorization: `Bearer ${token}`, ...headers },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });
  }

  function get(url: string, token: string): Promise<LightMyRequestResponse> {
    return admin().inject({ method: 'GET', url, headers: { authorization: `Bearer ${token}` } });
  }

  const approvals = (realmId: string, suffix = '') =>
    `/admin/v1-rc.0/realms/${realmId}/approvals${suffix}`;
  const rotateUrl = (realmId: string, keyId = 'signing-1', query = '?dryRun=false') =>
    `/admin/v1-rc.0/realms/${realmId}/fixture-keys/${keyId}/rotate${query}`;
  const ROTATION = { retireAfterDays: 7 };

  /** File the approval of the fixture rotation, as the requester. */
  async function file(realmId: string, token: string, extra: Record<string, unknown> = {}) {
    const response = await post(approvals(realmId), token, {
      operation: 'fixtureKeys.rotate',
      params: { keyId: 'signing-1' },
      query: { dryRun: 'false' },
      body: ROTATION,
      ...extra,
    });
    expect(response.statusCode, response.body).toBe(201);
    return response.json<{ id: string; status: string; approvalUrl: string }>();
  }

  /** Give `approvalId` an approval with the test factor, as the approval page will. */
  async function approve(
    realmId: string,
    approvalId: string,
    approver: { realmId: string; accountId: string }
  ) {
    const engine = await import('./admin/approvals/engine');
    const decision = { realmId, approvalId, approver, sessionIssuedAtMs: Date.now() };
    const { challenge } = await engine.startApproval(app(), test.factor, decision, engineOptions());
    return engine.completeApproval(
      app(),
      test.factor,
      { ...decision, response: test.answer(challenge, approver) },
      engineOptions()
    );
  }

  const engineOptions = () => ({ ...(fixture.registry ? { registry: fixture.registry } : {}) });

  async function auditRows(realmId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT seq::text AS seq, actor_id, operation_id, operation_class, effects, outcome,
              approvals, request_digest
         FROM admin_audit_log WHERE realm_id = $1 ORDER BY admin_audit_log.seq`,
      [realmId]
    );
    return rows;
  }

  async function storedApproval(approvalId: string) {
    const { rows } = await app().dbPool.query<{ status: string; op_hash: Buffer }>(
      'SELECT status, op_hash FROM admin_approvals WHERE id = $1',
      [approvalId]
    );
    return rows[0];
  }

  async function accountsIn(realmId: string): Promise<number> {
    const { rows } = await app().dbPool.query<{ count: string }>(
      'SELECT count(*) FROM users WHERE realm_id = $1',
      [realmId]
    );
    return Number(rows[0].count);
  }

  // Acceptance criterion: with the test factor, a human requester can run a
  // security fixture operation end to end.
  it('runs a security operation end to end: refused, filed, approved with the factor, retried once', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const operator = await operatorRealm();

    // 1. Without an approval, the operation does not run.
    const refused = await post(rotateUrl(realmId), requester.token, ROTATION);
    expect(refused.statusCode).toBe(403);
    expect(refused.json()).toMatchObject({ code: 'approval_required' });
    expect(runs).toEqual([]);

    // 2. The requester files an approval for the same request.
    const created = await post(approvals(realmId), requester.token, {
      operation: 'fixtureKeys.rotate',
      params: { keyId: 'signing-1' },
      query: { dryRun: 'false' },
      body: ROTATION,
      reason: 'Quarterly rotation <b>now</b>',
    });
    expect(created.statusCode, created.body).toBe(201);
    const filed = created.json<Record<string, unknown> & { id: string }>();
    expect(created.headers['etag']).toBe('"pending.0"');
    expect(created.headers['location']).toBe(approvals(realmId, `/${filed.id}`));
    expect(filed).toMatchObject({
      realmId,
      status: 'pending',
      operation: 'fixtureKeys.rotate',
      method: 'POST',
      params: { realmId, keyId: 'signing-1' },
      query: { dryRun: 'false' },
      reason: 'Quarterly rotation <b>now</b>',
      requester: { kind: 'human', realmId: operator.id, accountId: requester.userId },
      approvalsRequired: 1,
      approvals: [],
      usedAt: null,
      approvalUrl: `${operator.issuer}/approvals/${filed.id}`,
      display: {
        operation: 'fixtureKeys.rotate',
        title: 'Rotate the signing key signing-1',
        fields: [{ label: 'Retire the old key after', value: '7 days' }],
        reason: { type: 'quote', source: 'requester', text: 'Quarterly rotation <b>now</b>' },
      },
    });
    // The body is not part of the representation.
    expect(filed).not.toHaveProperty('body');
    const expiresIn =
      Date.parse(String(filed['expiresAt'])) - Date.parse(String(filed['createdAt']));
    expect(expiresIn).toBe(5 * 60_000);

    // 3. The requester's own fresh step-up, with the factor, approves it.
    const approved = await approve(realmId, filed.id, requester.approver);
    expect(approved.status).toBe('approved');

    // 4. The client reads where it stands.
    const read = await get(approvals(realmId, `/${filed.id}`), requester.token);
    expect(read.statusCode).toBe(200);
    expect(read.headers['etag']).toBe('"approved.1"');
    expect(read.json()).toMatchObject({
      status: 'approved',
      approvals: [
        {
          realmId: operator.id,
          accountId: requester.userId,
          credential: test.credentialOf(requester.approver),
          factor: 'test',
        },
      ],
    });

    // 5. The retry runs once, with the approval.
    const ran = await post(rotateUrl(realmId), requester.token, ROTATION, {
      'qauth-approval': filed.id,
    });
    expect(ran.statusCode, ran.body).toBe(200);
    expect(ran.json()).toEqual({ rotated: true });
    expect(runs).toEqual(['fixtureKeys.rotate']);
    expect(await accountsIn(realmId)).toBe(1);
    const consumed = await get(approvals(realmId, `/${filed.id}`), requester.token);
    expect(consumed.json()).toMatchObject({ status: 'consumed', display: null });
    expect(consumed.json<{ usedAt: string | null }>().usedAt).not.toBeNull();
    // The body it was filed with is no longer kept.
    const { rows } = await app().dbPool.query<{ body: unknown }>(
      `SELECT canonical_request -> 'body' AS body FROM admin_approvals WHERE id = $1`,
      [filed.id]
    );
    expect(rows[0].body).toBeNull();

    // A consumed approval runs nothing again.
    const again = await post(rotateUrl(realmId), requester.token, ROTATION, {
      'qauth-approval': filed.id,
    });
    expect(again.statusCode).toBe(403);
    expect(again.json()).toMatchObject({ code: 'approval_required' });
    expect(runs).toEqual(['fixtureKeys.rotate']);
  });

  it('runs an operation whose route parses no query or body, the query as the URL carries it', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const created = await post(approvals(realmId), requester.token, {
      operation: 'fixtureKeys.retire',
      params: { keyId: 'signing-1' },
      query: { note: 'end of life' },
    });
    expect(created.statusCode, created.body).toBe(201);
    const { id } = created.json<{ id: string }>();
    await approve(realmId, id, requester.approver);
    const url = `/admin/v1-rc.0/realms/${realmId}/fixture-keys/signing-1/retire`;
    const other = await post(`${url}?note=another`, requester.token, undefined, {
      'qauth-approval': id,
    });
    expect(other.statusCode).toBe(403);
    const ran = await post(`${url}?note=end%20of%20life`, requester.token, undefined, {
      'qauth-approval': id,
    });
    expect(ran.statusCode, ran.body).toBe(200);
    expect(ran.json()).toEqual({ retired: 'end of life' });
    expect(runs).toEqual(['fixtureKeys.retire']);
  });

  it("gates another route that names the engine's own filing operation", async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const response = await admin().inject({
      method: 'HEAD',
      url: `/admin/v1-rc.0/realms/${realmId}/fixture-approvals`,
      headers: { authorization: `Bearer ${requester.token}` },
    });
    expect(response.statusCode).toBe(403);
    expect(runs).toEqual([]);
  });

  it('refuses a retry whose body, path parameter or query differs from the request filed', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const filed = await file(realmId, requester.token);
    await approve(realmId, filed.id, requester.approver);
    const header = { 'qauth-approval': filed.id };

    for (const [url, body] of [
      [rotateUrl(realmId), { retireAfterDays: 8 }],
      [rotateUrl(realmId, 'signing-2'), ROTATION],
      [rotateUrl(realmId, 'signing-1', '?dryRun=true'), ROTATION],
      [rotateUrl(realmId, 'signing-1', ''), ROTATION],
    ] as const) {
      const response = await post(url, requester.token, body, header);
      expect(response.statusCode, url).toBe(403);
      expect(response.json()).toMatchObject({ code: 'approval_required' });
    }
    // Another security admin cannot use it either: it was filed by the requester.
    const other = await adminWith(realmId, 'security-admin');
    expect((await post(rotateUrl(realmId), other.token, ROTATION, header)).statusCode).toBe(403);
    expect(runs).toEqual([]);
    expect((await storedApproval(filed.id))?.status).toBe('approved');
  });

  // Acceptance criterion: two concurrent executions with one approval, exactly
  // one succeeds.
  it('lets exactly one of two concurrent retries run on one approval', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const filed = await file(realmId, requester.token);
    await approve(realmId, filed.id, requester.approver);
    const header = { 'qauth-approval': filed.id };

    // The first retry consumes the approval and is held inside its
    // transaction; the second passes the gate's read, then waits on the row.
    let release: () => void = () => undefined;
    steer.release = new Promise<void>((resolve) => {
      release = resolve;
    });
    const entered = new Promise<void>((resolve) => {
      steer.entered = resolve;
    });
    const first = post(rotateUrl(realmId), requester.token, ROTATION, header);
    await entered;
    steer.entered = undefined;
    const second = post(rotateUrl(realmId), requester.token, ROTATION, header);
    await waitFor(async () => (await waitingOnLocks()) >= 1);
    release();

    const statuses = (await Promise.all([first, second])).map((response) => response.statusCode);
    expect(statuses).toEqual([200, 403]);
    expect(runs).toEqual(['fixtureKeys.rotate']);
    expect(await accountsIn(realmId)).toBe(1);
    expect((await storedApproval(filed.id))?.status).toBe('consumed');
  });

  // Acceptance criterion: a rolled-back operation leaves the approval unconsumed.
  it('leaves the approval approved when the operation rolls back, so the retry can use it', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const filed = await file(realmId, requester.token);
    await approve(realmId, filed.id, requester.approver);
    const header = { 'qauth-approval': filed.id };

    steer.failAfterChange = true;
    const failed = await post(rotateUrl(realmId), requester.token, ROTATION, header);
    expect(failed.statusCode).toBe(500);
    expect(await accountsIn(realmId)).toBe(0);
    expect((await storedApproval(filed.id))?.status).toBe('approved');

    steer.failAfterChange = false;
    const ran = await post(rotateUrl(realmId), requester.token, ROTATION, header);
    expect(ran.statusCode).toBe(200);
    expect(await accountsIn(realmId)).toBe(1);
    expect((await storedApproval(filed.id))?.status).toBe('consumed');
  });

  // Acceptance criterion: a reader who is neither requester nor eligible
  // approver gets 404.
  it('answers 404 to a reader who is neither its requester nor an eligible approver, as for no approval', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const filed = await file(realmId, requester.token);
    // A viewer may read approvals, but neither filed this one nor may approve
    // it; a security admin may approve others' requests, but nobody but the
    // requester gives this one's only approval.
    const viewer = await adminWith(realmId, 'viewer');
    const securityAdmin = await adminWith(realmId, 'security-admin');
    const missing = '7d0f3b6e-2c1a-4e5f-9a8b-0c1d2e3f4a5b';

    const comparable = (response: LightMyRequestResponse, id: string) => {
      const body = { ...response.json<Record<string, unknown>>() };
      delete body['trace_id'];
      return { status: response.statusCode, body: JSON.stringify(body).replaceAll(id, '<id>') };
    };
    const unknown = comparable(await get(approvals(realmId, `/${missing}`), viewer.token), missing);
    expect(unknown.status).toBe(404);
    for (const reader of [viewer, securityAdmin]) {
      const response = await get(approvals(realmId, `/${filed.id}`), reader.token);
      expect(comparable(response, filed.id)).toEqual(unknown);
    }
    // Withdrawing it is refused the same way, before any permission check.
    const cancel = await post(
      approvals(realmId, `/${filed.id}/cancel`),
      securityAdmin.token,
      undefined,
      {
        'if-match': '"pending.0"',
      }
    );
    expect(cancel.statusCode).toBe(404);
    // The requester reads it.
    expect((await get(approvals(realmId, `/${filed.id}`), requester.token)).statusCode).toBe(200);
  });

  it('takes a required second approval only from a different human admin who may approve', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const filed = await file(realmId, requester.token);
    // The two-admin rule (#521) sets this; the engine already honours it.
    await app().dbPool.query('UPDATE admin_approvals SET approvals_required = 2 WHERE id = $1', [
      filed.id,
    ]);
    const second = await adminWith(realmId, 'security-admin');
    const editor = await adminWith(realmId, 'editor');

    expect((await approve(realmId, filed.id, requester.approver)).status).toBe('pending');
    // The requester cannot give the second one, an admin without
    // approvals.approve can neither read nor give it.
    await expect(approve(realmId, filed.id, requester.approver)).rejects.toMatchObject({
      statusCode: 403,
    });
    await expect(approve(realmId, filed.id, editor.approver)).rejects.toMatchObject({
      statusCode: 404,
    });
    // A security admin who may approve now reads it.
    expect((await get(approvals(realmId, `/${filed.id}`), second.token)).statusCode).toBe(200);
    const done = await approve(realmId, filed.id, second.approver);
    expect(done.status).toBe('approved');
    expect(done.approvals.map((given) => given.approverId)).toEqual([
      requester.userId,
      second.userId,
    ]);

    const ran = await post(rotateUrl(realmId), requester.token, ROTATION, {
      'qauth-approval': filed.id,
    });
    expect(ran.statusCode).toBe(200);
    const row = (await auditRows(realmId)).at(-1);
    expect(row?.approvals.map((given) => given.approverId)).toEqual([
      requester.userId,
      second.userId,
    ]);
  });

  it('takes an approver whose ids come in upper case as the account they name', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const filed = await file(realmId, requester.token);
    await app().dbPool.query('UPDATE admin_approvals SET approvals_required = 2 WHERE id = $1', [
      filed.id,
    ]);
    const engine = await import('./admin/approvals/engine');
    const shouted = {
      realmId: requester.approver.realmId.toUpperCase(),
      accountId: requester.approver.accountId.toUpperCase(),
    };
    // The page hands the ids over as it got them; the authenticator answers
    // with the account's own credential.
    const approveAs = async (approver: { realmId: string; accountId: string }) => {
      const decision = { realmId, approvalId: filed.id, approver, sessionIssuedAtMs: Date.now() };
      const { challenge } = await engine.startApproval(
        app(),
        test.factor,
        decision,
        engineOptions()
      );
      return engine.completeApproval(
        app(),
        test.factor,
        { ...decision, response: test.answer(challenge, requester.approver) },
        engineOptions()
      );
    };

    // The requester's own step-up, stored as the database names the account.
    const first = await approveAs(shouted);
    expect(first.status).toBe('pending');
    expect(first.approvals.map((given) => [given.approverRealmId, given.approverId])).toEqual([
      [requester.approver.realmId, requester.userId],
    ]);
    // Neither case gives the approval that needs a different account.
    await expect(approveAs(requester.approver)).rejects.toMatchObject({ statusCode: 403 });
    await expect(approveAs(shouted)).rejects.toMatchObject({ statusCode: 403 });
    expect((await storedApproval(filed.id))?.status).toBe('pending');
    const row = (await auditRows(realmId)).at(-1);
    expect(row).toMatchObject({ operation_id: 'approvals.approve', actor_id: requester.userId });
  });

  it('takes a decision only from a session issued after the approver was last disabled', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const filed = await file(realmId, requester.token);
    // The account is disabled once, then enabled again (#748).
    await app().dbPool.query('UPDATE users SET enabled = false WHERE id = $1', [requester.userId]);
    await app().dbPool.query('UPDATE users SET enabled = true WHERE id = $1', [requester.userId]);
    const { rows } = await app().dbPool.query<{ not_valid_before: string }>(
      'SELECT not_valid_before FROM users WHERE id = $1',
      [requester.userId]
    );
    const disabledAt = Number(rows[0].not_valid_before);
    const engine = await import('./admin/approvals/engine');
    const decision = (sessionIssuedAtMs: number) => ({
      realmId,
      approvalId: filed.id,
      approver: requester.approver,
      sessionIssuedAtMs,
    });

    // A session issued before the disablement is answered as a stranger is.
    await expect(
      engine.startApproval(app(), test.factor, decision(disabledAt - 60_000), engineOptions())
    ).rejects.toMatchObject({ statusCode: 404 });
    await expect(
      engine.denyApproval(app(), decision(disabledAt - 60_000), engineOptions())
    ).rejects.toMatchObject({ statusCode: 404 });
    // One signed in after it was enabled again approves.
    const fresh = decision(disabledAt + 5_000);
    const { challenge } = await engine.startApproval(app(), test.factor, fresh, engineOptions());
    const approved = await engine.completeApproval(
      app(),
      test.factor,
      { ...fresh, response: test.answer(challenge, requester.approver) },
      engineOptions()
    );
    expect(approved.status).toBe('approved');
  });

  it('refuses an answer the factor made for another approval', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const first = await file(realmId, requester.token);
    const second = await file(realmId, requester.token);
    const engine = await import('./admin/approvals/engine');
    const forFirst = await engine.startApproval(
      app(),
      test.factor,
      {
        realmId,
        approvalId: first.id,
        approver: requester.approver,
        sessionIssuedAtMs: Date.now(),
      },
      engineOptions()
    );
    await engine.startApproval(
      app(),
      test.factor,
      {
        realmId,
        approvalId: second.id,
        approver: requester.approver,
        sessionIssuedAtMs: Date.now(),
      },
      engineOptions()
    );
    await expect(
      engine.completeApproval(app(), test.factor, {
        realmId,
        approvalId: second.id,
        approver: requester.approver,
        sessionIssuedAtMs: Date.now(),
        response: test.answer(forFirst.challenge, requester.approver),
      })
    ).rejects.toMatchObject({ statusCode: 403 });
    expect((await storedApproval(second.id))?.status).toBe('pending');
  });

  it('lets a failure of the factor itself through, approving nothing and writing no refusal', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const filed = await file(realmId, requester.token);
    const engine = await import('./admin/approvals/engine');
    const broken = {
      ...test.factor,
      verify: async () => {
        throw new Error('the authenticator service is unreachable');
      },
    };
    const decision = {
      realmId,
      approvalId: filed.id,
      approver: requester.approver,
      sessionIssuedAtMs: Date.now(),
    };
    const { challenge } = await engine.startApproval(app(), broken, decision, engineOptions());

    const failed = await engine
      .completeApproval(
        app(),
        broken,
        { ...decision, response: test.answer(challenge, requester.approver) },
        engineOptions()
      )
      .catch((error: unknown) => error);
    // Not the 403 of a refused answer: the server's own failure.
    expect(failed).toBeInstanceOf(Error);
    expect(failed).toMatchObject({ message: 'the authenticator service is unreachable' });
    expect(failed).not.toHaveProperty('statusCode');
    expect((await storedApproval(filed.id))?.status).toBe('pending');
    expect((await auditRows(realmId)).map((row) => row.operation_id)).toEqual(['approvals.create']);
  });

  // Acceptance criterion: each state change writes an audit row.
  it('writes an audit row for each state change: filed, approved, denied, cancelled and consumed', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    const engine = await import('./admin/approvals/engine');

    // Filed, approved and consumed.
    const used = await file(realmId, requester.token);
    await approve(realmId, used.id, requester.approver);
    expect(
      (await post(rotateUrl(realmId), requester.token, ROTATION, { 'qauth-approval': used.id }))
        .statusCode
    ).toBe(200);
    // Filed and denied.
    const denied = await file(realmId, requester.token);
    expect(
      (
        await engine.denyApproval(app(), {
          realmId,
          approvalId: denied.id,
          approver: requester.approver,
          sessionIssuedAtMs: Date.now(),
        })
      ).status
    ).toBe('denied');
    // Filed and cancelled, with the version its ETag gave.
    const withdrawn = await file(realmId, requester.token);
    const stale = await post(
      approvals(realmId, `/${withdrawn.id}/cancel`),
      requester.token,
      undefined,
      {
        'if-match': '"approved.1"',
      }
    );
    expect(stale.statusCode).toBe(412);
    const cancelled = await post(
      approvals(realmId, `/${withdrawn.id}/cancel`),
      requester.token,
      undefined,
      {
        'if-match': '"pending.0"',
      }
    );
    expect(cancelled.statusCode, cancelled.body).toBe(200);
    expect(cancelled.json()).toMatchObject({ status: 'cancelled' });
    const twice = await post(
      approvals(realmId, `/${withdrawn.id}/cancel`),
      requester.token,
      undefined,
      {
        'if-match': '"cancelled.0"',
      }
    );
    expect(twice.statusCode).toBe(409);
    // A cancelled approval approves nothing.
    expect(
      (
        await post(rotateUrl(realmId), requester.token, ROTATION, {
          'qauth-approval': withdrawn.id,
        })
      ).statusCode
    ).toBe(403);

    const rows = (await auditRows(realmId)).map((row) => [row.operation_id, row.outcome]);
    expect(rows).toEqual([
      ['approvals.create', 'succeeded'],
      ['approvals.approve', 'succeeded'],
      ['fixtureKeys.rotate', 'succeeded'],
      ['approvals.create', 'succeeded'],
      ['approvals.deny', 'succeeded'],
      ['approvals.create', 'succeeded'],
      // A stale If-Match is refused before the handler: denied.
      ['approvals.cancel', 'denied'],
      ['approvals.cancel', 'succeeded'],
      // The handler's own refusal of an approval no longer open: failed, as
      // every refusal from inside a handler.
      ['approvals.cancel', 'failed'],
      ['fixtureKeys.rotate', 'denied'],
    ]);

    const all = await auditRows(realmId);
    const usedHash = (await storedApproval(used.id))?.op_hash;
    // The approval row names the credential; the consuming row lists the
    // approvals it ran on and the approval's op_hash.
    expect(all[1]).toMatchObject({
      actor_id: requester.userId,
      operation_class: 'security',
      effects: ['key-custody'],
      approvals: [
        { approverId: requester.userId, credentialId: test.credentialOf(requester.approver) },
      ],
    });
    expect(all[1].request_digest?.equals(usedHash ?? Buffer.alloc(0))).toBe(true);
    expect(all[2].approvals).toHaveLength(1);
    expect(all[2].request_digest?.equals(usedHash ?? Buffer.alloc(0))).toBe(true);
    // Filing is classified as the operation it is for.
    expect(all[0]).toMatchObject({ operation_class: 'security', effects: ['key-custody'] });
  });

  it('refuses to file an approval for what is not a security operation of this listener, or one it cannot parse', async () => {
    const realmId = await tenant('alpha');
    const requester = await adminWith(realmId, 'security-admin');
    for (const payload of [
      { operation: 'approvals.create' },
      { operation: 'realms.get' },
      {
        operation: 'fixtureKeys.rotate',
        params: { keyId: 'signing-1' },
        body: { retireAfterDays: 99 },
      },
      { operation: 'fixtureKeys.rotate', params: { keyId: 'signing-1', realmId }, body: ROTATION },
      {
        operation: 'fixtureKeys.rotate',
        params: { keyId: 'signing-1' },
        query: { other: 'x' },
        body: ROTATION,
      },
    ]) {
      const response = await post(approvals(realmId), requester.token, payload);
      expect(response.statusCode, JSON.stringify(payload)).toBe(400);
    }
    // Filing needs what the operation needs: an editor lacks its permission.
    const editor = await adminWith(realmId, 'editor');
    const refused = await post(approvals(realmId), editor.token, {
      operation: 'fixtureKeys.rotate',
      params: { keyId: 'signing-1' },
      body: ROTATION,
    });
    expect(refused.statusCode).toBe(403);
    expect(refused.json()).toMatchObject({ code: 'forbidden' });
  });

  /** Backends of this database waiting on a lock. */
  async function waitingOnLocks(): Promise<number> {
    const { rows } = await app().dbPool.query<{ count: string }>(
      `SELECT count(*) FROM pg_stat_activity
        WHERE datname = current_database() AND wait_event_type = 'Lock'`
    );
    return Number(rows[0].count);
  }
});

// Acceptance criterion: the boot fails for a security operation without a
// renderer.
describe('the boot of a security operation without a renderer (#512, real containers)', () => {
  it('refuses to boot the admin listener', async (ctx) => {
    if (!dockerUp) {
      ctx.skip();
      return;
    }
    await expect(bootWithAdminListener(() => fixtureAdminApi({ renderer: false }))).rejects.toThrow(
      /fixtureKeys.rotate, which has no renderer/
    );
  }, 240_000);
});

/** Poll `condition` until it holds, for up to 10 s. */
async function waitFor(condition: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (!(await condition())) {
    if (Date.now() > deadline) throw new Error('the condition never held');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
