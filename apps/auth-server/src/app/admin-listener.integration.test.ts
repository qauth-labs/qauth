import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

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
 * THE ADMIN LISTENER AND ITS PIPELINE (#511, ADR-019 Decisions 7 and 8),
 * against a real Postgres and Redis.
 *
 * The suite boots the real app with the admin listener beside it, as
 * `main.ts` does, and puts fixture operations behind the real pipeline: a
 * read, a write that creates an account in its realm, a write whose handler
 * fails after its change, and a security operation. No admin operation ships
 * yet (#517), so the registry is the suite's own, built from the server's
 * permission catalog. Each test acts on realms of its own: the audit log
 * refuses `TRUNCATE`, so rows stay, and are counted per realm.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');

/** What the fixture handlers saw, for the assertions. */
const runs: string[] = [];
const handlerTransactions: unknown[] = [];

function realmPath(realmId: string, suffix = ''): string {
  return `/admin/v1-rc.0/realms/${realmId}${suffix}`;
}

/** The fixture operations and their routes, imported once the boot reset the modules. */
async function fixtureAdminApi() {
  const operations = await import('./helpers/admin-operations');
  const { adminTransaction, recordAdminChange, requestAdminCaller } =
    await import('./admin/pipeline');

  const read = operations.defineOperation({
    id: 'realms.get',
    class: 'read',
    effects: [],
    permissions: ['realms.read'],
    description: 'Read a realm (fixture).',
  });
  const create = operations.defineOperation({
    id: 'fixtureAccounts.create',
    class: 'write',
    effects: [],
    permissions: ['realms.policies.write'],
    description: 'Create an account in the realm (fixture).',
  });
  const fail = operations.defineOperation({
    id: 'fixtureAccounts.fail',
    class: 'write',
    effects: [],
    permissions: ['realms.policies.write'],
    description: 'Create an account, then fail (fixture).',
  });
  const rotate = operations.defineOperation({
    id: 'fixtureKeys.rotate',
    class: 'security',
    effects: ['key-custody'],
    permissions: ['realms.policies.security'],
    description: 'A security operation (fixture).',
  });
  const registry = operations.createOperationRegistry([read, create, fail, rotate], {
    reserved: [],
  });

  const params = z.object({ realmId: z.uuid() });
  const schemaOf = (operation: typeof read) => ({
    ...operations.operationSchemaExtensions(operation),
    'x-qauth-stability': 'experimental' as const,
    'x-qauth-errors': [401, 403, 404],
    security: [{ bearerAuth: [] }],
    params,
  });

  return {
    registry,
    routes: (scope: FastifyInstance) => {
      scope.get(
        '/admin/v1-rc.0/realms/:realmId',
        { config: { operation: read.id }, schema: schemaOf(read) },
        async (request) => {
          runs.push(read.id);
          handlerTransactions.push(adminTransaction(request));
          const caller = requestAdminCaller(request);
          return {
            realm: caller.targetRealm.id,
            operator: caller.operator,
            requestRealm: request.realm?.id,
          };
        }
      );
      scope.post(
        '/admin/v1-rc.0/realms/:realmId/fixture-accounts',
        { config: { operation: create.id }, schema: schemaOf(create) },
        async (request) => {
          runs.push(create.id);
          const tx = adminTransaction(request);
          handlerTransactions.push(tx);
          const realmId = requestAdminCaller(request).targetRealm.id;
          const account = await request.server.repositories.users.create({ realmId }, tx);
          recordAdminChange(request, {
            change: { before: null, after: { id: account.id, recoveryCode: 'never-stored' } },
            annotations: { recoveryCode: 'secret' },
          });
          return { id: account.id };
        }
      );
      scope.post(
        '/admin/v1-rc.0/realms/:realmId/fixture-failures',
        { config: { operation: fail.id }, schema: schemaOf(fail) },
        async (request) => {
          runs.push(fail.id);
          const realmId = requestAdminCaller(request).targetRealm.id;
          await request.server.repositories.users.create({ realmId }, adminTransaction(request));
          throw new Error('the fixture handler failed after its change');
        }
      );
      scope.post(
        '/admin/v1-rc.0/realms/:realmId/fixture-keys/rotate',
        { config: { operation: rotate.id }, schema: schemaOf(rotate) },
        async (request) => {
          runs.push(rotate.id);
          const realmId = requestAdminCaller(request).targetRealm.id;
          await request.server.repositories.users.create({ realmId }, adminTransaction(request));
          return { rotated: true };
        }
      );
    },
  };
}

interface AuditRow {
  realm_id: string;
  seq: string;
  actor_kind: string;
  actor_id: string;
  actor_realm_id: string | null;
  operation_id: string;
  operation_class: string;
  effects: string[];
  outcome: string;
  masked_diff: unknown;
  trace_id: string | null;
  xmin: string;
}

/** The containers every server of this file runs on: one Postgres, one Redis. */
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

/** Boot the app with the fixture admin API on its admin listener, under `environment` too. */
function bootWithAdminListener(
  environment: Record<string, string> = {},
  logLines?: string[]
): Promise<BootedAuthServer> {
  if (!infra || !jwt) throw new Error('no infrastructure');
  return bootAuthServer(
    { ...baseEnvironment(infra, jwt), ...environment },
    {
      ...(logLines === undefined
        ? {}
        : { logStream: { write: (line: string) => logLines.push(line) } }),
      adminListener: fixtureAdminApi,
    }
  );
}

describe('the admin listener and its pipeline (#511, real containers)', () => {
  let booted: BootedAuthServer | undefined;
  const logLines: string[] = [];

  beforeAll(async () => {
    if (!dockerUp) return;
    booted = await bootWithAdminListener({}, logLines);
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
    handlerTransactions.length = 0;
    logLines.length = 0;
  });

  afterEach(() => {
    vi.restoreAllMocks();
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

  async function tenant(name: string): Promise<string> {
    const host = `${name}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    return realm.id;
  }

  /** An operator-realm admin with `role` on `realmId`, and its token. */
  async function adminWith(
    realmId: string,
    role: 'viewer' | 'editor' | 'security-admin',
    scope = ALL_ADMIN_SCOPES
  ): Promise<{ userId: string; token: string }> {
    const operator = await defaultRealm();
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
    return { userId, token };
  }

  function call(
    method: 'GET' | 'POST',
    url: string,
    token?: string,
    extra: { remoteAddress?: string } = {}
  ): Promise<LightMyRequestResponse> {
    return admin().inject({
      method,
      url,
      ...(token === undefined ? {} : { headers: { authorization: `Bearer ${token}` } }),
      ...extra,
    });
  }

  async function auditRows(realmId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT realm_id, seq::text AS seq, actor_kind, actor_id, actor_realm_id, operation_id,
              operation_class, effects, outcome, masked_diff, trace_id, xmin::text AS xmin
         FROM admin_audit_log WHERE realm_id = $1 ORDER BY admin_audit_log.seq`,
      [realmId]
    );
    return rows;
  }

  async function accountsIn(realmId: string): Promise<number> {
    const { rows } = await app().dbPool.query<{ count: string }>(
      'SELECT count(*) FROM users WHERE realm_id = $1',
      [realmId]
    );
    return Number(rows[0].count);
  }

  describe('two listeners', () => {
    it('answers 404 for an admin path on the public listener, which the admin listener serves', async () => {
      const realmId = await tenant('alpha');
      const { token } = await adminWith(realmId, 'viewer');

      const onPublic = await app().inject({
        method: 'GET',
        url: realmPath(realmId),
        headers: { authorization: `Bearer ${token}` },
      });
      expect(onPublic.statusCode).toBe(404);
      expect(onPublic.json()).toMatchObject({ code: 'not_found' });

      const onAdmin = await call('GET', realmPath(realmId), token);
      expect(onAdmin.statusCode).toBe(200);
      expect(onAdmin.json()).toEqual({ realm: realmId, operator: true, requestRealm: realmId });
      // The public listener ran nothing and wrote nothing.
      expect(runs).toEqual(['realms.get']);
      expect(await auditRows(realmId)).toHaveLength(1);
    });

    it('serves the admin OpenAPI document on the admin listener only', async () => {
      const onAdmin = await admin().inject({ method: 'GET', url: '/admin/v1-rc.0/openapi.json' });
      expect(onAdmin.statusCode).toBe(200);
      const document = onAdmin.json<{ info: { title: string }; paths: Record<string, unknown> }>();
      expect(document.info.title).toBe('QAuth Admin API');
      expect(Object.keys(document.paths).sort()).toEqual([
        '/admin/v1-rc.0/realms/{realmId}',
        '/admin/v1-rc.0/realms/{realmId}/fixture-accounts',
        '/admin/v1-rc.0/realms/{realmId}/fixture-failures',
        '/admin/v1-rc.0/realms/{realmId}/fixture-keys/rotate',
      ]);

      const onPublic = await app().inject({ method: 'GET', url: '/admin/v1-rc.0/openapi.json' });
      expect(onPublic.statusCode).toBe(404);
      const publicDocument = await app().inject({ method: 'GET', url: '/docs/json' });
      if (publicDocument.statusCode === 200) {
        expect(JSON.stringify(publicDocument.json())).not.toContain('/admin/');
      }
    });

    it('answers what no route serves with problem documents, before any stage', async () => {
      const unknown = await admin().inject({ method: 'POST', url: '/nowhere', payload: '{' });
      expect(unknown.statusCode).toBe(404);
      expect(unknown.headers['content-type']).toContain('application/problem+json');
      expect(unknown.json()).toMatchObject({ code: 'not_found', instance: '/nowhere' });
      expect(unknown.headers['x-request-id']).toBe(unknown.json<{ trace_id: string }>().trace_id);

      // The router's own refusal: a path that is not valid percent-encoding.
      const malformed = await admin().inject({ method: 'GET', url: '/admin/v1-rc.0/realms/%zz' });
      expect(malformed.statusCode).toBe(400);
      expect(malformed.json()).toMatchObject({ code: 'bad_request' });

      // No HEAD route stands beside a GET route.
      const realmId = await tenant('alpha');
      const head = await admin().inject({ method: 'HEAD', url: realmPath(realmId) });
      expect(head.statusCode).toBe(404);
      expect(runs).toEqual([]);
    });

    it('bounds the request id a caller sends, which the audit row records', async () => {
      const realmId = await tenant('alpha');
      const { token } = await adminWith(realmId, 'viewer');
      const response = await admin().inject({
        method: 'GET',
        url: realmPath(realmId),
        headers: { authorization: `Bearer ${token}`, 'x-request-id': 'x'.repeat(129) },
      });
      expect(response.statusCode).toBe(200);
      const traceId = response.headers['x-request-id'];
      expect(traceId).toMatch(/^[0-9a-f-]{36}$/);
      expect((await auditRows(realmId)).map((row) => row.trace_id)).toEqual([traceId]);
    });

    it('passes the API conventions check against the registry it was built with', async () => {
      const { checkApiConventions } = await import('./api-conventions/openapi-conventions');
      const { registry } = await fixtureAdminApi();
      const document = (
        await admin().inject({ method: 'GET', url: '/admin/v1-rc.0/openapi.json' })
      ).json();
      const report = checkApiConventions(document, { operations: registry });
      expect(report.checkedOperations).toBe(4);
      expect(report.violations).toEqual([]);
    });
  });

  describe('authentication comes first', () => {
    it('refuses a call without a token with 401 and the same answer whether the realm exists or not', async () => {
      const realmId = await tenant('alpha');
      const missing = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
      const comparable = (response: LightMyRequestResponse) => {
        const body = { ...response.json<Record<string, unknown>>() };
        delete body['trace_id'];
        delete body['instance'];
        return {
          status: response.statusCode,
          challenge: response.headers['www-authenticate'],
          body,
        };
      };

      const existing = await call('GET', realmPath(realmId));
      expect(existing.statusCode).toBe(401);
      expect(existing.json()).toMatchObject({ code: 'unauthorized' });
      expect(existing.headers['www-authenticate']).toBe('Bearer realm="OAuth"');
      expect(comparable(existing)).toEqual(comparable(await call('GET', realmPath(missing))));
      expect(JSON.stringify(existing.json())).not.toContain('alpha');
      expect(runs).toEqual([]);
      expect(await auditRows(realmId)).toEqual([]);
    });

    it('refuses a call from loopback without a token: the network position grants nothing', async () => {
      const realmId = await tenant('alpha');
      for (const remoteAddress of ['127.0.0.1', '::1']) {
        const response = await call('GET', realmPath(realmId), undefined, { remoteAddress });
        expect(response.statusCode).toBe(401);
      }

      // Over a real socket, from loopback to the listener's loopback address.
      const address = await admin().listen({ host: '127.0.0.1', port: 0 });
      try {
        const response = await fetch(`${address}${realmPath(realmId)}`);
        expect(response.status).toBe(401);
        expect(await response.json()).toMatchObject({ code: 'unauthorized' });
      } finally {
        await admin().server.close();
      }
      expect(runs).toEqual([]);
    });

    it('refuses a token that is not an admin token before it reads the realm', async () => {
      const realmId = await tenant('alpha');
      const operator = await defaultRealm();
      const { userId } = await adminWith(realmId, 'security-admin');
      const sign = (claims: Record<string, unknown>) =>
        app().jwtUtils.signAccessToken(operator, {
          sub: userId,
          clientId: 'admin-console',
          aud: ADMIN,
          scope: ALL_ADMIN_SCOPES,
          ...claims,
        });
      const refusals = [
        // Another family's audience.
        await sign({ aud: API_FAMILY_AUDIENCES.account }),
        // A delegated token.
        await sign({ act: { sub: 'agent' } }),
        // Not a token at all.
        'not-a-token',
      ];
      for (const token of refusals) {
        const response = await call('GET', realmPath(realmId), token);
        expect(response.statusCode).toBe(401);
        expect(response.json()).toMatchObject({ code: 'invalid_access_token' });
      }
      expect(runs).toEqual([]);
      expect(await auditRows(realmId)).toEqual([]);
    });
  });

  describe('a realm outside the grants', () => {
    it('answers 404, is logged, and adds no row to that realm', async () => {
      const granted = await tenant('alpha');
      const stranger = await tenant('beta');
      const { userId, token } = await adminWith(granted, 'security-admin');

      const response = await call('GET', realmPath(stranger), token);
      expect(response.statusCode).toBe(404);
      expect(response.json()).toMatchObject({ code: 'not_found' });
      expect(await auditRows(stranger)).toEqual([]);
      expect(runs).toEqual([]);
      const logged = logLines
        .map((line) => JSON.parse(line) as Record<string, unknown>)
        .find((line) => String(line['msg']).startsWith('An admin call named a realm outside'));
      expect(logged).toMatchObject({ realmId: stranger, adminCaller: { subject: userId } });
    });
  });

  describe('the audit row', () => {
    it('is written once for a successful read, in the transaction the handler ran in', async () => {
      const realmId = await tenant('alpha');
      const { userId, token } = await adminWith(realmId, 'viewer');
      const operator = await defaultRealm();
      const append = vi.spyOn(app().repositories.adminAuditLog, 'appendAdminAudit');

      const response = await admin().inject({
        method: 'GET',
        url: realmPath(realmId),
        headers: { authorization: `Bearer ${token}`, 'x-request-id': 'trace-read-1' },
      });
      expect(response.statusCode).toBe(200);
      expect(response.headers['x-request-id']).toBe('trace-read-1');

      expect(append).toHaveBeenCalledTimes(1);
      expect(append.mock.calls[0][0]).toBe(handlerTransactions[0]);
      const rows = await auditRows(realmId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        actor_kind: 'human_admin',
        actor_id: userId,
        actor_realm_id: operator.id,
        operation_id: 'realms.get',
        operation_class: 'read',
        effects: [],
        outcome: 'succeeded',
        masked_diff: null,
        trace_id: 'trace-read-1',
      });
    });

    it('is written once for a successful write, in the same transaction as the change, with the diff masked', async () => {
      const realmId = await tenant('alpha');
      const { token } = await adminWith(realmId, 'editor');

      const response = await call('POST', realmPath(realmId, '/fixture-accounts'), token);
      expect(response.statusCode).toBe(200);
      const { id } = response.json<{ id: string }>();

      const rows = await auditRows(realmId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        operation_id: 'fixtureAccounts.create',
        operation_class: 'write',
        outcome: 'succeeded',
      });
      expect(JSON.stringify(rows[0].masked_diff)).not.toContain('never-stored');
      expect(rows[0].masked_diff).toMatchObject({ before: null, after: { id } });
      // One transaction wrote both rows: they carry the same xmin.
      const { rows: account } = await app().dbPool.query<{ xmin: string }>(
        'SELECT xmin::text AS xmin FROM users WHERE id = $1',
        [id]
      );
      expect(account[0].xmin).toBe(rows[0].xmin);
    });

    it('rolls back with the change when it cannot be written, and the call fails', async () => {
      const realmId = await tenant('alpha');
      const { token } = await adminWith(realmId, 'editor');
      vi.spyOn(app().repositories.adminAuditLog, 'appendAdminAudit').mockRejectedValue(
        new Error('the audit log is down')
      );

      const response = await call('POST', realmPath(realmId, '/fixture-accounts'), token);
      expect(response.statusCode).toBe(500);
      expect(await accountsIn(realmId)).toBe(0);
    });

    it('chains every row of the realm, and the chain verifies', async () => {
      const realmId = await tenant('alpha');
      const { token } = await adminWith(realmId, 'editor');
      await call('GET', realmPath(realmId), token);
      await call('POST', realmPath(realmId, '/fixture-accounts'), token);
      await call('POST', realmPath(realmId, '/fixture-failures'), token);
      await call('POST', realmPath(realmId, '/fixture-keys/rotate'), token);

      expect((await auditRows(realmId)).map((row) => row.outcome)).toEqual([
        'succeeded',
        'succeeded',
        'failed',
        'denied',
      ]);
      await expect(
        app().repositories.adminAuditLog.verifyAdminAuditChain(realmId)
      ).resolves.toMatchObject({ ok: true, rowsChecked: 4 });
    });
  });

  describe('a refused or failed call', () => {
    it('refuses a caller without the permission with 403, and writes one denied row', async () => {
      const realmId = await tenant('alpha');
      // A viewer's role holds no write permission, whatever its token's scopes.
      const { userId, token } = await adminWith(realmId, 'viewer');

      const response = await call('POST', realmPath(realmId, '/fixture-accounts'), token);
      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({ code: 'forbidden' });
      // No scope would lift it: the challenge names none.
      expect(response.headers['www-authenticate']).not.toContain('insufficient_scope');
      expect(runs).toEqual([]);
      expect(await accountsIn(realmId)).toBe(0);
      const rows = await auditRows(realmId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        actor_id: userId,
        operation_id: 'fixtureAccounts.create',
        operation_class: 'write',
        outcome: 'denied',
        masked_diff: null,
      });
    });

    it("names the scope when the role holds the permission but the token's scopes do not", async () => {
      const realmId = await tenant('alpha');
      const { token } = await adminWith(realmId, 'editor', 'qauth:admin:read');

      const response = await call('POST', realmPath(realmId, '/fixture-accounts'), token);
      expect(response.statusCode).toBe(403);
      expect(response.headers['www-authenticate']).toContain('error="insufficient_scope"');
      expect(response.headers['www-authenticate']).toContain('scope="qauth:admin:write"');
      expect((await auditRows(realmId)).map((row) => row.outcome)).toEqual(['denied']);
    });

    it('names no scope when the role lacks the permission, whatever the token lacks too', async () => {
      const realmId = await tenant('alpha');
      // A viewer's token without the write scope: a wider token would not pass.
      const { token } = await adminWith(realmId, 'viewer', 'qauth:admin:read');

      const response = await call('POST', realmPath(realmId, '/fixture-accounts'), token);
      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({ code: 'forbidden' });
      expect(response.headers['www-authenticate']).not.toContain('insufficient_scope');
    });

    it('answers approval_required for a security operation and never runs it', async () => {
      const realmId = await tenant('alpha');
      // A security admin holds the permission and the scope: only the
      // missing approval stops it.
      const { token } = await adminWith(realmId, 'security-admin');

      const response = await call('POST', realmPath(realmId, '/fixture-keys/rotate'), token);
      expect(response.statusCode).toBe(403);
      expect(response.headers['content-type']).toContain('application/problem+json');
      expect(response.json()).toMatchObject({
        code: 'approval_required',
        type: 'https://docs.qauth.dev/reference/problem-types/#approval-required',
      });
      expect(runs).toEqual([]);
      expect(await accountsIn(realmId)).toBe(0);
      const rows = await auditRows(realmId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        operation_id: 'fixtureKeys.rotate',
        operation_class: 'security',
        effects: ['key-custody'],
        outcome: 'denied',
      });
    });

    it('leaves no change when the handler fails, and writes one failed row', async () => {
      const realmId = await tenant('alpha');
      const { token } = await adminWith(realmId, 'editor');

      const response = await call('POST', realmPath(realmId, '/fixture-failures'), token);
      expect(response.statusCode).toBe(500);
      expect(response.json()).toMatchObject({ code: 'internal_error' });
      expect(runs).toEqual(['fixtureAccounts.fail']);
      expect(await accountsIn(realmId)).toBe(0);
      const rows = await auditRows(realmId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        operation_id: 'fixtureAccounts.fail',
        outcome: 'failed',
        masked_diff: null,
      });
    });

    it('writes a denied row for a request refused after authorization, before its handler', async () => {
      const realmId = await tenant('alpha');
      const { token } = await adminWith(realmId, 'editor');

      // The body is read after the authority stage: one that does not parse
      // is refused there, and the handler never runs.
      const response = await admin().inject({
        method: 'POST',
        url: realmPath(realmId, '/fixture-accounts'),
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        payload: '{',
      });
      expect(response.statusCode).toBe(400);
      expect(runs).toEqual([]);
      expect(await accountsIn(realmId)).toBe(0);
      expect((await auditRows(realmId)).map((row) => row.outcome)).toEqual(['denied']);
    });
  });
});

describe('the request ceilings of the admin listener (#511, real containers)', () => {
  let booted: BootedAuthServer | undefined;

  beforeAll(async () => {
    if (!dockerUp) return;
    // Two requests a minute, per address and per token subject.
    booted = await bootWithAdminListener({ RATE_LIMIT_MAX: '2', RATE_LIMIT_WINDOW: '60' });
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
  });

  function servers(): { app: FastifyInstance; admin: FastifyInstance } {
    if (!booted?.admin) throw new Error('admin listener not booted');
    return { app: booted.app, admin: booted.admin };
  }

  it('limits calls per client address, before the token guard', async () => {
    const { admin } = servers();
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await admin.inject({
        method: 'GET',
        url: realmPath('018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f'),
        remoteAddress: '198.51.100.7',
      });
      statuses.push(response.statusCode);
      if (response.statusCode === 429) {
        expect(response.json()).toMatchObject({ code: 'too_many_requests' });
        expect(Number(response.headers['retry-after'])).toBeGreaterThan(0);
      }
    }
    expect(statuses).toEqual([401, 401, 429]);
    // Another address has its own count.
    const other = await admin.inject({
      method: 'GET',
      url: realmPath('018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f'),
      remoteAddress: '198.51.100.8',
    });
    expect(other.statusCode).toBe(401);
  });

  it('limits calls per token subject from any address, before the realm, writing no row', async () => {
    const { app, admin } = servers();
    const operator = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!operator?.issuer) throw new Error('default realm missing');
    const { realm } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'alpha', issuer: 'https://alpha.example.com', enabled: true },
      'alpha.example.com'
    );
    const userId = (await app.repositories.users.create({ realmId: operator.id })).id;
    await app.repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: 'viewer' },
      targetRealmId: realm.id,
      createdBy: null,
    });
    const token = await app.jwtUtils.signAccessToken(
      { id: operator.id },
      { sub: userId, clientId: 'admin-console', aud: ADMIN, scope: ALL_ADMIN_SCOPES }
    );

    const statuses: number[] = [];
    for (const remoteAddress of ['198.51.100.10', '198.51.100.11', '198.51.100.12']) {
      const response = await admin.inject({
        method: 'GET',
        url: realmPath(realm.id),
        headers: { authorization: `Bearer ${token}` },
        remoteAddress,
      });
      statuses.push(response.statusCode);
    }
    expect(statuses).toEqual([200, 200, 429]);
    expect(runs).toEqual(['realms.get', 'realms.get']);
    const { rows } = await app.dbPool.query<{ outcome: string }>(
      'SELECT outcome FROM admin_audit_log WHERE realm_id = $1 ORDER BY admin_audit_log.seq',
      [realm.id]
    );
    expect(rows.map((row) => row.outcome)).toEqual(['succeeded', 'succeeded']);
  });
});

describe('the admin listener closes with the server (#511, real containers)', () => {
  it('stops listening when the server closes', async (ctx) => {
    if (!dockerUp || !infra || !jwt) {
      ctx.skip();
      return;
    }
    const booted = await bootAuthServer(baseEnvironment(infra, jwt), {
      adminListener: () => ({}),
    });
    const admin = booted.admin;
    if (admin === undefined) throw new Error('admin listener not booted');
    const address = await admin.listen({ host: '127.0.0.1', port: 0 });
    expect((await fetch(`${address}/admin/v1-rc.0/openapi.json`)).status).toBe(200);

    await booted.close();

    expect(admin.server.listening).toBe(false);
    await expect(fetch(`${address}/admin/v1-rc.0/openapi.json`)).rejects.toThrow();
  }, 240_000);
});
