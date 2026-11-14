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
  provisionRealmKeys,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { ageAdminAccount } from '../testing/two-admin';
import { API_FAMILY_AUDIENCES } from './api-conventions/families';
import { ADMIN_SCOPE_LIST } from './helpers/admin-scopes';

/**
 * THE TWO-ADMIN RULE (#521, ADR-019 Decision 7), against a real Postgres and
 * Redis, through the server's own admin routes.
 *
 * The realm's policy patch (`realms.policies.update`) is both the operation
 * the tests make mandatory and the one that changes the mandatory set. The
 * approval page and the passkey factor do not exist yet (#617, #623), so
 * approvals are given by calling the approval engine with the test factor,
 * as the page will. An admin that approves another's request is aged past
 * the rule's 7-day window first (`testing/two-admin.ts`).
 *
 * Each test acts on realms of its own: the audit log refuses `TRUNCATE`.
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const MERGE_PATCH = 'application/merge-patch+json';
const UPDATE = 'realms.policies.update';

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
  operation_id: string;
  outcome: string;
  approvals: Array<{
    approverId: string;
    credentialId: string;
    approverCreatedBy: string | null;
    approvedAt: number;
  }> | null;
}

interface Filed {
  id: string;
  status: string;
  approvalsRequired: number;
  twoAdmin: 'recommended' | 'mandatory';
  eligibleApprovers: number;
}

describe('the two-admin rule (#521, real containers)', () => {
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

  async function operatorRealm(): Promise<{ id: string; issuer: string }> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer) throw new Error('default realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  /** A realm of the test's own, with its keys. */
  async function tenant(name: string): Promise<string> {
    const host = `${name}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    await provisionRealmKeys(app(), name);
    return realm.id;
  }

  type Admin = Awaited<ReturnType<typeof securityAdmin>>;

  /**
   * An operator-realm security admin of `realmId`, its grant made by
   * `createdBy`: its token, and its account as an approver.
   */
  async function securityAdmin(realmId: string, createdBy: string | null = null) {
    const operator = await operatorRealm();
    const userId = (
      await app().repositories.users.create({ realmId: operator.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: 'security-admin' },
      targetRealmId: realmId,
      createdBy,
    });
    const token = await signBoundAccessToken(app(), operator, {
      sub: userId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope: ALL_ADMIN_SCOPES,
    });
    return { userId, token, approver: { realmId: operator.id, accountId: userId } };
  }

  /** An account of the operator realm that made other admins. */
  async function creator(): Promise<string> {
    const operator = await operatorRealm();
    return (
      await app().repositories.users.create({ realmId: operator.id }, testPrimaryCredential())
    ).id;
  }

  const realmPath = (realmId: string) => `/admin/v1-rc.0/realms/${realmId}`;

  /** A call with `token` under the `DPoP` scheme and a fresh proof of its key (#520). */
  async function send(
    method: 'GET' | 'POST' | 'PATCH',
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

  /** The realm's ETag and two-admin set, as `realms.get` answers them. */
  async function read(realmId: string, token: string) {
    const response = await send('GET', realmPath(realmId), token);
    expect(response.statusCode, response.body).toBe(200);
    const { policies } = response.json<{
      policies: {
        admin: { twoAdminMandatoryOperations: string[] };
        password: { minScore: number };
      };
    }>();
    return {
      etag: response.headers['etag'] as string,
      mandatory: policies.admin.twoAdminMandatoryOperations,
      minScore: policies.password.minScore,
    };
  }

  /** A policy patch against `etag`, with the approval `approvalId` when given. */
  async function patch(
    realmId: string,
    token: string,
    body: unknown,
    etag: string,
    approvalId?: string
  ) {
    return send('PATCH', `${realmPath(realmId)}/policies`, token, JSON.stringify(body), {
      'content-type': MERGE_PATCH,
      'if-match': etag,
      ...(approvalId === undefined ? {} : { 'qauth-approval': approvalId }),
    });
  }

  /** File the approval of the policy patch `body`, as `requester`. */
  async function file(realmId: string, requester: Admin, body: unknown) {
    return send('POST', `${realmPath(realmId)}/approvals`, requester.token, {
      operation: UPDATE,
      body,
    });
  }

  /** Give `approvalId` `approver`'s approval with the test factor, as the approval page will. */
  async function approve(realmId: string, approvalId: string, approver: Admin) {
    const engine = await import('./admin/approvals/engine');
    const decision = {
      realmId,
      approvalId,
      approver: approver.approver,
      sessionIssuedAtMs: Date.now(),
    };
    const { challenge } = await engine.startApproval(app(), test.factor, decision);
    return engine.completeApproval(app(), test.factor, {
      ...decision,
      response: test.answer(challenge, approver.approver),
    });
  }

  /** Run a patch that needs the requester's approval alone: file, approve, send. */
  async function patchAlone(realmId: string, requester: Admin, body: unknown) {
    const { etag } = await read(realmId, requester.token);
    const filed = await file(realmId, requester, body);
    expect(filed.statusCode, filed.body).toBe(201);
    const { id } = filed.json<Filed>();
    expect((await approve(realmId, id, requester)).status).toBe('approved');
    return patch(realmId, requester.token, body, etag, id);
  }

  async function auditRows(realmId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT operation_id, outcome, approvals
         FROM admin_audit_log WHERE realm_id = $1 ORDER BY seq`,
      [realmId]
    );
    return rows;
  }

  // Acceptance criterion: one admin can add an operation to the mandatory set
  // but cannot remove one.
  it('lets one admin add an operation to the mandatory set, and not remove one', async () => {
    const realmId = await tenant('alpha');
    const requester = await securityAdmin(realmId);
    expect((await read(realmId, requester.token)).mandatory).toEqual([]);

    // Adding needs the requester's own approval, and nothing more.
    const added = await patchAlone(realmId, requester, {
      admin: { twoAdminMandatoryOperations: ['keys.rotate'] },
    });
    expect(added.statusCode, added.body).toBe(200);
    const more = await patchAlone(realmId, requester, {
      admin: { twoAdminMandatoryOperations: ['keys.rotate', 'clients.delete'] },
    });
    expect(more.statusCode, more.body).toBe(200);
    expect((await read(realmId, requester.token)).mandatory).toEqual([
      'keys.rotate',
      'clients.delete',
    ]);

    // Removing one, replacing the set or emptying it needs a second admin,
    // and no other admin can give one: nothing is filed, nothing changes.
    for (const body of [
      { admin: { twoAdminMandatoryOperations: ['keys.rotate'] } },
      { admin: { twoAdminMandatoryOperations: ['realms.delete'] } },
      { admin: { twoAdminMandatoryOperations: [] } },
      { admin: { twoAdminMandatoryOperations: null } },
    ]) {
      const refused = await file(realmId, requester, body);
      expect(refused.statusCode, JSON.stringify(body)).toBe(409);
      expect(refused.json()).toMatchObject({ code: 'approval_unavailable', status: 409 });
      const { etag } = await read(realmId, requester.token);
      const direct = await patch(realmId, requester.token, body, etag);
      expect(direct.statusCode).toBe(409);
      expect(direct.json()).toMatchObject({ code: 'approval_unavailable' });
    }
    expect((await read(realmId, requester.token)).mandatory).toEqual([
      'keys.rotate',
      'clients.delete',
    ]);
    const { rows } = await app().dbPool.query<{ count: string }>(
      `SELECT count(*) FROM admin_approvals WHERE realm_id = $1`,
      [realmId]
    );
    expect(Number(rows[0].count)).toBe(2);
  }, 120_000);

  // Acceptance criterion: a mandatory operation with no eligible approver
  // answers approval_unavailable and does not run.
  it('answers approval_unavailable for a mandatory operation no other admin can approve, and runs nothing', async () => {
    const realmId = await tenant('alpha');
    const requester = await securityAdmin(realmId);
    expect(
      (await patchAlone(realmId, requester, { admin: { twoAdminMandatoryOperations: [UPDATE] } }))
        .statusCode
    ).toBe(200);
    const { etag, minScore } = await read(realmId, requester.token);
    const loosening = { password: { minScore: minScore - 1 } };
    // Another admin, made just now: not one who can approve yet.
    await securityAdmin(realmId);

    const filed = await file(realmId, requester, loosening);
    expect(filed.statusCode, filed.body).toBe(409);
    const problem = filed.json<{ code: string; detail: string; type: string }>();
    expect(problem).toMatchObject({
      code: 'approval_unavailable',
      type: 'https://docs.qauth.dev/reference/problem-types/#approval-unavailable',
    });
    expect(problem.detail).toContain(
      'https://docs.qauth.dev/reference/security-operations/#when-no-admin-can-approve'
    );
    const direct = await patch(realmId, requester.token, loosening, etag);
    expect(direct.statusCode).toBe(409);
    expect(direct.json()).toMatchObject({ code: 'approval_unavailable' });

    // The operation did not run, and no approval was filed for it.
    expect((await read(realmId, requester.token)).minScore).toBe(minScore);
    const update = (await auditRows(realmId)).filter((row) => row.operation_id === UPDATE);
    expect(update.filter((row) => row.outcome === 'succeeded')).toHaveLength(1);
    const { rows } = await app().dbPool.query<{ count: string }>(
      `SELECT count(*) FROM admin_approvals WHERE realm_id = $1`,
      [realmId]
    );
    expect(Number(rows[0].count)).toBe(1);
  }, 120_000);

  // Acceptance criterion: the audit row lists both credential ids and both
  // approvers' creators.
  it('runs a mandatory operation on two approvals, and records both credentials and both creators', async () => {
    const realmId = await tenant('alpha');
    const madeRequester = await creator();
    const madeSecond = await creator();
    const requester = await securityAdmin(realmId, madeRequester);
    const second = await securityAdmin(realmId, madeSecond);
    await ageAdminAccount(app().dbPool, second.userId);
    expect(
      (await patchAlone(realmId, requester, { admin: { twoAdminMandatoryOperations: [UPDATE] } }))
        .statusCode
    ).toBe(200);
    const { etag, minScore } = await read(realmId, requester.token);
    const loosening = { password: { minScore: minScore - 1 } };

    const filed = await file(realmId, requester, loosening);
    expect(filed.statusCode, filed.body).toBe(201);
    const approval = filed.json<Filed>();
    expect(approval).toMatchObject({
      status: 'pending',
      approvalsRequired: 2,
      twoAdmin: 'mandatory',
      eligibleApprovers: 1,
    });

    // The requester's own step-up is not enough.
    expect((await approve(realmId, approval.id, requester)).status).toBe('pending');
    const early = await patch(realmId, requester.token, loosening, etag, approval.id);
    expect(early.statusCode).toBe(403);
    expect(early.json()).toMatchObject({ code: 'approval_required' });

    // Nor is an approval given with a passkey registered to the requester too.
    const shared = test.credentialOf(requester.approver);
    test.register(second.approver, shared);
    const engine = await import('./admin/approvals/engine');
    const decision = {
      realmId,
      approvalId: approval.id,
      approver: second.approver,
      sessionIssuedAtMs: Date.now(),
    };
    const borrowed = await engine.startApproval(app(), test.factor, decision);
    await expect(
      engine.completeApproval(app(), test.factor, {
        ...decision,
        response: test.answer(borrowed.challenge, second.approver, shared),
      })
    ).rejects.toMatchObject({ statusCode: 403 });

    // An admin made today may not approve: its answer is refused, and audited.
    const fresh = await securityAdmin(realmId);
    const denied = async () =>
      (await auditRows(realmId)).filter(
        (row) => row.operation_id === 'approvals.approve' && row.outcome === 'denied'
      ).length;
    const deniedBefore = await denied();
    await expect(
      engine.completeApproval(app(), test.factor, {
        ...decision,
        approver: fresh.approver,
        response: {},
      })
    ).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining('7 days') });
    expect(await denied()).toBe(deniedBefore + 1);

    // The second admin's own passkey gives it.
    expect((await approve(realmId, approval.id, second)).status).toBe('approved');
    const ran = await patch(realmId, requester.token, loosening, etag, approval.id);
    expect(ran.statusCode, ran.body).toBe(200);
    expect((await read(realmId, requester.token)).minScore).toBe(minScore - 1);

    const succeeded = (await auditRows(realmId))
      .filter((row) => row.operation_id === UPDATE && row.outcome === 'succeeded')
      .at(-1);
    expect(
      succeeded?.approvals?.map(({ approverId, credentialId, approverCreatedBy }) => ({
        approverId,
        credentialId,
        approverCreatedBy,
      }))
    ).toEqual([
      {
        approverId: requester.userId,
        credentialId: test.credentialOf(requester.approver),
        approverCreatedBy: madeRequester,
      },
      {
        approverId: second.userId,
        credentialId: test.credentialOf(second.approver),
        approverCreatedBy: madeSecond,
      },
    ]);
    // The refused approval with the requester's passkey left a denied row.
    expect(
      (await auditRows(realmId)).some(
        (row) => row.operation_id === 'approvals.approve' && row.outcome === 'denied'
      )
    ).toBe(true);
  }, 120_000);
});
