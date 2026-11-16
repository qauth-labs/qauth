import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { decodeJwt } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  dpopTestKey,
  keyOfToken,
  rememberTokenKey,
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
import { API_FAMILY_AUDIENCES, API_FAMILY_SCOPES } from './api-conventions/families';
import { ADMIN_SCOPE_LIST } from './helpers/admin-scopes';

/**
 * ACT-CHAIN TOKENS FOR ADMINS ACTING FOR A USER (#523, ADR-019 Decision 7,
 * ADR-020 §3), against a real Postgres and Redis.
 *
 * The HTTP operation that mints a token comes later, so the suite puts a
 * fixture security operation (`issue-for-other`) behind the real admin
 * pipeline: its handler mints a token with the capability the pipeline
 * issued it. The admin files an approval, approves it with the test factor
 * (the approval page does not exist yet), and retries the call. The token is
 * then used on the real account API and on fixture account routes, with DPoP
 * proofs made with the admin's own key.
 *
 * One case per acceptance criterion:
 *
 * - the family guard refuses the token on a route that does not declare
 *   `allowActChain`;
 * - a route that calls `requireFreshAuthentication` refuses it;
 * - the `admin_act_sessions` row and the operation's audit row are written in
 *   one transaction;
 * - `listAdminAccess` returns the admin, the time and the approval;
 * - revoking the admin's grant makes the token fail on its next use;
 * - each call made with it writes an audit row with the full act chain.
 *
 * Each test acts as an admin of its own: the audit log refuses `TRUNCATE`, so
 * its rows stay, and are read per admin.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const ACCOUNT_READ = API_FAMILY_SCOPES.account.read;
const ACCOUNT_WRITE = API_FAMILY_SCOPES.account.write;
/** The default realm's issuer: the base of the account API's DPoP proofs. */
const ORIGIN = 'https://auth.example.com';
const OPERATION = 'fixtureUsers.actChainTokens.create';
const CONSOLE_ID = 'admin-console';

/** How the test steers the fixture handler. */
const steer = { failAfterMint: false };

/** The fixture security operation, imported once the boot reset the modules. */
async function fixtureAdminApi() {
  const operations = await import('./helpers/admin-operations');
  const { requestAuthorizedOperation } = await import('./admin/pipeline');
  const { mintActChainToken } = await import('./admin/act-chain-tokens');

  const actFor = operations.defineOperation({
    id: OPERATION,
    class: 'security',
    effects: ['issue-for-other'],
    permissions: ['users.security'],
    description: 'Act for a user of the realm with an act-chain token (fixture).',
    render: (request: { params: unknown }) => ({
      title: `Act for the user ${(request.params as { userId: string }).userId}`,
    }),
  });
  const registry = operations.createAdminOperationRegistry([actFor], { reserved: [] });

  return {
    registry,
    routes: (scope: FastifyInstance) => {
      scope.post(
        '/admin/v1-rc.0/realms/:realmId/fixture-users/:userId/act-chain-tokens',
        {
          config: { operation: actFor.id },
          schema: {
            ...operations.operationSchemaExtensions(actFor),
            'x-qauth-stability': 'experimental',
            'x-qauth-errors': [400, 401, 403, 404],
            security: [{ dpopAuth: [] }],
            params: z.object({ realmId: z.uuid(), userId: z.uuid() }),
            body: z.strictObject({ scopes: z.array(z.string().max(64)).max(2).optional() }),
          },
        },
        async (request) => {
          const { userId } = request.params as { userId: string };
          const { scopes } = request.body as { scopes?: string[] };
          const minted = await mintActChainToken(requestAuthorizedOperation(request), {
            userId,
            ...(scopes === undefined ? {} : { scopes }),
          });
          if (steer.failAfterMint) throw new Error('the fixture failed after its mint');
          return minted;
        }
      );
    },
  };
}

/**
 * Fixture routes of the account API, in a scope whose calls are audited as
 * the account API's are: one guarded by the family guard alone, which does
 * not declare `allowActChain`, and one of an operation that takes an
 * act-chain token but asks for a fresh sign-in itself.
 */
async function fixtureAccountRoutes(app: FastifyInstance) {
  const { registerAdminActChainAudit } = await import('./helpers/admin-access');
  const { accountOperation, requireFreshAuthentication } =
    await import('./helpers/account-operation-guard');
  const { requireFamilyToken } = await import('./helpers/family-token');

  await app.register(async (scope) => {
    registerAdminActChainAudit(scope);
    scope.get(
      '/account/v1-rc.0/fixture-act-chain/undeclared',
      {
        config: { surface: 'api' },
        schema: { hide: true },
        preValidation: requireFamilyToken('account', {
          subjects: ['user'],
          requiredScopes: [ACCOUNT_READ],
        }),
      },
      async () => ({ ran: 'undeclared' })
    );
    const fresh = accountOperation({
      operationId: 'account.fixture.freshSignIn',
      operationClass: 'read',
      permission: 'profile.read',
      freshAuthentication: 'none',
      actChain: 'accepted',
    });
    scope.get(
      '/account/v1-rc.0/fixture-act-chain/fresh',
      {
        config: { surface: 'api' },
        schema: { ...fresh.schema, hide: true },
        preValidation: fresh.guard,
      },
      async (request) => {
        await requireFreshAuthentication(request);
        return { ran: 'fresh' };
      }
    );
  });
}

interface AuditRow {
  operation_id: string;
  outcome: string;
  actor_id: string;
  actor_realm_id: string | null;
  act_chain: unknown;
  xmin: string;
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

describe('act-chain tokens for admins acting for a user (#523, real containers)', () => {
  let booted: BootedAuthServer | undefined;
  let test: TestApprovalFactor;

  beforeAll(async () => {
    if (!dockerUp || !infra || !jwt) return;
    booted = await bootAuthServer(
      { ...baseEnvironment(infra, jwt), ...ADMIN_LISTENER_ENVIRONMENT },
      { adminListener: fixtureAdminApi, routes: fixtureAccountRoutes }
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
    steer.failAfterMint = false;
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

  /** A security admin of the operator realm: its token, its grant and its account as an approver. */
  async function securityAdmin() {
    const operator = await operatorRealm();
    const userId = (
      await app().repositories.users.create({ realmId: operator.id }, testPrimaryCredential())
    ).id;
    const grant = await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: 'security-admin' },
      targetRealmId: operator.id,
      createdBy: null,
    });
    const token = await signBoundAccessToken(app(), operator, {
      sub: userId,
      clientId: CONSOLE_ID,
      aud: ADMIN,
      scope: ALL_ADMIN_SCOPES,
    });
    return {
      userId,
      grantId: grant.id,
      token,
      approver: { realmId: operator.id, accountId: userId },
    };
  }

  async function adminPost(
    url: string,
    token: string,
    payload: unknown,
    headers: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    return admin().inject({
      method: 'POST',
      url,
      headers: { ...(await adminCallHeaders(token, 'POST', url)), ...headers },
      payload: payload as Record<string, unknown>,
    });
  }

  /** Give `approvalId` an approval with the test factor, as the approval page will. */
  async function approve(
    realmId: string,
    approvalId: string,
    approver: { realmId: string; accountId: string }
  ) {
    const engine = await import('./admin/approvals/engine');
    const decision = { realmId, approvalId, approver, sessionIssuedAtMs: Date.now() };
    const { challenge } = await engine.startApproval(app(), test.factor, decision);
    return engine.completeApproval(app(), test.factor, {
      ...decision,
      response: test.answer(challenge, approver),
    });
  }

  /**
   * A user of the operator realm and a security admin who, with an approval
   * for it, called the fixture operation that acts for them. The call's answer
   * is returned as it is, so a test can steer it to fail.
   */
  async function actForUser(body: { scopes?: string[] } = {}) {
    const realm = await operatorRealm();
    const userId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    const requester = await securityAdmin();
    const filed = await adminPost(`/admin/v1-rc.0/realms/${realm.id}/approvals`, requester.token, {
      operation: OPERATION,
      params: { userId },
      body,
    });
    expect(filed.statusCode, filed.body).toBe(201);
    const approvalId = filed.json<{ id: string }>().id;
    expect((await approve(realm.id, approvalId, requester.approver)).status).toBe('approved');
    const response = await adminPost(
      `/admin/v1-rc.0/realms/${realm.id}/fixture-users/${userId}/act-chain-tokens`,
      requester.token,
      body,
      { 'qauth-approval': approvalId }
    );
    return { realm, userId, requester, approvalId, response };
  }

  /** {@link actForUser}, succeeded: the token, remembered as bound to the admin's key. */
  async function actChainToken(body: { scopes?: string[] } = {}) {
    const acted = await actForUser(body);
    expect(acted.response.statusCode, acted.response.body).toBe(200);
    const minted = acted.response.json<{
      accessToken: string;
      tokenType: string;
      sessionId: string;
      expiresAt: number;
    }>();
    const key = keyOfToken(acted.requester.token);
    if (key === undefined) throw new Error('the admin token has no key');
    rememberTokenKey(minted.accessToken, key);
    return { ...acted, ...minted };
  }

  /** A call to the account API with `token` under the `DPoP` scheme, with a proof of its key. */
  async function accountCall(
    method: 'GET' | 'POST',
    path: string,
    token: string,
    options: { key?: Awaited<ReturnType<typeof dpopTestKey>>; payload?: unknown } = {}
  ): Promise<LightMyRequestResponse> {
    return app().inject({
      method,
      url: path,
      headers: await adminCallHeaders(token, method, path, {
        baseUrl: ORIGIN,
        ...(options.key === undefined ? {} : { key: options.key }),
      }),
      ...(options.payload === undefined
        ? {}
        : { payload: options.payload as Record<string, unknown> }),
    });
  }

  /** The admin audit rows `adminId` is the actor of, oldest first. */
  async function auditRowsOf(adminId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT operation_id, outcome, actor_id, actor_realm_id, act_chain, xmin::text AS xmin
         FROM admin_audit_log WHERE actor_id = $1 ORDER BY seq`,
      [adminId]
    );
    return rows;
  }

  /** The audit rows of the account API calls `adminId` made with an act-chain token. */
  async function accountCallRowsOf(adminId: string): Promise<AuditRow[]> {
    return (await auditRowsOf(adminId)).filter((row) => row.operation_id.startsWith('account.'));
  }

  async function sessionRowsOf(userId: string) {
    const { rows } = await app().dbPool.query<{
      id: string;
      approval_id: string;
      admin_user_id: string;
      token_jti: string;
      scopes: string[];
      created_at: string;
      expires_at: string;
      xmin: string;
    }>(
      `SELECT id, approval_id, admin_user_id, token_jti, scopes, created_at::text,
              expires_at::text, xmin::text AS xmin
         FROM admin_act_sessions WHERE user_id = $1`,
      [userId]
    );
    return rows;
  }

  const CONSENTS = '/account/v1-rc.0/consents';

  it('mints a token for the user, naming the admin, for the account API, bound to the admin key', async () => {
    const { realm, userId, requester, accessToken, tokenType } = await actChainToken();
    const claims = decodeJwt(accessToken);
    expect(tokenType).toBe('DPoP');
    expect(claims).toMatchObject({
      iss: realm.issuer,
      sub: userId,
      aud: API_FAMILY_AUDIENCES.account,
      act: { sub: requester.userId, iss: realm.issuer, client_id: CONSOLE_ID },
      client_id: CONSOLE_ID,
      cnf: { jkt: keyOfToken(requester.token)?.thumbprint },
      scope: ACCOUNT_READ,
    });
    expect(claims).not.toHaveProperty('auth_time');
    expect((claims.exp as number) - (claims.iat as number)).toBeLessThanOrEqual(600);

    // It works with a proof of the admin's key, and with no other.
    expect((await accountCall('GET', CONSENTS, accessToken)).statusCode).toBe(200);
    const stranger = await accountCall('GET', CONSENTS, accessToken, { key: await dpopTestKey() });
    expect(stranger.statusCode).toBe(401);
  });

  // Acceptance criterion: the guard refuses the token on a fixture route
  // without allowActChain.
  it('is refused by the family guard on a route that does not declare it takes one', async () => {
    const { requester, accessToken } = await actChainToken();
    const response = await accountCall(
      'GET',
      '/account/v1-rc.0/fixture-act-chain/undeclared',
      accessToken
    );
    expect(response.statusCode, response.body).toBe(403);
    expect(response.json()).toMatchObject({ code: 'delegated_token_refused' });
    // Refused before any check that would mark the call: no audit row.
    expect(await accountCallRowsOf(requester.userId)).toEqual([]);
  });

  // Acceptance criterion: a route that calls requireFreshAuthentication
  // refuses it.
  it('is refused by a route that asks for a fresh sign-in, and by an operation that refuses it', async () => {
    const { accessToken } = await actChainToken({ scopes: [ACCOUNT_READ, ACCOUNT_WRITE] });
    const fresh = await accountCall('GET', '/account/v1-rc.0/fixture-act-chain/fresh', accessToken);
    expect(fresh.statusCode, fresh.body).toBe(403);
    expect(fresh.json()).toMatchObject({ code: 'delegated_token_refused' });

    // The real password change asks for a fresh sign-in and refuses the token.
    const change = await accountCall('POST', '/account/v1-rc.0/password/change', accessToken, {
      payload: { currentPassword: 'irrelevant', newPassword: 'irrelevant as well' },
    });
    expect(change.statusCode, change.body).toBe(403);
    expect(change.json()).toMatchObject({ code: 'delegated_token_refused' });
  });

  // Acceptance criterion: the admin_act_sessions row and the audit row are
  // written in one transaction.
  it('writes its record and the operation audit row in one transaction, or neither', async () => {
    const { userId, requester, approvalId, sessionId, accessToken } = await actChainToken();
    const [session] = await sessionRowsOf(userId);
    expect(session).toMatchObject({
      id: sessionId,
      approval_id: approvalId,
      admin_user_id: requester.userId,
      token_jti: decodeJwt(accessToken).jti,
      scopes: [ACCOUNT_READ],
    });
    const operationRows = (await auditRowsOf(requester.userId)).filter(
      (row) => row.operation_id === OPERATION
    );
    expect(operationRows.map((row) => row.outcome)).toEqual(['succeeded']);
    // The same transaction wrote both rows.
    expect(operationRows[0].xmin).toBe(session.xmin);

    // A handler that fails after the mint leaves no record of the token.
    steer.failAfterMint = true;
    const failed = await actForUser();
    expect(failed.response.statusCode).toBe(500);
    expect(await sessionRowsOf(failed.userId)).toEqual([]);
    const failedRows = (await auditRowsOf(failed.requester.userId)).filter(
      (row) => row.operation_id === OPERATION
    );
    expect(failedRows.map((row) => row.outcome)).not.toContain('succeeded');
  });

  // Acceptance criterion: listAdminAccess returns the admin, the time and the
  // approval id.
  it('is listed for the user: who acted for them, when, and on which approval', async () => {
    const before = Date.now();
    const { realm, userId, requester, approvalId, sessionId, accessToken } = await actChainToken();
    const { listAdminAccess } = await import('./helpers/admin-access');
    const entries = await listAdminAccess(app(), realm.id, userId);
    const claims = decodeJwt(accessToken);
    expect(entries).toEqual([
      {
        id: sessionId,
        adminId: requester.userId,
        adminRealmId: realm.id,
        approvalId,
        operationId: OPERATION,
        scopes: [ACCOUNT_READ],
        actedAt: (claims.iat as number) * 1000,
        expiresAt: (claims.exp as number) * 1000,
      },
    ]);
    expect(entries[0].actedAt).toBeGreaterThanOrEqual(Math.floor(before / 1000) * 1000);
    // Another user of the realm sees nothing of it.
    const neighbour = await app().repositories.users.create(
      { realmId: realm.id },
      testPrimaryCredential()
    );
    expect(await listAdminAccess(app(), realm.id, neighbour.id)).toEqual([]);
  });

  // Acceptance criterion: revoking the grant makes the token fail on its next
  // use.
  it("fails on its next use once the admin's grant is revoked", async () => {
    const { realm, requester, accessToken } = await actChainToken();
    expect((await accountCall('GET', CONSENTS, accessToken)).statusCode).toBe(200);

    expect(await app().repositories.adminGrants.revoke(realm.id, requester.grantId)).toBeDefined();
    const refused = await accountCall('GET', CONSENTS, accessToken);
    expect(refused.statusCode, refused.body).toBe(401);
    expect(refused.headers['www-authenticate']).toContain('invalid_token');
    // The refused call is audited too, as denied, with the same act chain.
    const rows = await accountCallRowsOf(requester.userId);
    expect(rows.map((row) => [row.operation_id, row.outcome])).toEqual([
      ['account.consents.list', 'succeeded'],
      ['account.consents.list', 'denied'],
    ]);
    expect(rows[1].act_chain).toEqual(rows[0].act_chain);
  });

  // Acceptance criterion: each call writes an audit row with the full act
  // chain.
  it('writes an audit row with the full act chain for each call made with it', async () => {
    const { realm, userId, requester, accessToken } = await actChainToken({
      scopes: [ACCOUNT_READ, ACCOUNT_WRITE],
    });
    expect((await accountCall('GET', CONSENTS, accessToken)).statusCode).toBe(200);
    expect((await accountCall('GET', CONSENTS, accessToken)).statusCode).toBe(200);
    expect(
      (await accountCall('GET', '/account/v1-rc.0/fixture-act-chain/fresh', accessToken)).statusCode
    ).toBe(403);

    const chain = {
      sub: userId,
      act: { sub: requester.userId, iss: realm.issuer, client_id: CONSOLE_ID },
    };
    const calls = await accountCallRowsOf(requester.userId);
    expect(calls).toEqual([
      expect.objectContaining({ operation_id: 'account.consents.list', outcome: 'succeeded' }),
      expect.objectContaining({ operation_id: 'account.consents.list', outcome: 'succeeded' }),
      expect.objectContaining({ operation_id: 'account.fixture.freshSignIn', outcome: 'denied' }),
    ]);
    for (const row of calls) {
      expect(row.act_chain).toEqual(chain);
      expect(row.actor_realm_id).toBe(realm.id);
    }
  });
});
