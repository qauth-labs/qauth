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
  E2E_PASSWORD,
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
 * AN OPERATOR VERIFIES AN ACCOUNT (#1052, ADR-015 Decision 8 as amended
 * 2026-11-08), against a real Postgres and Redis: `users.verify` on the admin
 * listener, filed, approved and run, and the record the host's
 * `verify-account` command writes (`operator_cli`), each read back by the
 * sign-in gate of #1051 and the verified-owner check of #846.
 *
 * Each account registers through the real `POST /auth/register` and never
 * enters its mailbox code, so its address stays unconfirmed. The default
 * realm requires verified accounts, so it cannot sign in until an operator
 * verifies it. The command itself runs against a database with no admin
 * listener in the migration runner's suite (`runner.integration.test.ts`).
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');

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
  masked_diff: { before: Record<string, unknown>; after: Record<string, unknown> } | null;
}

interface EventRow {
  type: string;
  category: string;
  actor_type: string;
  actor_id: string | null;
  subject_id: string;
  data: unknown;
}

describe('users.verify and the host command (#1052, real containers)', () => {
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

  /**
   * A password account registered through the real route, whose mailbox code
   * is never entered: its address stays unconfirmed.
   */
  async function unconfirmedAccount(email: string): Promise<string> {
    const registered = await app().inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(registered.statusCode, registered.body).toBe(202);
    const { id } = await defaultRealm();
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      id,
      'password',
      email
    );
    if (!credential) throw new Error(`registration of ${email} left no password credential`);
    return credential.userId;
  }

  /** Whether the account's address is confirmed, as its password credential records it. */
  async function addressConfirmed(email: string): Promise<boolean> {
    const { id } = await defaultRealm();
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      id,
      'password',
      email
    );
    const data = credential?.credentialData as { email_verified?: boolean } | undefined;
    return data?.email_verified === true;
  }

  const signIn = (email: string) =>
    app().inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: E2E_PASSWORD },
    });

  /** The verified-owner decision of #846 for the account. */
  async function ownerDecision(userId: string) {
    // Imported after the boot, which resets the modules.
    const { checkVerifiedOwner } = await import('./helpers/verified-owner');
    return checkVerifiedOwner(app(), { realmId: (await defaultRealm()).id, userId });
  }

  const verificationPath = (realmId: string, userId: string) =>
    `/admin/v1-rc.0/realms/${realmId}/users/${userId}/verification`;

  /** A call with `token` under the `DPoP` scheme and a fresh proof of its key (#520). */
  async function send(
    method: 'GET' | 'POST',
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

  /** The verification call, naming the account's current state. */
  const verify = (
    realmId: string,
    userId: string,
    by: Admin,
    headers: Record<string, string> = {}
  ) =>
    send('POST', verificationPath(realmId, userId), by.token, {}, { 'if-match': '*', ...headers });

  /** File an approval for the verification of `userId` and approve it with the test factor. */
  async function fileAndApprove(realmId: string, userId: string, requester: Admin) {
    const filed = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realmId}/approvals`,
      requester.token,
      {
        operation: 'users.verify',
        params: { userId },
        body: {},
        reason: 'The deployment sends no mail; the owner confirmed by phone.',
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

  async function auditRows(realmId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT operation_id, outcome, masked_diff
         FROM admin_audit_log WHERE realm_id = $1 AND operation_id = 'users.verify' ORDER BY seq`,
      [realmId]
    );
    return rows;
  }

  async function verifiedEvents(realmId: string): Promise<EventRow[]> {
    const { rows } = await app().dbPool.query<EventRow>(
      `SELECT type, category, actor_type, actor_id, subject_id, data
         FROM events WHERE realm_id = $1 AND type = 'urn:qauth:event:user.verified:v1-rc.0'
        ORDER BY seq`,
      [realmId]
    );
    return rows;
  }

  async function operatorVerification(userId: string) {
    const { rows } = await app().dbPool.query<{
      operator_verified_at: string | null;
      operator_verified_by: string | null;
    }>('SELECT operator_verified_at, operator_verified_by FROM users WHERE id = $1', [userId]);
    return rows[0];
  }

  it('verifies an unconfirmed password account once approved: it signs in and may own an agent, its address stays unconfirmed, and the event names the admin', async () => {
    const email = 'verify-approved@example.com';
    const userId = await unconfirmedAccount(email);
    const realm = await defaultRealm();
    const requester = await adminWith('security-admin', 'qauth:admin:security');

    // Before: the gate refuses it as a wrong password, and it owns nothing.
    expect((await signIn(email)).statusCode).toBe(401);
    expect(await ownerDecision(userId)).toMatchObject({ verified: false, identity: 'password' });

    const approvalId = await fileAndApprove(realm.id, userId, requester);
    // The approver was shown the account, that it is unclaimed, and its
    // password credential with its unconfirmed address.
    const shown = await send(
      'GET',
      `/admin/v1-rc.0/realms/${realm.id}/approvals/${approvalId}`,
      requester.token
    );
    expect(shown.statusCode, shown.body).toBe(200);
    expect(shown.json()).toMatchObject({
      reason: 'The deployment sends no mail; the owner confirmed by phone.',
      display: {
        title: 'Verify an account as the operator',
        fields: expect.arrayContaining([
          { label: 'account', value: userId },
          {
            label: 'credential password (primary)',
            value: `address ${email} not confirmed`,
          },
        ]),
      },
    });
    expect(JSON.stringify(shown.json())).toContain('the account is unclaimed and this claims it');

    const done = await verify(realm.id, userId, requester, { 'qauth-approval': approvalId });
    expect(done.statusCode, done.body).toBe(200);
    expect(done.json()).toEqual({
      userId,
      verifiedAt: expect.any(String),
      method: 'operator',
      verifiedBy: requester.userId,
    });
    expect(await operatorVerification(userId)).toMatchObject({
      operator_verified_by: `operator:${requester.userId}`,
    });

    // email_verified is left as it was.
    expect(await addressConfirmed(email)).toBe(false);
    expect(await verifiedEvents(realm.id)).toEqual([
      {
        type: 'urn:qauth:event:user.verified:v1-rc.0',
        category: 'admin',
        actor_type: 'user',
        actor_id: requester.userId,
        subject_id: userId,
        data: { method: 'operator' },
      },
    ]);
    expect(await auditRows(realm.id)).toEqual([
      {
        operation_id: 'users.verify',
        outcome: 'succeeded',
        masked_diff: {
          before: { userId, operatorVerifiedAt: null, operatorVerifiedBy: null },
          after: {
            userId,
            operatorVerifiedAt: done.json<{ verifiedAt: string }>().verifiedAt,
            operatorVerifiedBy: `operator:${requester.userId}`,
          },
        },
      },
    ]);

    // After: the gate of #1051 lets it sign in, and the check of #846 passes.
    const signedIn = await signIn(email);
    expect(signedIn.statusCode, signedIn.body).toBe(200);
    expect(await ownerDecision(userId)).toEqual({
      verified: true,
      identity: 'password',
      operatorVerified: true,
    });

    // The approval was used; a second verification is refused.
    const again = await verify(realm.id, userId, requester, { 'qauth-approval': approvalId });
    expect(again.statusCode).toBe(409);
    expect(again.json()).toMatchObject({ code: 'conflict' });
  });

  it('changes nothing without an approval, and audits the refusal', async () => {
    const email = 'verify-unapproved@example.com';
    const userId = await unconfirmedAccount(email);
    const realm = await defaultRealm();

    // An editor's write scope reaches no security operation.
    const editor = await adminWith('editor', 'qauth:admin:read qauth:admin:write');
    const byEditor = await verify(realm.id, userId, editor);
    expect(byEditor.statusCode).toBe(403);
    expect(byEditor.json()).toMatchObject({ code: 'forbidden' });

    const securityAdmin = await adminWith('security-admin', 'qauth:admin:security');
    const unapproved = await verify(realm.id, userId, securityAdmin);
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });
    // Without If-Match the operation does not run either.
    const unconditional = await send(
      'POST',
      verificationPath(realm.id, userId),
      securityAdmin.token,
      {}
    );
    expect(unconditional.statusCode).toBe(428);

    expect(await operatorVerification(userId)).toEqual({
      operator_verified_at: null,
      operator_verified_by: null,
    });
    expect(await verifiedEvents(realm.id)).toEqual([]);
    expect((await signIn(email)).statusCode).toBe(401);
    const audited = await auditRows(realm.id);
    expect(audited.length).toBeGreaterThanOrEqual(2);
    expect(audited.every((row) => row.outcome === 'denied' && row.masked_diff === null)).toBe(true);
  });

  it('refuses to file or run the verification of a disabled account, with 409', async () => {
    const userId = await unconfirmedAccount('verify-disabled@example.com');
    const realm = await defaultRealm();
    await app().repositories.users.update(realm.id, userId, { enabled: false });
    const requester = await adminWith('security-admin', 'qauth:admin:security');

    const filed = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realm.id}/approvals`,
      requester.token,
      {
        operation: 'users.verify',
        params: { userId },
        body: {},
      }
    );
    expect(filed.statusCode).toBe(409);
    const run = await verify(realm.id, userId, requester);
    expect(run.statusCode).toBe(409);
    expect(await operatorVerification(userId)).toMatchObject({ operator_verified_at: null });
  });

  it('refuses an approved verification when the account changed after it was filed', async () => {
    const userId = await unconfirmedAccount('verify-moved@example.com');
    const realm = await defaultRealm();
    const requester = await adminWith('security-admin', 'qauth:admin:security');
    const approvalId = await fileAndApprove(realm.id, userId, requester);

    // A credential the approver never saw.
    await app().repositories.userCredentials.create({
      userId,
      realmId: realm.id,
      ...testPrimaryCredential(),
    });
    const done = await verify(realm.id, userId, requester, { 'qauth-approval': approvalId });
    expect(done.statusCode).toBe(403);
    expect(done.json()).toMatchObject({ code: 'approval_required' });
    expect(await operatorVerification(userId)).toMatchObject({ operator_verified_at: null });
  });

  it("lets the account the host's command verified sign in and own an agent, with its address unconfirmed", async () => {
    const email = 'verify-cli@example.com';
    const userId = await unconfirmedAccount(email);
    const realm = await defaultRealm();
    expect((await signIn(email)).statusCode).toBe(401);

    // What `verify-account` stores on the account (the migration runner's
    // suite runs the command itself).
    await app().repositories.users.recordOperatorVerification(realm.id, userId, 'operator_cli:ops');

    const signedIn = await signIn(email);
    expect(signedIn.statusCode, signedIn.body).toBe(200);
    expect(await ownerDecision(userId)).toEqual({
      verified: true,
      identity: 'password',
      operatorVerified: true,
    });
    expect(await addressConfirmed(email)).toBe(false);
  });
});
