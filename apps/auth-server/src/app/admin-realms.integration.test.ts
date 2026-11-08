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
import { API_FAMILY_AUDIENCES } from './api-conventions/families';
import { ADMIN_SCOPE_LIST } from './helpers/admin-scopes';

/**
 * THE REALM OPERATIONS OF THE ADMIN API (#517, ADR-019 Decisions 7 and 10),
 * against a real Postgres and Redis: `realms.get` and
 * `realms.policies.update`, the reference every later admin operation
 * follows.
 *
 * The suite boots the real app with the admin listener and the server's own
 * operation registry. Approvals are given by calling the approval engine
 * with the test factor, as the approval page will (#617, #623). Each test
 * acts on a realm of its own, which gets its keys: a secret policy field is
 * sealed and stored with the realm's `data_at_rest` key.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const MERGE_PATCH = 'application/merge-patch+json';

/** The SMTP password the tests set: it must never come back, in any form but a ciphertext. */
const SMTP_PASSWORD = 'smtp-password-5e2b9c1d-never-shown';

let infra: E2eInfrastructure | undefined;
let jwt: PemKeyPair | undefined;
let dockerUp = false;

/** Every line the server logged, at every level. */
const logLines: string[] = [];

beforeAll(async () => {
  dockerUp = await requireDockerOrSkip();
  if (!dockerUp) return;
  infra = await startE2eInfrastructure();
  jwt = await generateJwtPem();
}, 240_000);

afterAll(async () => {
  await infra?.teardown();
});

interface RealmBody {
  id: string;
  name: string;
  enabled: boolean;
  operator: boolean;
  createdAt: string;
  updatedAt: string;
  sandboxOf: string | null;
  sandbox: string | null;
  policySchemaVersion: string;
  policies: {
    password: { minScore: number; minLength: number };
    tokens: { accessTokenLifespanSeconds: number; refreshTokenLifespanSeconds: number };
    bruteForce: { lockoutSeconds: number; windowSeconds: number };
    mail: { provider: string; smtp: Record<string, unknown> };
  };
}

interface AuditRow {
  operation_id: string;
  outcome: string;
  masked_diff: unknown;
}

describe('the realm operations of the admin API (#517, real containers)', () => {
  let booted: BootedAuthServer | undefined;
  let test: TestApprovalFactor;

  beforeAll(async () => {
    if (!dockerUp || !infra || !jwt) return;
    booted = await bootAuthServer(
      { ...baseEnvironment(infra, jwt), ...ADMIN_LISTENER_ENVIRONMENT },
      {
        // The server's own operation registry and admin routes.
        adminListener: async () => ({}),
        logStream: { write: (line) => logLines.push(line) },
        logLevel: 'debug',
      }
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
  async function tenant(name: string): Promise<{ id: string }> {
    const host = `${name}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    await provisionRealmKeys(app(), name);
    return { id: realm.id };
  }

  type Admin = Awaited<ReturnType<typeof adminWith>>;

  /** An operator-realm admin with `role` on `realmId`: its token and its account as an approver. */
  async function adminWith(
    realmId: string,
    role: 'viewer' | 'editor' | 'security-admin',
    scope = ALL_ADMIN_SCOPES
  ) {
    const operator = await operatorRealm();
    const userId = (
      await app().repositories.users.create({ realmId: operator.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: role },
      targetRealmId: realmId,
      createdBy: null,
    });
    const token = await signBoundAccessToken(app(), operator, {
      sub: userId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope,
    });
    return { userId, token, approver: { realmId: operator.id, accountId: userId } };
  }

  const realmPath = (realmId: string) => `/admin/v1-rc.0/realms/${realmId}`;
  const policiesPath = (realmId: string) => `${realmPath(realmId)}/policies`;

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

  /** The realm, as `realms.get` answers it to `token`. */
  async function read(realmId: string, token: string) {
    const response = await send('GET', realmPath(realmId), token);
    expect(response.statusCode, response.body).toBe(200);
    return { etag: response.headers['etag'] as string, body: response.json<RealmBody>() };
  }

  /** A policy patch, a JSON Merge Patch against `etag`. */
  async function patch(
    realmId: string,
    token: string,
    body: unknown,
    etag: string | undefined,
    headers: Record<string, string> = {}
  ) {
    return send('PATCH', policiesPath(realmId), token, JSON.stringify(body), {
      'content-type': MERGE_PATCH,
      ...(etag === undefined ? {} : { 'if-match': etag }),
      ...headers,
    });
  }

  /** File an approval for one policy patch and approve it with the test factor. */
  async function fileAndApprove(realmId: string, requester: Admin, body: unknown) {
    const filed = await send('POST', `${realmPath(realmId)}/approvals`, requester.token, {
      operation: 'realms.policies.update',
      body,
    });
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
    return { approvalId, filed };
  }

  /** Run a security patch end to end: file it, approve it, and send it with the approval. */
  async function approvedPatch(realmId: string, requester: Admin, body: unknown) {
    const { etag } = await read(realmId, requester.token);
    const { approvalId, filed } = await fileAndApprove(realmId, requester, body);
    const shown = await send(
      'GET',
      `${realmPath(realmId)}/approvals/${approvalId}`,
      requester.token
    );
    const done = await patch(realmId, requester.token, body, etag, {
      'qauth-approval': approvalId,
    });
    return { done, approvalId, responses: [filed, shown, done] };
  }

  async function auditRows(realmId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT operation_id, outcome, masked_diff
         FROM admin_audit_log WHERE realm_id = $1 ORDER BY seq`,
      [realmId]
    );
    return rows;
  }

  /** The text of every row of `table` that belongs to the realm. */
  async function rowsText(table: string, realmId: string): Promise<string> {
    const { rows } = await app().dbPool.query<{ row: string }>(
      `SELECT t::text AS row FROM ${table} t WHERE t.realm_id = $1`,
      [realmId]
    );
    return rows.map((row) => row.row).join('\n');
  }

  // Scenario 1, and the review of #887: a viewer reads, and a patch is
  // refused before anything is read, so a stale If-Match is 403 too.
  it('lets a viewer with qauth:admin:read read the realm, and refuses its patch with 403', async () => {
    const realm = await tenant('alpha');
    const viewer = await adminWith(realm.id, 'viewer', 'qauth:admin:read');

    const { etag, body } = await read(realm.id, viewer.token);
    expect(etag).toMatch(/^"\d+"$/);
    expect(body).toMatchObject({
      id: realm.id,
      name: 'alpha',
      enabled: true,
      operator: false,
      sandboxOf: null,
      sandbox: null,
      policies: { password: { minScore: expect.any(Number) } },
    });
    expect(body.policies.mail.smtp).toHaveProperty('passwordSet', false);
    expect(body.policies.mail.smtp).not.toHaveProperty('password');

    for (const ifMatch of [etag, '"999"']) {
      const refused = await patch(
        realm.id,
        viewer.token,
        { tokens: { accessTokenLifespanSeconds: 300 } },
        ifMatch
      );
      expect(refused.statusCode, ifMatch).toBe(403);
      expect(refused.json()).toMatchObject({ code: 'forbidden' });
    }
    expect((await read(realm.id, viewer.token)).etag).toBe(etag);
  });

  // Scenarios 2 and 3: a tightening is a write, which needs no approval.
  it('lets an editor with qauth:admin:write shorten the access-token lifetime and raise the password score', async () => {
    const realm = await tenant('alpha');
    const editor = await adminWith(realm.id, 'editor', 'qauth:admin:read qauth:admin:write');
    const before = await read(realm.id, editor.token);

    const shortened = await patch(
      realm.id,
      editor.token,
      { tokens: { accessTokenLifespanSeconds: 300 } },
      before.etag
    );
    expect(shortened.statusCode, shortened.body).toBe(200);
    expect(shortened.json<RealmBody>().policies.tokens.accessTokenLifespanSeconds).toBe(300);
    const afterShortening = shortened.headers['etag'] as string;
    expect(afterShortening).not.toBe(before.etag);

    const raised = await patch(
      realm.id,
      editor.token,
      { password: { minScore: before.body.policies.password.minScore + 1 } },
      afterShortening
    );
    expect(raised.statusCode, raised.body).toBe(200);
    expect(raised.json<RealmBody>().policies.password.minScore).toBe(
      before.body.policies.password.minScore + 1
    );
    expect(await read(realm.id, editor.token)).toMatchObject({
      etag: raised.headers['etag'],
      body: { policies: { tokens: { accessTokenLifespanSeconds: 300 } } },
    });

    // Two write calls, one audit row each, no approval asked.
    const rows = (await auditRows(realm.id)).filter(
      (row) => row.operation_id === 'realms.policies.update'
    );
    expect(rows.map((row) => row.outcome)).toEqual(['succeeded', 'succeeded']);
    expect(rows[0].masked_diff).toMatchObject({
      before: {
        policies: {
          tokens: {
            accessTokenLifespanSeconds: before.body.policies.tokens.accessTokenLifespanSeconds,
          },
        },
      },
      after: { policies: { tokens: { accessTokenLifespanSeconds: 300 } } },
    });
  });

  // Scenario 4. Lowering the score is a security change: it needs
  // realms.policies.security, which the editor role does not hold, and so
  // qauth:admin:security and an approval.
  it('makes lowering the password score need an approval, and applies it once approved', async () => {
    const realm = await tenant('alpha');
    const editor = await adminWith(realm.id, 'editor', 'qauth:admin:read qauth:admin:write');
    const { etag, body } = await read(realm.id, editor.token);
    const lowered = { password: { minScore: body.policies.password.minScore - 1 } };

    const byEditor = await patch(realm.id, editor.token, lowered, etag);
    expect(byEditor.statusCode).toBe(403);
    expect(byEditor.json()).toMatchObject({ code: 'forbidden' });

    const securityAdmin = await adminWith(realm.id, 'security-admin');
    const unapproved = await patch(realm.id, securityAdmin.token, lowered, etag);
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });
    expect((await read(realm.id, editor.token)).etag).toBe(etag);

    const { done, responses } = await approvedPatch(realm.id, securityAdmin, lowered);
    expect(done.statusCode, done.body).toBe(200);
    expect(done.json<RealmBody>().policies.password.minScore).toBe(lowered.password.minScore);
    // The approver was shown the score beside the value it replaces.
    expect(responses[1].json()).toMatchObject({
      display: {
        fields: expect.arrayContaining([
          {
            label: 'password.minScore',
            before: String(body.policies.password.minScore),
            value: String(lowered.password.minScore),
          },
        ]),
      },
    });
  });

  // Scenario 5: a patch of a write field and a security field needs both
  // scopes, and one approval for both changes.
  it('makes a mixed patch need both scopes and one approval', async () => {
    const realm = await tenant('alpha');
    const { body } = await read(realm.id, (await adminWith(realm.id, 'viewer')).token);
    const mixed = {
      tokens: { accessTokenLifespanSeconds: 300 },
      password: { minScore: body.policies.password.minScore - 1 },
    };

    for (const [scope, missing] of [
      ['qauth:admin:read qauth:admin:write', 'qauth:admin:security'],
      ['qauth:admin:read qauth:admin:security', 'qauth:admin:write'],
    ]) {
      const { token } = await adminWith(realm.id, 'security-admin', scope);
      const { etag } = await read(realm.id, token);
      const refused = await patch(realm.id, token, mixed, etag);
      expect(refused.statusCode, scope).toBe(403);
      expect(refused.headers['www-authenticate']).toContain('error="insufficient_scope"');
      expect(refused.headers['www-authenticate']).toContain(missing);
    }

    const requester = await adminWith(realm.id, 'security-admin');
    const { done, approvalId } = await approvedPatch(realm.id, requester, mixed);
    expect(done.statusCode, done.body).toBe(200);
    expect(done.json<RealmBody>().policies).toMatchObject(mixed);
    const { rows } = await app().dbPool.query<{ id: string; status: string }>(
      'SELECT id, status FROM admin_approvals WHERE realm_id = $1',
      [realm.id]
    );
    expect(rows).toEqual([{ id: approvalId, status: 'consumed' }]);
  });

  // Scenario 6.
  it('answers 428 without If-Match and 412 with a stale one, changing nothing', async () => {
    const realm = await tenant('alpha');
    const editor = await adminWith(realm.id, 'editor');
    const { etag } = await read(realm.id, editor.token);
    const body = { tokens: { accessTokenLifespanSeconds: 300 } };

    expect((await patch(realm.id, editor.token, body, undefined)).statusCode).toBe(428);
    const moved = await patch(realm.id, editor.token, body, etag);
    expect(moved.statusCode, moved.body).toBe(200);
    expect((await patch(realm.id, editor.token, body, etag)).statusCode).toBe(412);
    expect((await read(realm.id, editor.token)).etag).toBe(moved.headers['etag']);
  });

  // Scenario 7, and the bound of d-1102-02.
  it('answers 400 validation_error for a field the policies do not have, and 422 for a value out of bounds', async () => {
    const realm = await tenant('alpha');
    const editor = await adminWith(realm.id, 'editor');
    const { etag } = await read(realm.id, editor.token);

    for (const body of [{ tokens: { lifetime: 60 } }, { sessions: {} }, { mail: null }]) {
      const refused = await patch(realm.id, editor.token, body, etag);
      expect(refused.statusCode, JSON.stringify(body)).toBe(400);
      expect(refused.json()).toMatchObject({ code: 'validation_error' });
    }

    const tooLong = await patch(
      realm.id,
      editor.token,
      { bruteForce: { lockoutSeconds: 86_401, windowSeconds: 86_401 } },
      etag
    );
    expect(tooLong.statusCode).toBe(422);
    expect(tooLong.json()).toMatchObject({ code: 'unprocessable_content' });
    expect(
      tooLong
        .json<{ errors: { pointer: string }[] }>()
        .errors.map((error) => error.pointer)
        .sort()
    ).toEqual(['/bruteForce/lockoutSeconds', '/bruteForce/windowSeconds']);
    expect((await read(realm.id, editor.token)).etag).toBe(etag);
  });

  // Scenario 8: a realm outside the caller's grants does not exist for it.
  it('answers 404 for a realm outside the grants of the caller', async () => {
    const granted = await tenant('alpha');
    const other = await tenant('beta');
    const { token } = await adminWith(granted.id, 'security-admin');

    const read404 = await send('GET', realmPath(other.id), token);
    expect(read404.statusCode).toBe(404);
    const patch404 = await patch(other.id, token, { password: { minScore: 4 } }, '"0"');
    expect(patch404.statusCode).toBe(404);
    // The same answer as for a realm that does not exist.
    const missing = await send('GET', realmPath('018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f'), token);
    expect(missing.statusCode).toBe(404);
    expect(read404.json<{ detail?: string }>().detail).toBe(
      missing.json<{ detail?: string }>().detail
    );
    expect(await auditRows(other.id)).toEqual([]);
  });

  // Acceptance criterion: a patch refused by its validation is rolled back,
  // and leaves the version as it was and no change in the audit log (the
  // refusal row the pipeline keeps for every refused call holds no diff).
  it('rolls a patch the policy rules refuse back, leaving the version and recording no change', async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');
    const { etag } = await read(realm.id, requester.token);

    // SMTP without a host, port, user or sender: a rule of the store refuses
    // it inside the handler's transaction, after the approval.
    const { done } = await approvedPatch(realm.id, requester, { mail: { provider: 'smtp' } });
    expect(done.statusCode, done.body).toBe(422);
    expect(done.json()).toMatchObject({ code: 'unprocessable_content' });
    expect(done.json<{ errors: { pointer: string }[] }>().errors.map((e) => e.pointer)).toContain(
      '/mail/smtp/host'
    );

    const { etag: after, body } = await read(realm.id, requester.token);
    expect(after).toBe(etag);
    expect(body.policies.mail.provider).toBe('mock');
    const rows = (await auditRows(realm.id)).filter(
      (row) => row.operation_id === 'realms.policies.update'
    );
    expect(rows.map((row) => row.outcome)).not.toContain('succeeded');
    expect(rows.every((row) => row.masked_diff === null)).toBe(true);
  });

  // Acceptance criterion: a secret is set only sealed, and its value never
  // comes back, nor reaches the audit log, an approval, an event or a log.
  it('sets the SMTP password from a sealed value, and never shows it anywhere', async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');
    const logStart = logLines.length;

    const sealed = await send('POST', `${realmPath(realm.id)}/secrets/seal`, requester.token, {
      operation: 'realms.policies.update',
      member: '/mail/smtp/password',
      value: SMTP_PASSWORD,
    });
    expect(sealed.statusCode, sealed.body).toBe(200);
    const body = {
      mail: { smtp: { password: { sealed: sealed.json<{ sealed: string }>().sealed } } },
    };

    const { done, responses } = await approvedPatch(realm.id, requester, body);
    expect(done.statusCode, done.body).toBe(200);
    expect(done.json<RealmBody>().policies.mail.smtp).toMatchObject({ passwordSet: true });
    expect(await app().realmSecretStore?.isSet(realm.id, 'mail.smtp.password')).toBe(true);
    const read200 = await send('GET', realmPath(realm.id), requester.token);

    for (const response of [sealed, ...responses, read200]) {
      expect(response.body).not.toContain(SMTP_PASSWORD);
      expect(JSON.stringify(response.headers)).not.toContain(SMTP_PASSWORD);
    }

    // The audit row says which secret changed, by its marker, and no value.
    const succeeded = (await auditRows(realm.id)).filter(
      (row) => row.operation_id === 'realms.policies.update' && row.outcome === 'succeeded'
    );
    expect(succeeded).toEqual([
      expect.objectContaining({
        masked_diff: {
          before: expect.objectContaining({ policies: { mail: { smtp: { password: '***' } } } }),
          after: expect.objectContaining({ policies: { mail: { smtp: { password: '***' } } } }),
        },
      }),
    ]);
    for (const table of ['admin_audit_log', 'events', 'admin_approvals', 'realm_secrets']) {
      expect(await rowsText(table, realm.id), table).not.toContain(SMTP_PASSWORD);
    }
    expect(logLines.slice(logStart).join('\n')).not.toContain(SMTP_PASSWORD);
  });

  // Scenario 9: every call above left its row, and the chain verifies.
  it('keeps an audit chain that verifies across reads, writes, refusals and approved changes', async () => {
    const realm = await tenant('alpha');
    const editor = await adminWith(realm.id, 'editor');
    const requester = await adminWith(realm.id, 'security-admin');
    const { etag, body } = await read(realm.id, editor.token);

    const written = await patch(
      realm.id,
      editor.token,
      { tokens: { accessTokenLifespanSeconds: 300 } },
      etag
    );
    expect(written.statusCode).toBe(200);
    expect((await patch(realm.id, editor.token, {}, etag)).statusCode).toBe(412);
    const { done } = await approvedPatch(realm.id, requester, {
      password: { minScore: body.policies.password.minScore - 1 },
    });
    expect(done.statusCode, done.body).toBe(200);

    const rows = await auditRows(realm.id);
    expect(rows.length).toBeGreaterThanOrEqual(4);
    await expect(
      app().repositories.adminAuditLog.verifyAdminAuditChain(realm.id)
    ).resolves.toMatchObject({ ok: true, rowsChecked: rows.length });
  });
});
