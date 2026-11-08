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
 * THE PREVIEW OF A REALM POLICY CHANGE (#589, ADR-020 §5), against a real
 * Postgres and Redis: `POST /admin/v1-rc.0/realms/{realmId}/policies/preview`
 * answers what `realms.policies.update` would make of the same merge patch,
 * and writes nothing but the audit row every admin call leaves (ADR-019
 * Decision 7).
 *
 * The suite boots the real app with the admin listener and the server's own
 * operation registry, as `admin-realms.integration.test.ts` does. Each test
 * acts on a realm of its own, which gets its keys: a secret policy field is
 * sealed with the realm's `data_at_rest` key.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const MERGE_PATCH = 'application/merge-patch+json';

/** The SMTP passwords the tests seal: they must never come back, in any form. */
const SMTP_PASSWORD = 'smtp-password-0c6f1e7a-never-previewed';
const OTHER_SMTP_PASSWORD = 'smtp-password-93d2b4f8-never-previewed';

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

interface Policies {
  password: { minScore: number; minLength: number };
  tokens: { accessTokenLifespanSeconds: number };
  bruteForce: { lockoutSeconds: number };
  mail: { invalidateExistingTokensOnResend: boolean; smtp: Record<string, unknown> };
}

interface PreviewBody {
  etag: string;
  class: 'write' | 'security';
  effects: string[];
  permissions: string[];
  scopes: string[];
  approvalRequired: boolean;
  twoAdmin: 'recommended' | 'mandatory' | null;
  eligibleApprovers: number | null;
  changes: {
    path: string;
    before: unknown;
    after: unknown;
    direction: 'tightening' | 'loosening' | 'neutral';
    class: 'write' | 'security';
    effects: string[];
    permissions: string[];
    scopes: string[];
    secret: boolean;
    environmentBound: boolean;
  }[];
}

interface AuditRow {
  operation_id: string;
  operation_class: string;
  effects: string[];
  outcome: string;
  masked_diff: unknown;
}

describe('the preview of a realm policy change (#589, real containers)', () => {
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
  const previewPath = (realmId: string) => `${policiesPath(realmId)}/preview`;

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
    return {
      etag: response.headers['etag'] as string,
      policies: response.json<{ policies: Policies }>().policies,
    };
  }

  /** The preview of a policy patch: a JSON Merge Patch, sent with no `If-Match`. */
  async function preview(
    realmId: string,
    token: string,
    body: unknown,
    headers: Record<string, string> = {}
  ) {
    return send('POST', previewPath(realmId), token, JSON.stringify(body), {
      'content-type': MERGE_PATCH,
      ...headers,
    });
  }

  /** A preview `token` may see, as its body. */
  async function previewed(realmId: string, token: string, body: unknown): Promise<PreviewBody> {
    const response = await preview(realmId, token, body);
    expect(response.statusCode, response.body).toBe(200);
    return response.json<PreviewBody>();
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

  /** Seal `value` for the SMTP password of `realmId`, as the console does before a patch. */
  async function seal(realmId: string, requester: Admin, value: string): Promise<string> {
    const sealed = await send('POST', `${realmPath(realmId)}/secrets/seal`, requester.token, {
      operation: 'realms.policies.update',
      member: '/mail/smtp/password',
      value,
    });
    expect(sealed.statusCode, sealed.body).toBe(200);
    return sealed.json<{ sealed: string }>().sealed;
  }

  /** Run a security patch end to end: file it, approve it, and send it with the approval. */
  async function approvedPatch(realmId: string, requester: Admin, body: unknown) {
    const { etag } = await read(realmId, requester.token);
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
    return patch(realmId, requester.token, body, etag, { 'qauth-approval': approvalId });
  }

  async function auditRows(realmId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT operation_id, operation_class, effects, outcome, masked_diff
         FROM admin_audit_log WHERE realm_id = $1 ORDER BY seq`,
      [realmId]
    );
    return rows;
  }

  /** The text of every row of `table` that belongs to the realm. */
  async function rowsText(table: string, realmId: string): Promise<string> {
    const { rows } = await app().dbPool.query<{ row: string }>(
      `SELECT t::text AS row FROM ${table} t WHERE t.realm_id = $1 ORDER BY t::text`,
      [realmId]
    );
    return rows.map((row) => row.row).join('\n');
  }

  /** What a save would change of the realm: its row, its approvals, its events and its secrets. */
  async function stored(realmId: string) {
    const { rows } = await app().dbPool.query<{ row: string }>(
      'SELECT r::text AS row FROM realms r WHERE r.id = $1',
      [realmId]
    );
    return {
      realm: rows.map((row) => row.row).join('\n'),
      approvals: await rowsText('admin_approvals', realmId),
      events: await rowsText('events', realmId),
      secrets: await rowsText('realm_secrets', realmId),
    };
  }

  // Acceptance criterion of #589: a loosening is a security change, which
  // needs an approval.
  it('reports a loosening as a security change that needs an approval', async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');
    const { etag, policies } = await read(realm.id, requester.token);
    const lowered = policies.password.minScore - 1;

    const answer = await previewed(realm.id, requester.token, {
      password: { minScore: lowered },
    });
    expect(answer).toEqual({
      etag,
      class: 'security',
      effects: ['credential-path'],
      permissions: ['realms.policies.security', 'realms.read'],
      scopes: ['qauth:admin:read', 'qauth:admin:security'],
      approvalRequired: true,
      // A second admin is recommended for every security change until the
      // two-admin rule is built (#521).
      twoAdmin: 'recommended',
      // The requester never approves its own request, and no one else holds
      // approvals.approve on the realm.
      eligibleApprovers: 0,
      changes: [
        {
          path: 'password.minScore',
          before: policies.password.minScore,
          after: lowered,
          direction: 'loosening',
          class: 'security',
          effects: ['credential-path'],
          permissions: ['realms.policies.security'],
          scopes: ['qauth:admin:security'],
          secret: false,
          environmentBound: false,
        },
      ],
    });
  });

  // Acceptance criterion of #589: a tightening is a write, which needs no
  // approval.
  it('reports a tightening as a write that needs no approval', async () => {
    const realm = await tenant('alpha');
    const editor = await adminWith(realm.id, 'editor');
    const { etag, policies } = await read(realm.id, editor.token);

    const answer = await previewed(realm.id, editor.token, {
      tokens: { accessTokenLifespanSeconds: 300 },
    });
    expect(answer).toEqual({
      etag,
      class: 'write',
      effects: [],
      permissions: ['realms.policies.write', 'realms.read'],
      scopes: ['qauth:admin:read', 'qauth:admin:write'],
      approvalRequired: false,
      twoAdmin: null,
      eligibleApprovers: null,
      changes: [
        {
          path: 'tokens.accessTokenLifespanSeconds',
          before: policies.tokens.accessTokenLifespanSeconds,
          after: 300,
          direction: 'tightening',
          class: 'write',
          effects: [],
          permissions: ['realms.policies.write'],
          scopes: ['qauth:admin:write'],
          secret: false,
          environmentBound: false,
        },
      ],
    });
  });

  // Acceptance criterion of #589: for every fixture, the preview and the real
  // update classify the same way. Each fixture is previewed, then sent as the
  // real patch against the same state with a token that holds exactly the
  // scopes the preview named: a write is saved, a security change is refused
  // for want of an approval, and the patch's audit row records the class and
  // the effects the preview reported.
  it('classifies every fixture as the real update does', async () => {
    const realm = await tenant('alpha');
    const viewer = await adminWith(realm.id, 'viewer', 'qauth:admin:read');
    const sealer = await adminWith(realm.id, 'security-admin');
    const sealed = await seal(realm.id, sealer, SMTP_PASSWORD);

    const fixtures: readonly { name: string; body: (policies: Policies) => unknown }[] = [
      {
        name: 'lowers the password score',
        body: (p) => ({ password: { minScore: p.password.minScore - 1 } }),
      },
      {
        name: 'raises the password score',
        body: (p) => ({ password: { minScore: p.password.minScore + 1 } }),
      },
      {
        name: 'raises the password length',
        body: (p) => ({ password: { minLength: p.password.minLength + 4 } }),
      },
      {
        name: 'lowers the password length',
        body: (p) => ({ password: { minLength: p.password.minLength - 1 } }),
      },
      {
        name: 'shortens the access token',
        body: () => ({ tokens: { accessTokenLifespanSeconds: 300 } }),
      },
      {
        name: 'lengthens the access token',
        body: (p) => ({
          tokens: { accessTokenLifespanSeconds: p.tokens.accessTokenLifespanSeconds + 60 },
        }),
      },
      {
        name: 'lengthens the lockout',
        body: (p) => ({ bruteForce: { lockoutSeconds: p.bruteForce.lockoutSeconds + 60 } }),
      },
      {
        name: 'turns a field no change of which is a security change',
        body: (p) => ({
          mail: { invalidateExistingTokensOnResend: !p.mail.invalidateExistingTokensOnResend },
        }),
      },
      { name: 'changes nothing', body: () => ({}) },
      {
        name: 'sends a stored value back',
        body: (p) => ({ password: { minLength: p.password.minLength } }),
      },
      {
        name: 'mixes a write and a security change',
        body: (p) => ({
          tokens: { accessTokenLifespanSeconds: 300 },
          password: { minScore: p.password.minScore - 1 },
        }),
      },
      {
        name: 'adds an operation to the two-admin set',
        body: () => ({ admin: { twoAdminMandatoryOperations: ['realms.policies.update'] } }),
      },
      {
        name: 'resets a field to its default',
        body: () => ({ registration: { cimd: { trustPolicy: null } } }),
      },
      {
        name: 'sets the SMTP password',
        body: () => ({ mail: { smtp: { password: { sealed } } } }),
      },
    ];

    for (const fixture of fixtures) {
      const { etag, policies } = await read(realm.id, viewer.token);
      const body = fixture.body(policies);
      const answer = await previewed(realm.id, viewer.token, body);
      expect(answer.etag, fixture.name).toBe(etag);

      const requester = await adminWith(realm.id, 'security-admin', answer.scopes.join(' '));
      const saved = await patch(realm.id, requester.token, body, etag);
      if (answer.class === 'write') {
        expect(saved.statusCode, `${fixture.name}: ${saved.body}`).toBe(200);
        expect(answer.approvalRequired, fixture.name).toBe(false);
      } else {
        expect(saved.statusCode, `${fixture.name}: ${saved.body}`).toBe(403);
        expect(saved.json(), fixture.name).toMatchObject({ code: 'approval_required' });
        expect(answer.approvalRequired, fixture.name).toBe(true);
      }
      const update = (await auditRows(realm.id)).filter(
        (row) => row.operation_id === 'realms.policies.update'
      );
      const last = update.at(-1);
      expect(
        { class: last?.operation_class, effects: [...(last?.effects ?? [])].sort() },
        fixture.name
      ).toEqual({ class: answer.class, effects: [...answer.effects].sort() });
    }

    // Both classes were met.
    const classes = new Set(
      (await auditRows(realm.id))
        .filter((row) => row.operation_id === 'realms.policies.update')
        .map((row) => row.operation_class)
    );
    expect([...classes].sort()).toEqual(['security', 'write']);
  }, 120_000);

  // Acceptance criterion of #589: a preview writes no row and no event. The
  // one row it leaves is the audit row of the read, which every admin call
  // leaves (ADR-019 Decision 7), with no change in it.
  it('writes nothing: no change of the realm, no approval, no event, no secret', async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');
    const { policies } = await read(realm.id, requester.token);
    const sealed = await seal(realm.id, requester, SMTP_PASSWORD);
    const before = await stored(realm.id);
    const auditBefore = (await auditRows(realm.id)).length;

    const bodies = [
      { tokens: { accessTokenLifespanSeconds: 300 } },
      { password: { minScore: policies.password.minScore - 1 } },
      { mail: { smtp: { password: { sealed } } } },
      {},
    ];
    for (const body of bodies) {
      await previewed(realm.id, requester.token, body);
    }

    expect(await stored(realm.id)).toEqual(before);
    const added = (await auditRows(realm.id)).slice(auditBefore);
    expect(added).toEqual(
      bodies.map(() => ({
        operation_id: 'realms.policies.preview',
        operation_class: 'read',
        effects: [],
        outcome: 'succeeded',
        masked_diff: null,
      }))
    );
    await expect(
      app().repositories.adminAuditLog.verifyAdminAuditChain(realm.id)
    ).resolves.toMatchObject({ ok: true });
  });

  // Acceptance criterion of #589: a secret field never appears in the
  // answer, only whether it is set.
  it('shows the SMTP password only as set or not set, never its value', async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');
    const logStart = logLines.length;
    const first = await seal(realm.id, requester, SMTP_PASSWORD);

    // Not set yet: a preview of setting it.
    const setting = await preview(realm.id, requester.token, {
      mail: { smtp: { password: { sealed: first } } },
    });
    expect(setting.statusCode, setting.body).toBe(200);
    expect(setting.json<PreviewBody>().changes).toEqual([
      expect.objectContaining({
        path: 'mail.smtp.password',
        before: 'not set',
        after: 'set',
        secret: true,
        class: 'security',
      }),
    ]);

    const saved = await approvedPatch(realm.id, requester, {
      mail: { smtp: { password: { sealed: first } } },
    });
    expect(saved.statusCode, saved.body).toBe(200);

    // Set: a preview of replacing it, and of clearing it.
    const second = await seal(realm.id, requester, OTHER_SMTP_PASSWORD);
    const replacing = await preview(realm.id, requester.token, {
      mail: { smtp: { password: { sealed: second } } },
    });
    const clearing = await preview(realm.id, requester.token, {
      mail: { smtp: { password: null } },
    });
    expect(replacing.statusCode, replacing.body).toBe(200);
    expect(clearing.statusCode, clearing.body).toBe(200);
    expect(replacing.json<PreviewBody>().changes).toEqual([
      expect.objectContaining({ path: 'mail.smtp.password', before: 'set', after: 'set' }),
    ]);
    expect(clearing.json<PreviewBody>().changes).toEqual([
      expect.objectContaining({ path: 'mail.smtp.password', before: 'set', after: 'not set' }),
    ]);

    for (const response of [setting, replacing, clearing]) {
      for (const text of [response.body, JSON.stringify(response.headers)]) {
        for (const secret of [SMTP_PASSWORD, OTHER_SMTP_PASSWORD, first, second]) {
          expect(text).not.toContain(secret);
        }
        expect(text).not.toContain('sealed');
      }
    }
    expect(await app().realmSecretStore?.isSet(realm.id, 'mail.smtp.password')).toBe(true);
    const logged = logLines.slice(logStart).join('\n');
    expect(logged).not.toContain(SMTP_PASSWORD);
    expect(logged).not.toContain(OTHER_SMTP_PASSWORD);
  });

  // Acceptance criterion of #589: a realm outside the caller's grants does
  // not exist for it, and a preview of it shows nothing.
  it('answers 404 for a realm outside the grants of the caller', async () => {
    const granted = await tenant('alpha');
    const other = await tenant('beta');
    const { token } = await adminWith(granted.id, 'security-admin');

    const outside = await preview(other.id, token, { password: { minScore: 1 } });
    expect(outside.statusCode).toBe(404);
    const missingId = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
    const missing = await preview(missingId, token, { password: { minScore: 1 } });
    expect(missing.statusCode).toBe(404);
    const answer = (response: LightMyRequestResponse, id: string) => {
      const { code, title, detail } = response.json<{
        code?: string;
        title?: string;
        detail?: string;
      }>();
      return { code, title, detail: detail?.replaceAll(id, '<realmId>') };
    };
    expect(answer(outside, other.id)).toEqual(answer(missing, missingId));
    expect(outside.body).not.toContain('minScore');
    expect(await auditRows(other.id)).toEqual([]);
  });

  it('lets a viewer with qauth:admin:read preview a change it may not save', async () => {
    const realm = await tenant('alpha');
    const viewer = await adminWith(realm.id, 'viewer', 'qauth:admin:read');
    const { etag, policies } = await read(realm.id, viewer.token);

    const answer = await previewed(realm.id, viewer.token, {
      password: { minScore: policies.password.minScore - 1 },
    });
    expect(answer).toMatchObject({ etag, class: 'security', approvalRequired: true });
    // The save itself stays the viewer's to be refused.
    const refused = await patch(
      realm.id,
      viewer.token,
      { password: { minScore: policies.password.minScore - 1 } },
      etag
    );
    expect(refused.statusCode).toBe(403);
  });

  it('counts the admins other than the requester who may approve the change', async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');
    const { policies } = await read(realm.id, requester.token);
    const loosening = { password: { minScore: policies.password.minScore - 1 } };
    const count = async () =>
      (await previewed(realm.id, requester.token, loosening)).eligibleApprovers;

    expect(await count()).toBe(0);
    await adminWith(realm.id, 'security-admin');
    expect(await count()).toBe(1);
    // Neither an editor nor a viewer holds approvals.approve, and an admin of
    // another realm approves nothing here.
    await adminWith(realm.id, 'editor');
    await adminWith(realm.id, 'viewer');
    await adminWith((await tenant('beta')).id, 'security-admin');
    expect(await count()).toBe(1);
    await adminWith(realm.id, 'security-admin');
    expect(await count()).toBe(2);
  });

  it('refuses what the update refuses: another media type, an unknown field, a value out of bounds', async () => {
    const realm = await tenant('alpha');
    const editor = await adminWith(realm.id, 'editor');
    const before = await stored(realm.id);

    const json = await preview(
      realm.id,
      editor.token,
      { tokens: { accessTokenLifespanSeconds: 300 } },
      { 'content-type': 'application/json' }
    );
    expect(json.statusCode).toBe(415);

    for (const body of [{ tokens: { lifetime: 60 } }, { sessions: {} }, { mail: null }]) {
      const refused = await preview(realm.id, editor.token, body);
      expect(refused.statusCode, JSON.stringify(body)).toBe(400);
      expect(refused.json()).toMatchObject({ code: 'validation_error' });
    }

    const tooLong = await preview(realm.id, editor.token, {
      bruteForce: { lockoutSeconds: 86_401, windowSeconds: 86_401 },
    });
    expect(tooLong.statusCode).toBe(422);
    expect(tooLong.json()).toMatchObject({ code: 'unprocessable_content' });
    expect(
      tooLong
        .json<{ errors: { pointer: string }[] }>()
        .errors.map((error) => error.pointer)
        .sort()
    ).toEqual(['/bruteForce/lockoutSeconds', '/bruteForce/windowSeconds']);
    expect(await stored(realm.id)).toEqual(before);
  });
});
