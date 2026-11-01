import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { TestApprovalFactor } from '../testing/approval-factor';
import { fixturePluginImporter, fixturePluginMethod } from '../testing/auth-method-plugins';
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
 * THE PLUGIN OPERATIONS OF THE ADMIN API (#600, ADR-019 Decisions 7, 10 and
 * 12), against a real Postgres and Redis.
 *
 * The suite boots the real app with the admin listener and its own operation
 * registry, and one fixture plugin (`corp`, type `corp_sso`) whose config has
 * a secret member, `clientSecret`. Approvals are given by calling the
 * approval engine with the test factor, as the approval page will (#617,
 * #623).
 *
 * Each test acts on a realm of its own, which gets its keys: a plugin secret
 * is encrypted with the realm's `data_at_rest` key.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const PLUGIN_PACKAGE = '@example/qauth-plugin-corp-sso';

/** The secret the tests set: it must never come back, in any form but a ciphertext. */
const SECRET = 'corp-client-secret-4f1c9a7e-never-shown';

const CONFIG = { issuer: 'https://idp.example', clientId: 'qauth' };

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

describe('the plugin operations of the admin API (#600, real containers)', () => {
  let booted: BootedAuthServer | undefined;
  let test: TestApprovalFactor;

  beforeAll(async () => {
    if (!dockerUp || !infra || !jwt) return;
    booted = await bootAuthServer(
      {
        ...baseEnvironment(infra, jwt),
        ADMIN_API_ENABLED: 'true',
        AUTH_METHOD_PLUGINS: PLUGIN_PACKAGE,
        PLUGIN_API_ENABLED: 'true',
      },
      {
        // The server's own operation registry and admin routes.
        adminListener: async () => ({}),
        authMethodPlugins: {
          importPackage: fixturePluginImporter({
            [PLUGIN_PACKAGE]: {
              authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }),
            },
          }),
        },
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

  /** A realm of the test's own, with its keys, and its host. */
  async function tenant(name: string): Promise<{ id: string; host: string }> {
    const host = `${name}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    await provisionRealmKeys(app(), name);
    return { id: realm.id, host };
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

  const pluginPath = (realmId: string, suffix = '') =>
    `/admin/v1-rc.0/realms/${realmId}/plugins${suffix}`;

  function send(
    method: 'GET' | 'POST',
    url: string,
    token: string,
    payload?: unknown,
    headers: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    return admin().inject({
      method,
      url,
      headers: { authorization: `Bearer ${token}`, ...headers },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });
  }

  /** File an approval for one request of a plugin operation and approve it with the test factor. */
  async function fileAndApprove(
    realmId: string,
    requester: Awaited<ReturnType<typeof adminWith>>,
    operation: 'plugins.update' | 'plugins.enable' | 'plugins.disable',
    body?: unknown
  ) {
    const filed = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realmId}/approvals`,
      requester.token,
      {
        operation,
        params: { plugin: 'corp' },
        ...(body === undefined ? {} : { body }),
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
    return { approvalId, filed };
  }

  /**
   * Run a security operation end to end: file its approval, approve it with
   * the test factor, and send it with the approval. Answers every response,
   * for the secret scan.
   */
  async function approved(
    realmId: string,
    requester: Awaited<ReturnType<typeof adminWith>>,
    operation: 'plugins.update' | 'plugins.enable' | 'plugins.disable',
    suffix: string,
    body?: unknown,
    headers: Record<string, string> = {}
  ) {
    const { approvalId, filed } = await fileAndApprove(realmId, requester, operation, body);
    const read = await send(
      'GET',
      `/admin/v1-rc.0/realms/${realmId}/approvals/${approvalId}`,
      requester.token
    );
    const done = await send('POST', pluginPath(realmId, suffix), requester.token, body, {
      'qauth-approval': approvalId,
      ...headers,
    });
    expect(done.statusCode, done.body).toBe(200);
    return { done, responses: [filed, read, done] };
  }

  /** Seal `value` for the plugin's client secret in the realm. */
  async function seal(realmId: string, token: string, value = SECRET) {
    const sealed = await send('POST', pluginPath(realmId, '/corp/secrets/seal'), token, {
      path: 'clientSecret',
      value,
    });
    expect(sealed.statusCode, sealed.body).toBe(200);
    return { response: sealed, sealed: sealed.json<{ sealed: string }>().sealed };
  }

  /**
   * Configure the plugin with CONFIG and the client secret `value`, sealed,
   * over the state of version `version`.
   */
  async function configure(
    realmId: string,
    requester: Awaited<ReturnType<typeof adminWith>>,
    version = 0,
    value = SECRET
  ) {
    const sealed = await seal(realmId, requester.token, value);
    const result = await approved(
      realmId,
      requester,
      'plugins.update',
      '/corp/config',
      { config: CONFIG, secrets: { clientSecret: { sealed: sealed.sealed } } },
      { 'if-match': `"${version}"` }
    );
    return { ...result, responses: [sealed.response, ...result.responses] };
  }

  /** The text of every row of `table` that belongs to the realm. */
  async function rowsText(table: string, realmId: string): Promise<string> {
    const { rows } = await app().dbPool.query<{ row: string }>(
      `SELECT t::text AS row FROM ${table} t WHERE t.realm_id = $1`,
      [realmId]
    );
    return rows.map((row) => row.row).join('\n');
  }

  // Acceptance criterion: enabling a plugin needs qauth:admin:security, and
  // qauth:admin:write is refused.
  describe('who may enable a plugin', () => {
    it('refuses a token that carries qauth:admin:write but not qauth:admin:security, naming the scope', async () => {
      const realm = await tenant('alpha');
      const { token } = await adminWith(
        realm.id,
        'security-admin',
        'qauth:admin:read qauth:admin:write'
      );

      const response = await send('POST', pluginPath(realm.id, '/corp/enable'), token);

      expect(response.statusCode).toBe(403);
      expect(response.headers['www-authenticate']).toContain('error="insufficient_scope"');
      expect(response.headers['www-authenticate']).toContain('scope="qauth:admin:security"');
      expect(
        await app().repositories.realmAuthMethodPlugins.find(realm.id, 'corp')
      ).toBeUndefined();
    });

    it("refuses an editor, whose role holds no security permission, whatever the token's scopes", async () => {
      const realm = await tenant('alpha');
      const { token } = await adminWith(realm.id, 'editor');

      const response = await send('POST', pluginPath(realm.id, '/corp/enable'), token);

      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({ code: 'forbidden' });
    });

    it('lets a security admin through the permission check to the approval gate, and enables with an approval', async () => {
      const realm = await tenant('alpha');
      const requester = await adminWith(realm.id, 'security-admin');

      const unapproved = await send('POST', pluginPath(realm.id, '/corp/enable'), requester.token);
      expect(unapproved.statusCode).toBe(403);
      expect(unapproved.json()).toMatchObject({ code: 'approval_required' });

      // A plugin is enabled only with a config its schema accepts.
      await configure(realm.id, requester);
      const { done } = await approved(realm.id, requester, 'plugins.enable', '/corp/enable');
      expect(done.json()).toMatchObject({ name: 'corp', type: 'corp_sso', enabled: true });
    });

    it('reads the plugins with qauth:admin:read alone', async () => {
      const realm = await tenant('alpha');
      const { token } = await adminWith(realm.id, 'viewer', 'qauth:admin:read');

      const list = await send('GET', pluginPath(realm.id), token);
      expect(list.statusCode, list.body).toBe(200);
      expect(list.json()).toEqual({
        items: [
          {
            name: 'corp',
            type: 'corp_sso',
            package: PLUGIN_PACKAGE,
            firstParty: false,
            contract: 'qauth-auth-method/1-rc.0',
            displayName: 'Fixture provider',
            enabled: false,
            config: {},
            secrets: [{ path: 'clientSecret', set: false }],
            version: 0,
          },
        ],
        nextCursor: null,
      });
      const one = await send('GET', pluginPath(realm.id, '/corp'), token);
      expect(one.statusCode).toBe(200);
      expect(one.headers['etag']).toBe('"0"');
      expect((await send('GET', pluginPath(realm.id, '/other'), token)).statusCode).toBe(404);
    });
  });

  // Acceptance criterion: a plugin secret never appears in a response, event
  // or log.
  it('never shows a plugin secret in a response, an audit row, an event, an approval or a log line', async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');
    const logStart = logLines.length;

    const configured = await configure(realm.id, requester);
    expect(configured.done.json()).toMatchObject({
      config: CONFIG,
      secrets: [{ path: 'clientSecret', set: true }],
      version: 1,
    });
    const enabled = await approved(realm.id, requester, 'plugins.enable', '/corp/enable');
    const read = [
      await send('GET', pluginPath(realm.id), requester.token),
      await send('GET', pluginPath(realm.id, '/corp'), requester.token),
    ];

    for (const response of [...configured.responses, ...enabled.responses, ...read]) {
      expect(response.body).not.toContain(SECRET);
      expect(JSON.stringify(response.headers)).not.toContain(SECRET);
    }

    // Stored encrypted: the row holds a data-at-rest ciphertext, never the value.
    const row = await app().repositories.realmAuthMethodPlugins.find(realm.id, 'corp');
    expect(row?.secrets['clientSecret']).toMatch(/^v1\.[^.]+\.[^.]+\.[^.]+$/);
    expect(JSON.stringify(row)).not.toContain(SECRET);

    // The audit row of the configure says which secret it set, and no value.
    const { rows: diffs } = await app().dbPool.query<{ masked_diff: unknown }>(
      `SELECT masked_diff FROM admin_audit_log
        WHERE realm_id = $1 AND operation_id = 'plugins.update' AND outcome = 'succeeded'`,
      [realm.id]
    );
    expect(diffs).toEqual([
      {
        masked_diff: expect.objectContaining({
          before: null,
          after: expect.objectContaining({
            secrets: [{ path: 'clientSecret', set: true }],
            secretsChanged: ['clientSecret'],
          }),
        }),
      },
    ]);

    // The audit rows, the events and the used approvals hold no trace of it.
    for (const table of ['admin_audit_log', 'events', 'admin_approvals']) {
      expect(await rowsText(table, realm.id), table).not.toContain(SECRET);
    }
    expect((await rowsText('admin_audit_log', realm.id)).length).toBeGreaterThan(0);

    // Nor does any line the server logged, at any level, while it ran.
    expect(logLines.slice(logStart).join('\n')).not.toContain(SECRET);
  });

  it('refuses a secret sent among the plain config members, before any approval stores it', async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');

    const filed = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realm.id}/approvals`,
      requester.token,
      {
        operation: 'plugins.update',
        params: { plugin: 'corp' },
        body: { config: { ...CONFIG, clientSecret: SECRET } },
      }
    );
    expect(filed.statusCode).toBe(400);
    expect(filed.body).not.toContain(SECRET);
    expect(await rowsText('admin_approvals', realm.id)).toBe('');
  });

  it("refuses a config the plugin's schema refuses, naming the member and never its value", async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');
    const { sealed } = await seal(realm.id, requester.token);
    const body = {
      config: { issuer: 'not a url', clientId: 'qauth' },
      secrets: { clientSecret: { sealed } },
    };
    const { approvalId } = await fileAndApprove(realm.id, requester, 'plugins.update', body);

    const refused = await send(
      'POST',
      pluginPath(realm.id, '/corp/config'),
      requester.token,
      body,
      { 'qauth-approval': approvalId, 'if-match': '"0"' }
    );
    expect(refused.statusCode).toBe(400);
    expect(refused.json<{ detail?: string }>().detail).toContain('issuer: invalid_format');
    expect(refused.body).not.toContain('not a url');
    expect(refused.body).not.toContain(SECRET);
    expect(await app().repositories.realmAuthMethodPlugins.find(realm.id, 'corp')).toBeUndefined();
    // The approval the refused request left approved holds a ciphertext, never the value.
    expect(await rowsText('admin_approvals', realm.id)).not.toContain(SECRET);
  });

  it('seals a secret for a write admin, and refuses a sealed value of another realm', async () => {
    const alpha = await tenant('alpha');
    const beta = await tenant('beta');
    const editor = await adminWith(alpha.id, 'editor');
    const viewer = await adminWith(alpha.id, 'viewer', 'qauth:admin:read');

    // Sealing changes nothing, so a write admin may; a reader may not.
    const { response, sealed } = await seal(alpha.id, editor.token);
    expect(response.json()).toEqual({
      path: 'clientSecret',
      sealed: expect.stringMatching(/^v1\./),
    });
    expect(response.body).not.toContain(SECRET);
    expect(await app().repositories.realmAuthMethodPlugins.find(alpha.id, 'corp')).toBeUndefined();
    const refused = await send('POST', pluginPath(alpha.id, '/corp/secrets/seal'), viewer.token, {
      path: 'clientSecret',
      value: SECRET,
    });
    expect(refused.statusCode).toBe(403);
    const notSecret = await send('POST', pluginPath(alpha.id, '/corp/secrets/seal'), editor.token, {
      path: 'clientId',
      value: SECRET,
    });
    expect(notSecret.statusCode).toBe(400);

    // Alpha's sealed value does not open in beta.
    const requester = await adminWith(beta.id, 'security-admin');
    const body = { config: CONFIG, secrets: { clientSecret: { sealed } } };
    const { approvalId } = await fileAndApprove(beta.id, requester, 'plugins.update', body);
    const foreign = await send('POST', pluginPath(beta.id, '/corp/config'), requester.token, body, {
      'qauth-approval': approvalId,
      'if-match': '"0"',
    });
    expect(foreign.statusCode).toBe(400);
    expect(await app().repositories.realmAuthMethodPlugins.find(beta.id, 'corp')).toBeUndefined();
  });

  // Acceptance criterion: a disabled plugin's routes answer 404.
  it("answers 404 for a disabled plugin's routes, as for a path no route serves, and serves them while it is on", async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');
    const browser = (method: 'GET' | 'POST', url: string, payload?: string) =>
      app().inject({
        method,
        url,
        authority: realm.host,
        ...(payload === undefined
          ? {}
          : { payload, headers: { 'content-type': 'application/x-www-form-urlencoded' } }),
      });
    // The not_found document echoes the path it was asked for: compare with
    // the path written out of it, and without the trace id.
    const comparable = (response: LightMyRequestResponse, path: string) => {
      const body = { ...response.json<Record<string, unknown>>() };
      delete body['trace_id'];
      if (body['instance'] === path) body['instance'] = '<path>';
      if (typeof body['detail'] === 'string')
        body['detail'] = body['detail'].replace(path, '<path>');
      return { status: response.statusCode, body };
    };
    const CALLBACK = '/upstream/corp_sso/callback';
    const NOWHERE = '/upstream/corp_sso/nowhere';
    const absent = comparable(await browser('GET', NOWHERE), NOWHERE);
    const absentPost = comparable(await browser('POST', NOWHERE, 'a=b'), NOWHERE);
    expect(absent.status).toBe(404);
    expect(absent.body['code']).toBe('not_found');
    const callback = async () => comparable(await browser('GET', `${CALLBACK}?state=x`), CALLBACK);

    // Installed, never enabled in the realm: as absent as a path no route
    // serves, and refused before a malformed body is read.
    expect(await callback()).toEqual(absent);
    expect(comparable(await browser('POST', CALLBACK, '%zz=&'), CALLBACK)).toEqual(absentPost);

    await configure(realm.id, requester);
    // Configured, still off.
    expect(await callback()).toEqual(absent);

    await approved(realm.id, requester, 'plugins.enable', '/corp/enable');
    // On: the route answers. No upstream sign-in is pending in this browser.
    const on = await browser('GET', `${CALLBACK}?state=x`);
    expect(on.statusCode).toBe(400);

    await approved(realm.id, requester, 'plugins.disable', '/corp/disable');
    expect(await callback()).toEqual(absent);
    // The config is kept: the plugin is off, not forgotten.
    expect(await app().repositories.realmAuthMethodPlugins.find(realm.id, 'corp')).toMatchObject({
      enabled: false,
      config: CONFIG,
    });

    // Another realm never had it on.
    const other = await tenant('beta');
    const elsewhere = await app().inject({
      method: 'GET',
      url: `${CALLBACK}?state=x`,
      authority: other.host,
    });
    expect(elsewhere.statusCode).toBe(404);
  });

  it('refuses a write named against a state that moved with 412, and a configure that names none with 428', async () => {
    const realm = await tenant('alpha');
    const requester = await adminWith(realm.id, 'security-admin');
    await configure(realm.id, requester);

    // A second configure written against version 0, which moved to 1.
    const { sealed } = await seal(realm.id, requester.token, 'another-client-secret-value');
    const body = { config: CONFIG, secrets: { clientSecret: { sealed } } };
    const update = await fileAndApprove(realm.id, requester, 'plugins.update', body);
    const unnamed = await send(
      'POST',
      pluginPath(realm.id, '/corp/config'),
      requester.token,
      body,
      {
        'qauth-approval': update.approvalId,
      }
    );
    expect(unnamed.statusCode).toBe(428);
    const moved = await send('POST', pluginPath(realm.id, '/corp/config'), requester.token, body, {
      'qauth-approval': update.approvalId,
      'if-match': '"0"',
    });
    expect(moved.statusCode).toBe(412);

    const { approvalId } = await fileAndApprove(realm.id, requester, 'plugins.enable');

    const stale = await send(
      'POST',
      pluginPath(realm.id, '/corp/enable'),
      requester.token,
      undefined,
      {
        'qauth-approval': approvalId,
        'if-match': '"0"',
      }
    );
    expect(stale.statusCode).toBe(412);
    expect((await app().repositories.realmAuthMethodPlugins.find(realm.id, 'corp'))?.enabled).toBe(
      false
    );
  });
});
