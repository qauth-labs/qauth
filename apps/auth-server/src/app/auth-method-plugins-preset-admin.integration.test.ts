import {
  EXAMPLE_TENANT_PRESET_ID,
  EXAMPLE_TENANT_PRESET_PACKAGE,
  EXAMPLE_TENANT_PRESET_SECRET_PATH,
  EXAMPLE_TENANT_PRESET_TYPE,
  exampleTenantIssuer,
  exampleTenantPresetPackage,
} from '@qauth-labs/fastify-plugin-federation/src/testing/upstream-oidc-fixtures';
import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import type { FastifyInstance, FastifyRequest, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  signBoundAccessToken,
} from '../testing/admin-dpop';
import type { TestApprovalFactor } from '../testing/approval-factor';
import { fixturePluginImporter } from '../testing/auth-method-plugins';
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
 * A PRESET PLUGIN'S KEPT SECRET THROUGH `plugins.update` (#1031, ADR-019
 * Decision 12), against a real Postgres and Redis.
 *
 * The suite boots the real app with the admin listener and one preset plugin
 * on the generic upstream OpenID Connect client (#951), from the first-party
 * list: the tenant preset, whose `tenant` member is no URL and shapes the
 * issuer's path (`https://idp.example.com/<tenant>`), and whose
 * `tokenEndpoint` member sets the token endpoint by hand on the provider's
 * one origin. The preset names where its secret goes (`secretDestination`),
 * so a configure that keeps the stored secret while either changes is
 * refused, as the generic client asks for its secret again; the URL rule,
 * which compares only origins, would see neither.
 *
 * Each test acts on a realm of its own, which gets its keys: a plugin secret
 * is encrypted with the realm's `data_at_rest` key.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const PLUGIN = EXAMPLE_TENANT_PRESET_ID;
const SECRET_MEMBER = `/secrets/${EXAMPLE_TENANT_PRESET_SECRET_PATH}`;

/** The secret the tests set first, and the one they seal again for a new destination. */
const SECRET = 'tenant-preset-secret-3b9e2d71-never-shown';
const NEW_SECRET = 'tenant-preset-secret-for-the-new-tenant';

const CONFIG = { tenant: 'alpha', clientId: 'qauth' };
const TOKEN_ENDPOINT = `${exampleTenantIssuer('alpha')}/oauth/token`;

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

describe("a preset plugin's kept secret through plugins.update (#1031, real containers)", () => {
  let booted: BootedAuthServer | undefined;
  let test: TestApprovalFactor;

  beforeAll(async () => {
    if (!dockerUp || !infra || !jwt) return;
    booted = await bootAuthServer(
      {
        ...baseEnvironment(infra, jwt),
        ...ADMIN_LISTENER_ENVIRONMENT,
        AUTH_METHOD_PLUGINS: EXAMPLE_TENANT_PRESET_PACKAGE,
      },
      {
        // The server's own operation registry and admin routes.
        adminListener: async () => ({}),
        authMethodPlugins: {
          importPackage: fixturePluginImporter({
            [EXAMPLE_TENANT_PRESET_PACKAGE]: exampleTenantPresetPackage(),
          }),
          firstParty: [EXAMPLE_TENANT_PRESET_PACKAGE],
        },
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
  async function tenantRealm(name: string): Promise<{ id: string }> {
    const host = `${name}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    await provisionRealmKeys(app(), name);
    return { id: realm.id };
  }

  /** An operator-realm security admin of `realmId`: its token and its account as an approver. */
  async function securityAdmin(realmId: string) {
    const operator = await operatorRealm();
    const userId = (
      await app().repositories.users.create({ realmId: operator.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: 'security-admin' },
      targetRealmId: realmId,
      createdBy: null,
    });
    const token = await signBoundAccessToken(app(), operator, {
      sub: userId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope: ALL_ADMIN_SCOPES,
    });
    return { token, approver: { realmId: operator.id, accountId: userId } };
  }

  type Requester = Awaited<ReturnType<typeof securityAdmin>>;

  const pluginPath = (realmId: string, suffix: string) =>
    `/admin/v1-rc.0/realms/${realmId}/plugins/${PLUGIN}${suffix}`;

  /** A call with `token` under the `DPoP` scheme and a fresh proof of its key (#520). */
  async function send(
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

  /** File an approval for one request of a plugin operation and approve it with the test factor. */
  async function fileAndApprove(
    realmId: string,
    requester: Requester,
    operation: 'plugins.update' | 'plugins.enable',
    body: unknown
  ): Promise<string> {
    const filed = await send(`/admin/v1-rc.0/realms/${realmId}/approvals`, requester.token, {
      operation,
      params: { plugin: PLUGIN },
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
    return approvalId;
  }

  /** Send an approved plugin operation and answer its response, whatever its status. */
  async function sendApproved(
    realmId: string,
    requester: Requester,
    operation: 'plugins.update' | 'plugins.enable',
    suffix: string,
    body: unknown
  ): Promise<LightMyRequestResponse> {
    const approvalId = await fileAndApprove(realmId, requester, operation, body);
    return send(pluginPath(realmId, suffix), requester.token, body, {
      'qauth-approval': approvalId,
    });
  }

  /** Seal `value` for the preset's client secret in the realm (`secrets.seal`, #984). */
  async function seal(realmId: string, token: string, value: string): Promise<string> {
    const sealed = await send(`/admin/v1-rc.0/realms/${realmId}/secrets/seal`, token, {
      operation: 'plugins.update',
      member: SECRET_MEMBER,
      params: { plugin: PLUGIN },
      value,
    });
    expect(sealed.statusCode, sealed.body).toBe(200);
    return sealed.json<{ sealed: string }>().sealed;
  }

  /** Configure the preset with `config` and the client secret `value`, sealed, over version `version`. */
  async function configure(
    realmId: string,
    requester: Requester,
    config: Record<string, unknown>,
    version = 0,
    value = SECRET
  ): Promise<LightMyRequestResponse> {
    const sealed = await seal(realmId, requester.token, value);
    const done = await sendApproved(realmId, requester, 'plugins.update', '/config', {
      version,
      config,
      secrets: { [EXAMPLE_TENANT_PRESET_SECRET_PATH]: { sealed } },
    });
    expect(done.statusCode, done.body).toBe(200);
    return done;
  }

  /** The realm's stored state of the preset. */
  async function stored(realmId: string) {
    return app().repositories.realmAuthMethodPlugins.find(realmId, PLUGIN);
  }

  /** Enable the preset over version `version`, and answer the config its context is handed. */
  async function contextConfig(
    realmId: string,
    requester: Requester,
    version: number
  ): Promise<unknown> {
    const enabled = await sendApproved(realmId, requester, 'plugins.enable', '/enable', {
      version,
    });
    expect(enabled.statusCode, enabled.body).toBe(200);
    // Imported once the boot reset the modules, as the engine is.
    const { authMethodPluginContext } = await import('./helpers/auth-method-plugins');
    const realmRow = await app().repositories.realms.findById(realmId);
    const method = app().authMethodPlugins.ofType(EXAMPLE_TENANT_PRESET_TYPE)?.method;
    if (realmRow === undefined || method === undefined) throw new Error('realm or plugin missing');
    // The context the preset's routes build for a request on the realm's host.
    const request = { realm: realmRow, log: app().log } as unknown as FastifyRequest;
    return (await authMethodPluginContext(app(), request, method)).config;
  }

  /** Expect `response` to be the refusal of a kept secret that would follow a new destination. */
  function expectSecretMovedRefusal(response: LightMyRequestResponse): void {
    expect(response.statusCode, response.body).toBe(400);
    expect(response.headers['content-type']).toContain('application/problem+json');
    const detail = response.json<{ detail?: string }>().detail;
    expect(detail).toContain('the plugin names another destination for its secrets');
    expect(detail).toContain(
      `the stored secret "${EXAMPLE_TENANT_PRESET_SECRET_PATH}" was set for the old one: seal it again`
    );
    expect(response.body).not.toContain(SECRET);
  }

  // Acceptance criterion: a configure that changes the issuer through a
  // member that shapes its path, and keeps the stored secret, answers 400,
  // and the stored config is unchanged.
  it('refuses a configure that moves the issuer through the tenant while it keeps the stored secret', async () => {
    const realm = await tenantRealm('alpha');
    const requester = await securityAdmin(realm.id);
    await configure(realm.id, requester, CONFIG);
    const before = await stored(realm.id);
    expect(before).toMatchObject({ version: 1, config: CONFIG });

    const moved = { version: 1, config: { ...CONFIG, tenant: 'beta' } };
    expectSecretMovedRefusal(
      await sendApproved(realm.id, requester, 'plugins.update', '/config', moved)
    );
    expect(await stored(realm.id)).toMatchObject({
      version: 1,
      config: CONFIG,
      secrets: before?.secrets,
    });
  });

  // Acceptance criterion: the same holds for a token endpoint set by hand
  // that changes on the same origin.
  it('refuses a configure that sets or moves the token endpoint on the same origin while it keeps the stored secret', async () => {
    const realm = await tenantRealm('alpha');
    const requester = await securityAdmin(realm.id);
    const withToken = { ...CONFIG, tokenEndpoint: TOKEN_ENDPOINT };
    await configure(realm.id, requester, withToken);
    const before = await stored(realm.id);

    // Another path of the same origin: the URL rule would see no new origin.
    const moved = { version: 1, config: { ...withToken, tokenEndpoint: `${TOKEN_ENDPOINT}-2` } };
    expectSecretMovedRefusal(
      await sendApproved(realm.id, requester, 'plugins.update', '/config', moved)
    );
    // Back to the discovered token endpoint.
    const discovered = { version: 1, config: CONFIG };
    expectSecretMovedRefusal(
      await sendApproved(realm.id, requester, 'plugins.update', '/config', discovered)
    );
    expect(await stored(realm.id)).toMatchObject({
      version: 1,
      config: withToken,
      secrets: before?.secrets,
    });
  });

  // Acceptance criterion: the same update with a newly sealed secret
  // succeeds, and the context opens the new secret.
  it('takes the new tenant with a newly sealed secret, which the context opens', async () => {
    const realm = await tenantRealm('alpha');
    const requester = await securityAdmin(realm.id);
    await configure(realm.id, requester, CONFIG);

    const moved = { ...CONFIG, tenant: 'beta' };
    const done = await configure(realm.id, requester, moved, 1, NEW_SECRET);
    expect(done.json()).toMatchObject({
      version: 2,
      config: moved,
      secrets: [{ path: EXAMPLE_TENANT_PRESET_SECRET_PATH, set: true }],
    });
    expect(done.body).not.toContain(NEW_SECRET);
    expect(await contextConfig(realm.id, requester, 2)).toEqual({
      ...moved,
      [EXAMPLE_TENANT_PRESET_SECRET_PATH]: NEW_SECRET,
    });
  });

  // Acceptance criterion: an update that changes neither the issuer nor the
  // token endpoint keeps the stored secret.
  it('keeps the stored secret for a configure that changes neither the issuer nor the token endpoint', async () => {
    const realm = await tenantRealm('alpha');
    const requester = await securityAdmin(realm.id);
    const withToken = { ...CONFIG, tokenEndpoint: TOKEN_ENDPOINT };
    await configure(realm.id, requester, withToken);
    const before = await stored(realm.id);

    const renamed = { ...withToken, clientId: 'qauth-2' };
    const kept = await sendApproved(realm.id, requester, 'plugins.update', '/config', {
      version: 1,
      config: renamed,
    });
    expect(kept.statusCode, kept.body).toBe(200);
    expect(kept.json()).toMatchObject({
      version: 2,
      config: renamed,
      secrets: [{ path: EXAMPLE_TENANT_PRESET_SECRET_PATH, set: true }],
    });
    // The very ciphertext stored before, never sealed again.
    expect((await stored(realm.id))?.secrets).toEqual(before?.secrets);
    expect(await contextConfig(realm.id, requester, 2)).toEqual({
      ...renamed,
      [EXAMPLE_TENANT_PRESET_SECRET_PATH]: SECRET,
    });
  });
});
