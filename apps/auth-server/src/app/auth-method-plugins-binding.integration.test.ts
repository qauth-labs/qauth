import type { AuthMethod } from '@qauth-labs/fastify-plugin-federation';
import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import type { FastifyInstance, FastifyRequest, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  signBoundAccessToken,
} from '../testing/admin-dpop';
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
 * A REALM'S PLUGIN STATE BELONGS TO THE PACKAGE AND THE TYPE THAT WROTE IT
 * (#949), against a real Postgres and Redis.
 *
 * Each test configures and enables the plugin `corp` in a realm under one
 * deployment, then boots another over the same database with another plugin
 * behind the id `corp`: another package, the same package under another type,
 * or a new version of the same package. The first two find the realm's state
 * off, its secrets closed and its enable refused until a configure writes the
 * state again for them; the version bump finds it on.
 *
 * Approvals are given by calling the approval engine with the test factor,
 * as `auth-method-plugins-admin.integration.test.ts` does.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');

/** The package the realm configures the plugin under first. */
const PACKAGE_A = '@example/qauth-plugin-corp-sso';
/** Another package that declares the same AuthMethod id. */
const PACKAGE_B = '@example/another-corp-sso';

const SECRET_A = 'corp-client-secret-of-package-a-3b9d';
const SECRET_B = 'corp-client-secret-of-package-b-71fe';
const CONFIG = { issuer: 'https://idp.example', clientId: 'qauth' };

const CALLBACK = (type: string) => `/upstream/${type}/callback?state=x`;

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

/** One booted deployment, with the modules its boot loaded. */
interface Deployment {
  readonly booted: BootedAuthServer;
  readonly app: FastifyInstance;
  readonly admin: FastifyInstance;
  readonly factor: TestApprovalFactor;
  readonly engine: typeof import('./admin/approvals/engine');
  readonly runtime: typeof import('./helpers/auth-method-plugins');
}

/** An operator-realm admin of a realm: its account, and its account as an approver. */
interface RealmAdmin {
  readonly userId: string;
  readonly approver: { readonly realmId: string; readonly accountId: string };
}

describe("a realm's plugin state is bound to the plugin that wrote it (#949, real containers)", () => {
  let current: Deployment | undefined;

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  afterEach(async () => {
    await current?.booted.close();
    current = undefined;
  });

  /**
   * Close the running deployment, if any, and boot one that loads `method`
   * from `packageName`, over the same database and Redis.
   */
  async function deploy(packageName: string, method: AuthMethod): Promise<Deployment> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    await current?.booted.close();
    current = undefined;
    const booted = await bootAuthServer(
      {
        ...baseEnvironment(infra, jwt),
        ...ADMIN_LISTENER_ENVIRONMENT,
        AUTH_METHOD_PLUGINS: packageName,
        PLUGIN_API_ENABLED: 'true',
      },
      {
        // The server's own operation registry and admin routes.
        adminListener: async () => ({}),
        authMethodPlugins: {
          importPackage: fixturePluginImporter({ [packageName]: { authMethod: method } }),
        },
      }
    );
    if (booted.admin === undefined) throw new Error('admin listener not booted');
    // Imported once the boot reset the modules, as the engine is.
    const { createTestApprovalFactor } = await import('../testing/approval-factor');
    current = {
      booted,
      app: booted.app,
      admin: booted.admin,
      factor: createTestApprovalFactor(),
      engine: await import('./admin/approvals/engine'),
      runtime: await import('./helpers/auth-method-plugins'),
    };
    return current;
  }

  /** A realm of the test's own, with its keys, and its host. */
  async function tenant(at: Deployment, name: string): Promise<{ id: string; host: string }> {
    const host = `${name}.example.com`;
    const { realm } = await at.app.repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    await provisionRealmKeys(at.app, name);
    return { id: realm.id, host };
  }

  async function operatorRealm(at: Deployment): Promise<{ id: string; issuer: string }> {
    const realm = await at.app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer) throw new Error('default realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  /** An operator-realm security admin of `realmId`. */
  async function securityAdmin(at: Deployment, realmId: string): Promise<RealmAdmin> {
    const operator = await operatorRealm(at);
    const userId = (
      await at.app.repositories.users.create({ realmId: operator.id }, testPrimaryCredential())
    ).id;
    await at.app.repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: 'security-admin' },
      targetRealmId: realmId,
      createdBy: null,
    });
    return { userId, approver: { realmId: operator.id, accountId: userId } };
  }

  /** The calls of `who` on the deployment `at`, with a token that deployment signs. */
  async function adminCalls(at: Deployment, realmId: string, who: RealmAdmin) {
    const token = await signBoundAccessToken(at.app, await operatorRealm(at), {
      sub: who.userId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope: ALL_ADMIN_SCOPES,
    });
    const pluginPath = (suffix = '') => `/admin/v1-rc.0/realms/${realmId}/plugins/corp${suffix}`;

    async function send(
      method: 'GET' | 'POST',
      url: string,
      payload?: unknown,
      headers: Record<string, string> = {}
    ): Promise<LightMyRequestResponse> {
      return at.admin.inject({
        method,
        url,
        headers: { ...(await adminCallHeaders(token, method, url)), ...headers },
        ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
      });
    }

    /** File, approve and send one request of a plugin security operation. */
    async function approvedCall(
      operation: 'plugins.update' | 'plugins.enable' | 'plugins.disable',
      suffix: string,
      body: unknown
    ): Promise<LightMyRequestResponse> {
      const filed = await send('POST', `/admin/v1-rc.0/realms/${realmId}/approvals`, {
        operation,
        params: { plugin: 'corp' },
        body,
      });
      expect(filed.statusCode, filed.body).toBe(201);
      const approvalId = filed.json<{ id: string }>().id;
      const decision = {
        realmId,
        approvalId,
        approver: who.approver,
        sessionIssuedAtMs: Date.now(),
      };
      const { challenge } = await at.engine.startApproval(at.app, at.factor, decision);
      await at.engine.completeApproval(at.app, at.factor, {
        ...decision,
        response: at.factor.answer(challenge, who.approver),
      });
      return send('POST', pluginPath(suffix), body, { 'qauth-approval': approvalId });
    }

    /** Seal `value` for the client secret of the plugin this deployment loaded. */
    async function seal(value: string): Promise<string> {
      const sealed = await send('POST', pluginPath('/secrets/seal'), {
        path: 'clientSecret',
        value,
      });
      expect(sealed.statusCode, sealed.body).toBe(200);
      return sealed.json<{ sealed: string }>().sealed;
    }

    return {
      read: () => send('GET', pluginPath()),
      /** Configure CONFIG over the state of `version`, with `secret` sealed, or no secret. */
      async configure(version: number, secret?: string): Promise<LightMyRequestResponse> {
        const secrets =
          secret === undefined ? {} : { secrets: { clientSecret: { sealed: await seal(secret) } } };
        return approvedCall('plugins.update', '/config', { version, config: CONFIG, ...secrets });
      },
      enable: (version: number) => approvedCall('plugins.enable', '/enable', { version }),
    };
  }

  /** A GET of the plugin's callback on the realm host: 404 while it is off there. */
  async function callbackStatus(at: Deployment, host: string, type: string): Promise<number> {
    const response = await at.app.inject({ method: 'GET', url: CALLBACK(type), authority: host });
    return response.statusCode;
  }

  /** The context the plugin's routes build for a request on the realm, or the error. */
  async function contextOf(at: Deployment, realmId: string, type: string): Promise<unknown> {
    const realmRow = await at.app.repositories.realms.findById(realmId);
    const method = at.app.authMethodPlugins.ofType(type)?.method;
    if (realmRow === undefined || method === undefined) throw new Error('realm or plugin missing');
    const request = { realm: realmRow, log: at.app.log } as unknown as FastifyRequest;
    return at.runtime
      .authMethodPluginContext(at.app, request, method)
      .catch((error: unknown) => error);
  }

  /**
   * Under `PACKAGE_A`, type `corp_sso`: configure the plugin in a new realm
   * with SECRET_A and enable it (state version 2), and check that it is on.
   */
  async function configuredUnderA() {
    const at = await deploy(PACKAGE_A, fixturePluginMethod({ type: 'corp_sso', id: 'corp' }));
    await resetE2eState(at.app);
    const realm = await tenant(at, 'alpha');
    const who = await securityAdmin(at, realm.id);
    const calls = await adminCalls(at, realm.id, who);
    expect((await calls.configure(0, SECRET_A)).statusCode).toBe(200);
    const enabled = await calls.enable(1);
    expect(enabled.statusCode, enabled.body).toBe(200);
    expect(enabled.json()).toMatchObject({
      enabled: true,
      configuredBy: { package: PACKAGE_A, type: 'corp_sso' },
      mismatch: null,
      version: 2,
    });
    // On: the route answers; no upstream sign-in is pending in this browser.
    expect(await callbackStatus(at, realm.host, 'corp_sso')).toBe(400);
    const stored = (await at.app.repositories.realmAuthMethodPlugins.find(realm.id, 'corp'))
      ?.secrets['clientSecret'];
    if (stored === undefined) throw new Error('the secret was not stored');
    return { realm, who, stored };
  }

  // Acceptance criterion: after the package behind an id is swapped, the
  // plugin answers 404, its stored secrets do not open, and enable is refused
  // until a configure.
  it('keeps a state another package wrote off, closed and unenabled until a configure under the new package', async () => {
    const { realm, who, stored } = await configuredUnderA();

    // The deployment now loads another package that declares the same id.
    const at = await deploy(PACKAGE_B, fixturePluginMethod({ type: 'corp_sso', id: 'corp' }));
    const calls = await adminCalls(at, realm.id, who);
    const pluginB = at.app.authMethodPlugins.find('corp');
    if (pluginB === undefined) throw new Error('package B did not load');
    expect(pluginB.package).toBe(PACKAGE_B);

    // 404, as a path no route serves, and no sign-in button.
    expect(await callbackStatus(at, realm.host, 'corp_sso')).toBe(404);
    const { upstreamProviderCatalog } = await import('./helpers/upstream-providers');
    expect(await upstreamProviderCatalog(at.app).offered(realm.id)).toEqual([]);
    expect(await contextOf(at, realm.id, 'corp_sso')).toBeInstanceOf(
      at.runtime.AuthMethodPluginDisabledError
    );

    // plugins.get says why, and shows no secret as set.
    const read = await calls.read();
    expect(read.statusCode).toBe(200);
    expect(read.json()).toMatchObject({
      package: PACKAGE_B,
      enabled: false,
      config: CONFIG,
      secrets: [{ path: 'clientSecret', set: false }],
      configuredBy: { package: PACKAGE_A, type: 'corp_sso' },
      mismatch: 'package_changed',
      version: 2,
    });

    // The stored secret does not open for package B; it still opens for the
    // package that sealed it, so the binding, nothing else, refuses it.
    const cipher = at.runtime.authMethodPluginSecretCipher(at.app);
    await expect(cipher.open(realm.id, pluginB, 'clientSecret', stored)).rejects.toMatchObject({
      code: 'DATA_DECRYPTION_FAILED',
    });
    expect(
      await cipher.open(
        realm.id,
        { id: 'corp', package: PACKAGE_A, type: 'corp_sso' },
        'clientSecret',
        stored
      )
    ).toBe(SECRET_A);

    // An approved enable is refused.
    const refused = await calls.enable(2);
    expect(refused.statusCode).toBe(400);
    expect(refused.json<{ detail?: string }>().detail).toContain('package_changed');
    expect(refused.body).not.toContain(SECRET_A);

    // A configure that does not seal the secret again keeps none of package
    // A's, and the plugin's schema needs one.
    const unsealed = await calls.configure(2);
    expect(unsealed.statusCode).toBe(400);
    expect(unsealed.json<{ detail?: string }>().detail).toContain('clientSecret: invalid_type');

    // A configure under package B, with the secret sealed again: the state is
    // B's, and still off.
    const configured = await calls.configure(2, SECRET_B);
    expect(configured.statusCode, configured.body).toBe(200);
    expect(configured.json()).toMatchObject({
      enabled: false,
      secrets: [{ path: 'clientSecret', set: true }],
      configuredBy: { package: PACKAGE_B, type: 'corp_sso' },
      mismatch: null,
      version: 3,
    });
    expect(await at.app.repositories.realmAuthMethodPlugins.find(realm.id, 'corp')).toMatchObject({
      enabled: false,
      pluginPackage: PACKAGE_B,
      pluginType: 'corp_sso',
    });
    expect(await callbackStatus(at, realm.host, 'corp_sso')).toBe(404);

    // An approved enable then turns it on, with B's secret.
    const enabled = await calls.enable(3);
    expect(enabled.statusCode, enabled.body).toBe(200);
    expect(enabled.json()).toMatchObject({ enabled: true, mismatch: null, version: 4 });
    expect(await callbackStatus(at, realm.host, 'corp_sso')).toBe(400);
    const context = await contextOf(at, realm.id, 'corp_sso');
    expect((context as { config?: unknown }).config).toEqual({ ...CONFIG, clientSecret: SECRET_B });
  }, 240_000);

  it('keeps a state the same package wrote under another type off until a configure', async () => {
    const { realm, who } = await configuredUnderA();

    // A version of package A that changed its type, and so its routes.
    const at = await deploy(PACKAGE_A, fixturePluginMethod({ type: 'corp_sso_v2', id: 'corp' }));
    const calls = await adminCalls(at, realm.id, who);

    expect(await callbackStatus(at, realm.host, 'corp_sso_v2')).toBe(404);
    expect(await contextOf(at, realm.id, 'corp_sso_v2')).toBeInstanceOf(
      at.runtime.AuthMethodPluginDisabledError
    );
    expect((await calls.read()).json()).toMatchObject({
      type: 'corp_sso_v2',
      enabled: false,
      configuredBy: { package: PACKAGE_A, type: 'corp_sso' },
      mismatch: 'type_changed',
    });
    const refused = await calls.enable(2);
    expect(refused.statusCode).toBe(400);
    expect(refused.json<{ detail?: string }>().detail).toContain('type_changed');
  }, 240_000);

  // Acceptance criterion: a version bump of the same package needs nothing.
  it('keeps the state on, and its secret open, across a new version of the same package', async () => {
    const { realm, who } = await configuredUnderA();

    // The new version: the same package, id and type, another method.
    const upgraded = {
      ...fixturePluginMethod({ type: 'corp_sso', id: 'corp' }),
      display: { name: 'Fixture provider, version 2' },
    };
    const at = await deploy(PACKAGE_A, upgraded);
    const calls = await adminCalls(at, realm.id, who);

    expect(await callbackStatus(at, realm.host, 'corp_sso')).toBe(400);
    expect((await calls.read()).json()).toMatchObject({
      displayName: 'Fixture provider, version 2',
      enabled: true,
      secrets: [{ path: 'clientSecret', set: true }],
      configuredBy: { package: PACKAGE_A, type: 'corp_sso' },
      mismatch: null,
      version: 2,
    });
    const context = await contextOf(at, realm.id, 'corp_sso');
    expect((context as { config?: unknown }).config).toEqual({ ...CONFIG, clientSecret: SECRET_A });
  }, 240_000);
});
