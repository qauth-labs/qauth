import { types } from 'node:util';

import type { RealmAuthMethodPlugin } from '@qauth-labs/fastify-plugin-db';
import {
  AuthMethodConfigError,
  rankAttributeSource,
  UPSTREAM_PRESET_PROVENANCE,
} from '@qauth-labs/fastify-plugin-federation';
import {
  EXAMPLE_PRESET_ID,
  EXAMPLE_PRESET_PACKAGE,
  EXAMPLE_PRESET_SECRET_PATH,
  EXAMPLE_PRESET_TYPE,
  examplePresetPackage,
} from '@qauth-labs/fastify-plugin-federation/src/testing/upstream-oidc-fixtures';
import { AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX } from '@qauth-labs/fastify-plugin-signer';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { redactLoggedUrl } from '../../config/logger';
import { fixturePluginImporter, fixturePluginMethod } from '../../testing/auth-method-plugins';
import {
  INSTALLED_PLUGIN_ID,
  INSTALLED_PLUGIN_TYPE,
  type InstalledFixturePlugin,
  installFixturePluginPackage,
} from '../../testing/installed-auth-method-plugin';
import { testRealm } from '../../testing/request-realm';
import {
  importedPackages,
  SDK_PRESET_ID,
  SDK_PRESET_MEMBER,
  SDK_PRESET_PACKAGE,
  SDK_PRESET_SOURCE,
  SDK_PRESET_TYPE,
  writeSdkPresetPackage,
  type WrittenSdkPresetPackage,
} from '../../testing/sdk-preset-package';
import {
  SIGNED_SECRET_PRESET_ID,
  SIGNED_SECRET_PRESET_PACKAGE,
  SIGNED_SECRET_PRESET_TYPE,
  signedSecretPresetPackage,
} from '../../testing/signed-secret-preset';
import { pluginConfigBodySchema, pluginResource } from '../admin/plugins/routes';
import {
  AUTH_METHOD_PLUGIN_SIGNER_CALLER,
  authMethodPluginContext,
  AuthMethodPluginDisabledError,
  authMethodPluginEnabledIn,
  authMethodPluginRuntime,
  authMethodPluginSecretCipher,
  authMethodPluginSecretContext,
  authMethodPluginStateMismatch,
  FIRST_PARTY_AUTH_METHOD_PLUGINS,
  loadDeploymentAuthMethodPlugins,
} from './auth-method-plugins';
import { upstreamAttributeProvenance } from './upstream-attribute-provenance';

/**
 * The plugin runtime (#600): what a plugin is handed, and what the boot logs.
 */

const REALM = testRealm({
  id: '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b',
  name: 'alpha',
  issuer: 'https://auth.example.com',
});
const SECRET = 'fixture-client-secret-value';
const CIPHERTEXT = 'v1.kid-1.aXZhaXZhaXZhaXZh.Y2lwaGVydGV4dGNpcGhlcnRleHQ';
const PLUGIN_PACKAGE = '@example/qauth-plugin-corp-sso';
/** What names the fixture plugin's secrets: its id, its package and its type (#949). */
const CORP = { id: 'corp', package: PLUGIN_PACKAGE, type: 'corp_sso' } as const;

const silent = () => ({ info: vi.fn(), warn: vi.fn() });

async function corpPlugin() {
  const runtime = await loadDeploymentAuthMethodPlugins(
    silent(),
    { packages: [PLUGIN_PACKAGE], pluginApiEnabled: true, nodeEnv: 'test' },
    {
      importPackage: fixturePluginImporter({
        [PLUGIN_PACKAGE]: { authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }) },
      }),
    }
  );
  return runtime;
}

/** A server with everything a plugin must never reach beside what it may. */
async function server(row: Partial<RealmAuthMethodPlugin> | undefined) {
  const runtime = await corpPlugin();
  const db = { name: 'the database handle', query: vi.fn() };
  const redis = { name: 'the Redis handle', get: vi.fn() };
  const signer = {
    signClientAssertion: vi.fn(async () => 'signed-assertion'),
    getUpstreamJwks: vi.fn(async () => ({ keys: [] })),
    decrypt: vi.fn(async () => Buffer.from(SECRET, 'utf8')),
    encrypt: vi.fn(async () => CIPHERTEXT),
    signJws: vi.fn(),
    getCookieSecrets: vi.fn(),
  };
  const egress = { request: vi.fn(), validateDestination: vi.fn() };
  const stored: RealmAuthMethodPlugin | undefined =
    row === undefined
      ? undefined
      : {
          realmId: REALM.id,
          pluginId: 'corp',
          pluginPackage: PLUGIN_PACKAGE,
          pluginType: 'corp_sso',
          enabled: true,
          config: { issuer: 'https://idp.example', clientId: 'qauth' },
          secrets: { clientSecret: CIPHERTEXT },
          version: 1,
          assertionClientId: null,
          assertionIssuer: null,
          assertionAlgorithm: null,
          createdAt: 0,
          updatedAt: 0,
          ...row,
        };
  const find = vi.fn(async () => stored);
  const fastify = {
    authMethodPlugins: runtime,
    repositories: { realmAuthMethodPlugins: { find } },
    signer,
    egress,
    db,
    dbPool: db,
    redis,
  } as unknown as FastifyInstance;
  const child = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
  const request = {
    realm: REALM,
    log: { child: vi.fn(() => child) },
  } as unknown as FastifyRequest;
  return { fastify, request, runtime, signer, egress, db, redis, find, child };
}

/** Every value reachable from `root` through own properties and prototypes. */
function reachable(root: unknown): unknown[] {
  const seen = new Set<unknown>();
  const queue: unknown[] = [root];
  while (queue.length > 0) {
    const value = queue.shift();
    if ((typeof value !== 'object' && typeof value !== 'function') || value === null) continue;
    if (seen.has(value)) continue;
    seen.add(value);
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor && 'value' in descriptor) queue.push(descriptor.value);
    }
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (prototype !== Object.prototype && prototype !== Function.prototype) queue.push(prototype);
  }
  return [...seen];
}

describe('the plugin context (#600)', () => {
  // Acceptance criterion: the plugin context exposes no database handle and
  // no key material.
  it('holds the config, the egress client, the signer and a logger, and nothing that reaches the database or a key', async () => {
    const { fastify, request, runtime, signer, egress, db, redis } = await server({});
    const method = runtime.ofType('corp_sso')?.method;
    if (method === undefined) throw new Error('the fixture plugin did not load');

    const context = await authMethodPluginContext(fastify, request, method);

    expect(Object.keys(context).sort()).toEqual(['config', 'egress', 'log', 'routeUrl', 'signer']);
    expect(Object.keys(context.egress)).toEqual(['request']);
    expect(Object.keys(context.signer).sort()).toEqual(['getUpstreamJwks', 'signClientAssertion']);
    expect(Object.keys(context.log).sort()).toEqual(['debug', 'error', 'info', 'warn']);

    const values = reachable(context);
    for (const forbidden of [fastify, db, redis, signer, egress, request]) {
      expect(values).not.toContain(forbidden);
    }
    for (const value of values) {
      if (typeof value === 'function') {
        expect([
          'decrypt',
          'encrypt',
          'signJws',
          'getCookieSecrets',
          'validateDestination',
        ]).not.toContain(value.name.replace(/^bound /, ''));
      }
      expect(types.isKeyObject(value)).toBe(false);
      expect(types.isCryptoKey(value)).toBe(false);
    }
    expect(JSON.stringify(context.config)).not.toMatch(/PRIVATE KEY/);
  });

  it("decrypts the realm's secret members under the plugin's own context, as the api signer caller", async () => {
    const { fastify, request, runtime, signer } = await server({});
    const method = runtime.ofType('corp_sso')?.method;
    if (method === undefined) throw new Error('the fixture plugin did not load');

    const context = await authMethodPluginContext(fastify, request, method);

    expect(context.config).toEqual({
      issuer: 'https://idp.example',
      clientId: 'qauth',
      clientSecret: SECRET,
    });
    expect(Object.isFrozen(context.config)).toBe(true);
    expect(signer.decrypt).toHaveBeenCalledWith(AUTH_METHOD_PLUGIN_SIGNER_CALLER, {
      realmId: REALM.id,
      ciphertext: CIPHERTEXT,
      context: authMethodPluginSecretContext(CORP, 'clientSecret'),
    });
    expect(AUTH_METHOD_PLUGIN_SIGNER_CALLER).toBe('api');
    expect(authMethodPluginSecretContext(CORP, 'clientSecret')).toBe(
      'auth-method-plugin:corp:@example/qauth-plugin-corp-sso:corp_sso:clientSecret'
    );
  });

  it('seals a plugin secret as local and opens it as api, under the plugin secret prefix', async () => {
    const { fastify, signer } = await server({});
    const cipher = authMethodPluginSecretCipher(fastify);

    expect(await cipher.seal(REALM.id, CORP, 'clientSecret', SECRET)).toBe(CIPHERTEXT);
    expect(await cipher.open(REALM.id, CORP, 'clientSecret', CIPHERTEXT)).toBe(SECRET);

    const context = authMethodPluginSecretContext(CORP, 'clientSecret');
    expect(context.startsWith(AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX)).toBe(true);
    expect(signer.encrypt).toHaveBeenCalledWith('local', {
      realmId: REALM.id,
      plaintext: Buffer.from(SECRET, 'utf8'),
      context,
    });
    expect(signer.decrypt).toHaveBeenCalledWith('api', {
      realmId: REALM.id,
      ciphertext: CIPHERTEXT,
      context,
    });
  });

  it('binds the signer to the realm, the plugin and the api caller', async () => {
    const { fastify, request, runtime, signer } = await server({});
    const method = runtime.ofType('corp_sso')?.method;
    if (method === undefined) throw new Error('the fixture plugin did not load');
    const context = await authMethodPluginContext(fastify, request, method);

    await context.signer.signClientAssertion({
      audience: 'https://idp.example',
      claims: { jti: 'j', exp: Math.floor(Date.now() / 1000) + 60 },
    });
    await context.signer.getUpstreamJwks();

    expect(signer.signClientAssertion).toHaveBeenCalledWith(
      'api',
      expect.objectContaining({ realmId: REALM.id, providerId: 'corp_sso' })
    );
    expect(signer.getUpstreamJwks).toHaveBeenCalledWith('api', REALM.id, 'corp_sso');
    expect(context.routeUrl('/callback')).toBe(
      'https://auth.example.com/upstream/corp_sso/callback'
    );
  });

  it('logs through a child logger that names the plugin', async () => {
    const { fastify, request, runtime, child } = await server({});
    const method = runtime.ofType('corp_sso')?.method;
    if (method === undefined) throw new Error('the fixture plugin did not load');
    const context = await authMethodPluginContext(fastify, request, method);

    context.log.info({ code: 'abc' }, 'callback reached');

    expect(request.log.child).toHaveBeenCalledWith({ authMethodPlugin: 'corp' });
    expect(child.info).toHaveBeenCalledWith(
      { authMethod: { code: '[Redacted]' } },
      'callback reached'
    );
  });

  it("redacts the plugin's own secrets in its log lines, by name and by value", async () => {
    const { fastify, request, runtime, child } = await server({});
    const method = runtime.ofType('corp_sso')?.method;
    if (method === undefined) throw new Error('the fixture plugin did not load');
    const context = await authMethodPluginContext(fastify, request, method);

    context.log.warn({ clientSecret: 'by-name', sent: `secret=${SECRET}` }, `sent ${SECRET}`);

    expect(child.warn).toHaveBeenCalledWith(
      { authMethod: { clientSecret: '[Redacted]', sent: 'secret=[Redacted]' } },
      'sent [Redacted]'
    );
  });

  it.each<[string, Partial<RealmAuthMethodPlugin> | undefined]>([
    ['has no row for the plugin', undefined],
    ['has the plugin off', { enabled: false }],
  ])('builds no context when the realm %s', async (_case, row) => {
    const { fastify, request, runtime, signer } = await server(row);
    const method = runtime.ofType('corp_sso')?.method;
    if (method === undefined) throw new Error('the fixture plugin did not load');

    await expect(authMethodPluginContext(fastify, request, method)).rejects.toBeInstanceOf(
      AuthMethodPluginDisabledError
    );
    expect(signer.decrypt).not.toHaveBeenCalled();
    expect(await authMethodPluginEnabledIn(fastify, REALM.id, CORP)).toBe(false);
  });

  // #949: a state is the plugin's that wrote it, its package and its type.
  it.each<[string, Partial<RealmAuthMethodPlugin>]>([
    [
      'another package wrote under the same id',
      { pluginPackage: '@example/another-corp-sso', pluginType: 'corp_sso' },
    ],
    [
      'this package wrote under another type',
      { pluginPackage: PLUGIN_PACKAGE, pluginType: 'corp_sso_v1' },
    ],
    ['a release before #949 wrote, naming no package', { pluginPackage: null, pluginType: null }],
  ])('builds no context, and opens no secret, from an enabled state %s', async (_case, binding) => {
    const { fastify, request, runtime, signer } = await server({ enabled: true, ...binding });
    const method = runtime.ofType('corp_sso')?.method;
    if (method === undefined) throw new Error('the fixture plugin did not load');

    await expect(authMethodPluginContext(fastify, request, method)).rejects.toBeInstanceOf(
      AuthMethodPluginDisabledError
    );
    expect(signer.decrypt).not.toHaveBeenCalled();
    expect(await authMethodPluginEnabledIn(fastify, REALM.id, CORP)).toBe(false);
  });

  it('names why a state is not the plugin, or nothing when the package and the type match', () => {
    const plugin = { package: PLUGIN_PACKAGE, type: 'corp_sso' };
    expect(
      authMethodPluginStateMismatch(plugin, {
        pluginPackage: PLUGIN_PACKAGE,
        pluginType: 'corp_sso',
      })
    ).toBeNull();
    expect(
      authMethodPluginStateMismatch(plugin, { pluginPackage: '@example/b', pluginType: 'corp_sso' })
    ).toBe('package_changed');
    // The package is named first: both differ.
    expect(
      authMethodPluginStateMismatch(plugin, { pluginPackage: '@example/b', pluginType: 'b_sso' })
    ).toBe('package_changed');
    expect(
      authMethodPluginStateMismatch(plugin, { pluginPackage: PLUGIN_PACKAGE, pluginType: 'b_sso' })
    ).toBe('type_changed');
    expect(authMethodPluginStateMismatch(plugin, { pluginPackage: null, pluginType: null })).toBe(
      'package_unrecorded'
    );
  });

  // #949, acceptance: a version bump of the same package needs nothing.
  it('builds the context of a new version of the same package from the state the old one wrote', async () => {
    const { fastify, request, signer } = await server({});
    // The new version: another method object, the same package, id and type.
    const upgraded = await loadDeploymentAuthMethodPlugins(
      silent(),
      { packages: [PLUGIN_PACKAGE], pluginApiEnabled: true, nodeEnv: 'test' },
      {
        importPackage: fixturePluginImporter({
          [PLUGIN_PACKAGE]: { authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }) },
        }),
      }
    );
    const server2 = { ...fastify, authMethodPlugins: upgraded } as unknown as FastifyInstance;
    const method = upgraded.ofType('corp_sso')?.method;
    if (method === undefined) throw new Error('the fixture plugin did not load');

    const context = await authMethodPluginContext(server2, request, method);
    expect(context.config).toMatchObject({ clientSecret: SECRET });
    expect(signer.decrypt).toHaveBeenCalledWith('api', {
      realmId: REALM.id,
      ciphertext: CIPHERTEXT,
      context: authMethodPluginSecretContext(CORP, 'clientSecret'),
    });
  });

  it('builds no context for a method that is no loaded plugin', async () => {
    const { fastify, request } = await server({});
    await expect(
      authMethodPluginContext(fastify, request, fixturePluginMethod({ type: 'other_sso' }))
    ).rejects.toBeInstanceOf(AuthMethodPluginDisabledError);
  });

  it("refuses a stored config the plugin's schema refuses, naming members, never values", async () => {
    const { fastify, request, runtime } = await server({ secrets: {} });
    const method = runtime.ofType('corp_sso')?.method;
    if (method === undefined) throw new Error('the fixture plugin did not load');

    const error = await authMethodPluginContext(fastify, request, method).catch(
      (reason: unknown) => reason
    );
    expect(error).toBeInstanceOf(AuthMethodConfigError);
    expect((error as AuthMethodConfigError).issues).toEqual(['clientSecret: invalid_type']);
  });
});

describe('a preset plugin on the generic OpenID Connect client (#951)', () => {
  /**
   * A signer whose ciphertexts open only under the context they were sealed
   * with, as the real one's do: what the admin API seals, the plugin's
   * context opens, and nothing else.
   */
  function sealingSigner() {
    const sealed = new Map<string, { context: string | undefined; plaintext: Buffer }>();
    return {
      encrypt: vi.fn(
        async (_caller: string, request: { plaintext: Uint8Array; context?: string }) => {
          const ciphertext = `v1.kid-1.${`n${sealed.size}`.padEnd(16, 'A')}.Y2lwaGVydGV4dGNpcGhlcnRleHQ`;
          sealed.set(ciphertext, {
            context: request.context,
            plaintext: Buffer.from(request.plaintext),
          });
          return ciphertext;
        }
      ),
      decrypt: vi.fn(async (_caller: string, request: { ciphertext: string; context?: string }) => {
        const entry = sealed.get(request.ciphertext);
        if (entry === undefined || entry.context !== request.context) {
          throw new Error('the ciphertext does not open under this context');
        }
        return entry.plaintext;
      }),
      signClientAssertion: vi.fn(),
      getUpstreamJwks: vi.fn(async () => ({ keys: [] })),
    };
  }

  // Acceptance: a preset plugin built on the generic client loads from the
  // first-party list with PLUGIN_API_ENABLED off.
  it('loads from the first-party list with the plugin API off, and logs it as first-party', async () => {
    const log = silent();
    const runtime = await loadDeploymentAuthMethodPlugins(
      log,
      { packages: [EXAMPLE_PRESET_PACKAGE], pluginApiEnabled: false, nodeEnv: 'test' },
      {
        importPackage: fixturePluginImporter({ [EXAMPLE_PRESET_PACKAGE]: examplePresetPackage() }),
        firstParty: [EXAMPLE_PRESET_PACKAGE],
      }
    );
    expect(log.warn).not.toHaveBeenCalled();
    expect(log.info).toHaveBeenCalledWith(
      expect.objectContaining({
        authMethodPlugin: EXAMPLE_PRESET_PACKAGE,
        id: EXAMPLE_PRESET_ID,
        type: EXAMPLE_PRESET_TYPE,
        firstParty: true,
      }),
      `AuthMethod plugin ${EXAMPLE_PRESET_PACKAGE} loaded: ${EXAMPLE_PRESET_ID} (${EXAMPLE_PRESET_TYPE})`
    );
    expect(runtime.find(EXAMPLE_PRESET_ID)?.secretPaths).toEqual([EXAMPLE_PRESET_SECRET_PATH]);
  });

  // Acceptance: its client secret is write-only end to end.
  it('keeps its client secret write-only from the seal to the context', async () => {
    const runtime = await loadDeploymentAuthMethodPlugins(
      silent(),
      { packages: [EXAMPLE_PRESET_PACKAGE], pluginApiEnabled: false, nodeEnv: 'test' },
      {
        importPackage: fixturePluginImporter({ [EXAMPLE_PRESET_PACKAGE]: examplePresetPackage() }),
        firstParty: [EXAMPLE_PRESET_PACKAGE],
      }
    );
    const plugin = runtime.find(EXAMPLE_PRESET_ID);
    if (plugin === undefined) throw new Error('the preset did not load');
    const signer = sealingSigner();
    const plainConfig = {
      clientId: 'qauth',
      clientAuthentication: { method: 'client_secret_basic' },
    };

    // The admin API refuses the secret among the plain members, nested or dotted.
    const body = pluginConfigBodySchema(runtime.installed);
    for (const config of [
      {
        ...plainConfig,
        clientAuthentication: { method: 'client_secret_basic', clientSecret: SECRET },
      },
      { ...plainConfig, [EXAMPLE_PRESET_SECRET_PATH]: SECRET },
    ]) {
      expect(body.safeParse({ version: 0, config }).success).toBe(false);
    }

    // It seals the value for the member, under the plugin's own context...
    const sealed = await authMethodPluginSecretCipher({
      signer,
    } as unknown as FastifyInstance).seal(REALM.id, plugin, EXAMPLE_PRESET_SECRET_PATH, SECRET);
    expect(signer.encrypt).toHaveBeenCalledWith('local', {
      realmId: REALM.id,
      plaintext: Buffer.from(SECRET, 'utf8'),
      context: `auth-method-plugin:${EXAMPLE_PRESET_ID}:${EXAMPLE_PRESET_PACKAGE}:${EXAMPLE_PRESET_TYPE}:${EXAMPLE_PRESET_SECRET_PATH}`,
    });
    expect(
      body.safeParse({
        version: 0,
        config: plainConfig,
        secrets: { [EXAMPLE_PRESET_SECRET_PATH]: { sealed } },
      }).success
    ).toBe(true);

    // ...the realm's row holds the ciphertext apart, and the API shows neither.
    const row: RealmAuthMethodPlugin = {
      realmId: REALM.id,
      pluginId: plugin.id,
      pluginPackage: EXAMPLE_PRESET_PACKAGE,
      pluginType: EXAMPLE_PRESET_TYPE,
      enabled: true,
      config: plainConfig,
      secrets: { [EXAMPLE_PRESET_SECRET_PATH]: sealed },
      version: 1,
      assertionClientId: null,
      assertionIssuer: null,
      assertionAlgorithm: null,
      createdAt: 0,
      updatedAt: 0,
    };
    const resource = pluginResource(plugin, row);
    expect(resource).toMatchObject({
      name: EXAMPLE_PRESET_ID,
      type: EXAMPLE_PRESET_TYPE,
      firstParty: true,
      config: plainConfig,
      secrets: [{ path: EXAMPLE_PRESET_SECRET_PATH, set: true }],
    });
    expect(JSON.stringify(resource)).not.toContain(SECRET);
    expect(JSON.stringify(resource)).not.toContain(sealed);

    // ...and only the plugin's context gets it back, in place, as the api caller.
    const child = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    const fastify = {
      authMethodPlugins: runtime,
      repositories: { realmAuthMethodPlugins: { find: vi.fn(async () => row) } },
      signer,
      egress: { request: vi.fn(), validateDestination: vi.fn() },
    } as unknown as FastifyInstance;
    const request = {
      realm: REALM,
      log: { child: vi.fn(() => child) },
    } as unknown as FastifyRequest;
    const context = await authMethodPluginContext(fastify, request, plugin.method);
    expect(context.config).toEqual({
      clientId: 'qauth',
      clientAuthentication: { method: 'client_secret_basic', clientSecret: SECRET },
      formPost: false,
    });
    expect(signer.decrypt).toHaveBeenCalledWith('api', {
      realmId: REALM.id,
      ciphertext: sealed,
      context: `auth-method-plugin:${EXAMPLE_PRESET_ID}:${EXAMPLE_PRESET_PACKAGE}:${EXAMPLE_PRESET_TYPE}:${EXAMPLE_PRESET_SECRET_PATH}`,
    });
    context.log.warn({ clientSecret: SECRET, note: `sent ${SECRET}` }, `sent ${SECRET}`);
    expect(JSON.stringify(child.warn.mock.calls)).not.toContain(SECRET);

    // A ciphertext sealed for another plugin, another package behind the same
    // id (#949), or another member, never opens as this one.
    const cipher = authMethodPluginSecretCipher({ signer } as unknown as FastifyInstance);
    for (const foreign of [
      { id: 'corp', package: EXAMPLE_PRESET_PACKAGE, type: EXAMPLE_PRESET_TYPE },
      { id: EXAMPLE_PRESET_ID, package: '@example/another-preset', type: EXAMPLE_PRESET_TYPE },
      { id: EXAMPLE_PRESET_ID, package: EXAMPLE_PRESET_PACKAGE, type: 'another_type' },
    ]) {
      const other = await cipher.seal(REALM.id, foreign, EXAMPLE_PRESET_SECRET_PATH, SECRET);
      const misplaced = { ...row, secrets: { [EXAMPLE_PRESET_SECRET_PATH]: other } };
      (
        fastify.repositories.realmAuthMethodPlugins.find as ReturnType<typeof vi.fn>
      ).mockResolvedValue(misplaced);
      await expect(authMethodPluginContext(fastify, request, plugin.method)).rejects.toThrow(
        'does not open'
      );
    }
  });
});

describe('loadDeploymentAuthMethodPlugins (#600)', () => {
  it('ships an empty first-party list: every provider plugin lives in its own repository (#671)', () => {
    expect(FIRST_PARTY_AUTH_METHOD_PLUGINS).toEqual([]);
    expect(Object.isFrozen(FIRST_PARTY_AUTH_METHOD_PLUGINS)).toBe(true);
  });

  it('logs why a third-party plugin is not loaded while the plugin API is off', async () => {
    const log = silent();
    const importPackage = vi.fn(fixturePluginImporter({}));
    const runtime = await loadDeploymentAuthMethodPlugins(
      log,
      { packages: [PLUGIN_PACKAGE], pluginApiEnabled: false, nodeEnv: 'test' },
      { importPackage }
    );

    expect(runtime.installed).toEqual([]);
    expect(importPackage).not.toHaveBeenCalled();
    expect(log.warn).toHaveBeenCalledWith(
      { authMethodPlugin: PLUGIN_PACKAGE, reason: 'plugin-api-off' },
      expect.stringContaining('the experimental plugin API is off. Set PLUGIN_API_ENABLED=true')
    );
    expect(log.info).not.toHaveBeenCalled();
  });

  it('logs each plugin it loads, with its id, type and contract', async () => {
    const log = silent();
    const runtime = await loadDeploymentAuthMethodPlugins(
      log,
      { packages: [PLUGIN_PACKAGE], pluginApiEnabled: false, nodeEnv: 'test' },
      {
        firstParty: [PLUGIN_PACKAGE],
        importPackage: fixturePluginImporter({
          [PLUGIN_PACKAGE]: { authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }) },
        }),
      }
    );

    expect(runtime.find('corp')?.type).toBe('corp_sso');
    expect(runtime.ofType('corp_sso')?.id).toBe('corp');
    expect(log.info).toHaveBeenCalledWith(
      {
        authMethodPlugin: PLUGIN_PACKAGE,
        id: 'corp',
        type: 'corp_sso',
        kind: 'auth-method',
        firstParty: true,
        contract: 'qauth-auth-method/1-rc.0',
      },
      `AuthMethod plugin ${PLUGIN_PACKAGE} loaded: corp (corp_sso)`
    );
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('refuses the test support outside NODE_ENV=test', async () => {
    await expect(
      loadDeploymentAuthMethodPlugins(
        silent(),
        { packages: [], pluginApiEnabled: false, nodeEnv: 'production' },
        { firstParty: [PLUGIN_PACKAGE] }
      )
    ).rejects.toThrow(/refused unless NODE_ENV is test/);
  });
});

describe('a plugin installed as a package (#1009)', () => {
  // No importer: the loader's own import() resolves the package in
  // node_modules, as a deployment's does.
  let installed: InstalledFixturePlugin;

  beforeAll(async () => {
    installed = await installFixturePluginPackage();
  });

  afterAll(async () => {
    await installed.remove();
  });

  it('loads with the plugin API on', async () => {
    const log = silent();
    const runtime = await loadDeploymentAuthMethodPlugins(log, {
      packages: [installed.packageName],
      pluginApiEnabled: true,
      nodeEnv: 'test',
    });

    expect(runtime.installed.map((plugin) => [plugin.package, plugin.id, plugin.type])).toEqual([
      [installed.packageName, INSTALLED_PLUGIN_ID, INSTALLED_PLUGIN_TYPE],
    ]);
    // Its secret member is read from the schema it built with the server's Zod.
    expect(runtime.ofType(INSTALLED_PLUGIN_TYPE)?.secretPaths).toEqual(['clientSecret']);
    expect(log.info).toHaveBeenCalledWith(
      expect.objectContaining({ authMethodPlugin: installed.packageName, firstParty: false }),
      `AuthMethod plugin ${installed.packageName} loaded: ${INSTALLED_PLUGIN_ID} (${INSTALLED_PLUGIN_TYPE})`
    );
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('is skipped with the plugin API off, and the boot says why', async () => {
    const log = silent();
    const runtime = await loadDeploymentAuthMethodPlugins(log, {
      packages: [installed.packageName],
      pluginApiEnabled: false,
      nodeEnv: 'test',
    });

    expect(runtime.installed).toEqual([]);
    expect(log.warn).toHaveBeenCalledWith(
      { authMethodPlugin: installed.packageName, reason: 'plugin-api-off' },
      `The AuthMethod plugin ${installed.packageName} is not loaded: it is not a first-party plugin, and the experimental plugin API is off. Set PLUGIN_API_ENABLED=true to load it, or remove it from AUTH_METHOD_PLUGINS`
    );
    expect(log.info).not.toHaveBeenCalled();
  });
});

describe('a preset package that imports only the plugin SDK (#671)', () => {
  // The package as a provider plugin in its own repository writes it, loaded
  // through the server's loader and built on the server's client.
  let written: WrittenSdkPresetPackage;

  beforeAll(async () => {
    written = await writeSdkPresetPackage();
  });

  afterAll(async () => {
    await written.remove();
  });

  it('imports the plugin SDK and its peer Zod, and nothing of the server', () => {
    expect(importedPackages(SDK_PRESET_SOURCE)).toEqual(['@qauth-labs/plugin-sdk', 'zod']);
  });

  it("loads with the plugin API on, its method built on the server's client, and says how it was built", async () => {
    const log = silent();
    const runtime = await loadDeploymentAuthMethodPlugins(
      log,
      { packages: [SDK_PRESET_PACKAGE], pluginApiEnabled: true, nodeEnv: 'test' },
      { importPackage: written.importPackage }
    );

    const plugin = runtime.ofType(SDK_PRESET_TYPE);
    expect(plugin).toMatchObject({
      package: SDK_PRESET_PACKAGE,
      id: SDK_PRESET_ID,
      kind: 'upstream-oidc-preset',
      firstParty: false,
      secretPaths: ['clientSecret'],
      responseMembers: [SDK_PRESET_MEMBER],
    });
    // The server's client: its callback and its form_post bounce.
    expect(plugin?.method.routes.map((route) => `${route.method} ${route.path}`)).toEqual([
      'GET /callback',
      'POST /callback',
    ]);
    expect(log.info).toHaveBeenCalledWith(
      expect.objectContaining({
        authMethodPlugin: SDK_PRESET_PACKAGE,
        kind: 'upstream-oidc-preset',
        firstParty: false,
      }),
      `AuthMethod plugin ${SDK_PRESET_PACKAGE} loaded: ${SDK_PRESET_ID} (${SDK_PRESET_TYPE})`
    );
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('is skipped with the plugin API off, and the boot says why', async () => {
    const log = silent();
    const importPackage = vi.fn(written.importPackage);
    const runtime = await loadDeploymentAuthMethodPlugins(
      log,
      { packages: [SDK_PRESET_PACKAGE], pluginApiEnabled: false, nodeEnv: 'test' },
      { importPackage }
    );

    expect(runtime.installed).toEqual([]);
    expect(importPackage).not.toHaveBeenCalled();
    expect(log.warn).toHaveBeenCalledWith(
      { authMethodPlugin: SDK_PRESET_PACKAGE, reason: 'plugin-api-off' },
      `The AuthMethod plugin ${SDK_PRESET_PACKAGE} is not loaded: it is not a first-party plugin, and the experimental plugin API is off. Set PLUGIN_API_ENABLED=true to load it, or remove it from AUTH_METHOD_PLUGINS`
    );
    expect(log.info).not.toHaveBeenCalled();
  });

  it('censors the response member its form_post bounce carries in the request log, once it loads', async () => {
    const url = `/upstream/${SDK_PRESET_TYPE}/callback?state=s&${SDK_PRESET_MEMBER}=${encodeURIComponent(JSON.stringify({ name: 'Ada' }))}`;
    await loadDeploymentAuthMethodPlugins(
      silent(),
      { packages: [SDK_PRESET_PACKAGE], pluginApiEnabled: true, nodeEnv: 'test' },
      { importPackage: written.importPackage }
    );

    const logged = redactLoggedUrl(url);
    expect(logged).not.toContain('Ada');
    expect(logged).toContain('state=s');
  });

  it("records on the preset-built method's attributes how it was built, and nothing on a plain plugin's", async () => {
    const runtime = await loadDeploymentAuthMethodPlugins(
      silent(),
      { packages: [SDK_PRESET_PACKAGE, PLUGIN_PACKAGE], pluginApiEnabled: true, nodeEnv: 'test' },
      {
        importPackage: async (name) =>
          name === PLUGIN_PACKAGE
            ? { authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }) }
            : written.importPackage(name),
      }
    );

    const fastify = { authMethodPlugins: runtime };
    expect(upstreamAttributeProvenance(fastify, SDK_PRESET_TYPE)).toBe(UPSTREAM_PRESET_PROVENANCE);
    expect(upstreamAttributeProvenance(fastify, 'corp_sso')).toBeNull();
    expect(upstreamAttributeProvenance(fastify, 'oidc_corp')).toBeNull();
    // A process without the plugin runtime records none.
    expect(upstreamAttributeProvenance({}, SDK_PRESET_TYPE)).toBeNull();
    // The rank reads it from the row, on any role.
    expect(rankAttributeSource(SDK_PRESET_TYPE, UPSTREAM_PRESET_PROVENANCE)).toBe(
      rankAttributeSource('oidc_corp')
    );
    expect(rankAttributeSource('corp_sso', null)).toBe(0);
  });
});

describe("whose client a preset plugin's client assertions speak for (#1073)", () => {
  async function runtime() {
    return loadDeploymentAuthMethodPlugins(
      silent(),
      {
        packages: [SIGNED_SECRET_PRESET_PACKAGE, PLUGIN_PACKAGE],
        pluginApiEnabled: true,
        nodeEnv: 'test',
      },
      {
        importPackage: fixturePluginImporter({
          [SIGNED_SECRET_PRESET_PACKAGE]: signedSecretPresetPackage(),
          [PLUGIN_PACKAGE]: { authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }) },
        }),
      }
    );
  }

  it("answers a preset's client id, assertion issuer and algorithm for a realm's config", async () => {
    const plugins = await runtime();
    const preset = plugins.find(SIGNED_SECRET_PRESET_ID);
    if (preset === undefined) throw new Error('the preset did not load');
    expect(preset.kind).toBe('upstream-oidc-preset');

    expect(
      plugins.assertionClientOf(preset, { servicesId: 'com.example.signin', teamId: 'TEAM123456' })
    ).toEqual({
      clientId: 'com.example.signin',
      assertionIssuer: 'TEAM123456',
      algorithm: 'ES256',
    });
    // No assertion issuer: the signer then signs with the client id as iss.
    expect(plugins.assertionClientOf(preset, { servicesId: 'com.example.signin' })).toEqual({
      clientId: 'com.example.signin',
      algorithm: 'ES256',
    });
  });

  it('answers none for a provider config that authenticates with a client secret, and never echoes it', async () => {
    const plugins = await runtime();
    const preset = plugins.find(SIGNED_SECRET_PRESET_ID);
    if (preset === undefined) throw new Error('the preset did not load');

    expect(
      plugins.assertionClientOf(preset, {
        servicesId: 'com.example.signin',
        clientSecret: 'a-client-secret-value',
      })
    ).toBeUndefined();
  });

  it('answers none for a plugin that exports its own AuthMethod, or one this runtime did not load', async () => {
    const plugins = await runtime();
    const corp = plugins.find('corp');
    const preset = plugins.find(SIGNED_SECRET_PRESET_ID);
    if (corp === undefined || preset === undefined) throw new Error('the plugins did not load');

    expect(plugins.assertionClientOf(corp, { issuer: 'https://idp.example' })).toBeUndefined();
    // A runtime without the preset's mapping, as a test builds one.
    expect(
      authMethodPluginRuntime([preset]).assertionClientOf(preset, { servicesId: 'x' })
    ).toBeUndefined();
    // Another plugin object under the preset's type is not the installed one.
    expect(
      plugins.assertionClientOf({ ...preset }, { servicesId: 'com.example.signin' })
    ).toBeUndefined();
  });

  it("throws when the preset's mapping fails on a config its schema never took", async () => {
    const plugins = await runtime();
    const preset = plugins.find(SIGNED_SECRET_PRESET_ID);
    if (preset === undefined) throw new Error('the preset did not load');

    expect(() => plugins.assertionClientOf(preset, { servicesId: '' })).toThrow(TypeError);
    expect(SIGNED_SECRET_PRESET_TYPE).toBe(preset.type);
  });
});
