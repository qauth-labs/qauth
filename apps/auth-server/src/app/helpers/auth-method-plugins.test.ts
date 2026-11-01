import { types } from 'node:util';

import type { RealmAuthMethodPlugin } from '@qauth-labs/fastify-plugin-db';
import { AuthMethodConfigError } from '@qauth-labs/fastify-plugin-federation';
import { AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX } from '@qauth-labs/fastify-plugin-signer';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { fixturePluginImporter, fixturePluginMethod } from '../../testing/auth-method-plugins';
import { testRealm } from '../../testing/request-realm';
import {
  AUTH_METHOD_PLUGIN_SIGNER_CALLER,
  authMethodPluginContext,
  AuthMethodPluginDisabledError,
  authMethodPluginEnabledIn,
  authMethodPluginSecretCipher,
  authMethodPluginSecretContext,
  FIRST_PARTY_AUTH_METHOD_PLUGINS,
  loadDeploymentAuthMethodPlugins,
} from './auth-method-plugins';

/**
 * The plugin runtime (#600): what a plugin is handed, and what the boot logs.
 */

const REALM = testRealm({
  id: '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b',
  name: 'alpha',
  issuer: 'https://auth.example.com',
});
const SECRET = 'fixture-client-secret-value';
const CIPHERTEXT = 'v1.kid-1.aXY.Y2lwaGVydGV4dA';
const PLUGIN_PACKAGE = '@example/qauth-plugin-corp-sso';

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
          enabled: true,
          config: { issuer: 'https://idp.example', clientId: 'qauth' },
          secrets: { clientSecret: CIPHERTEXT },
          version: 1,
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
      context: authMethodPluginSecretContext('corp', 'clientSecret'),
    });
    expect(AUTH_METHOD_PLUGIN_SIGNER_CALLER).toBe('api');
    expect(authMethodPluginSecretContext('corp', 'clientSecret')).toBe(
      'auth-method-plugin:corp:clientSecret'
    );
  });

  it('seals a plugin secret as local and opens it as api, under the plugin secret prefix', async () => {
    const { fastify, signer } = await server({});
    const cipher = authMethodPluginSecretCipher(fastify);

    expect(await cipher.seal(REALM.id, 'corp', 'clientSecret', SECRET)).toBe(CIPHERTEXT);
    expect(await cipher.open(REALM.id, 'corp', 'clientSecret', CIPHERTEXT)).toBe(SECRET);

    const context = authMethodPluginSecretContext('corp', 'clientSecret');
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
    expect(await authMethodPluginEnabledIn(fastify, REALM.id, { id: 'corp' })).toBe(false);
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

describe('loadDeploymentAuthMethodPlugins (#600)', () => {
  it('ships an empty first-party list until the first-party plugins land', () => {
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
