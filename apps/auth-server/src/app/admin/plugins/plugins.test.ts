import { describe, expect, it } from 'vitest';

import { fixturePluginImporter, fixturePluginMethod } from '../../../testing/auth-method-plugins';
import { OPERATION_REGISTRY } from '../../helpers/admin-operations';
import { ADMIN_SCOPES } from '../../helpers/admin-scopes';
import { loadDeploymentAuthMethodPlugins } from '../../helpers/auth-method-plugins';
import type { AdminRateLimitCheck } from '../pipeline';
import { PLUGIN_OPERATION_IDS } from './operations';
import { pluginConfigBodySchema, pluginResource } from './routes';

/**
 * The plugin operations of the admin API (#600), without a listener: their
 * classes, what an approver is shown, the body a configure request may send
 * and the representation. The routes behind the pipeline are exercised
 * against real containers in `auth-method-plugins-admin.integration.test.ts`.
 */

const SECRET = 'fixture-client-secret-value';
/** A value as plugins.secrets.seal answers one. */
const SEALED = 'v1.kid-1.aXY.Y2lwaGVydGV4dA';

async function installed() {
  const runtime = await loadDeploymentAuthMethodPlugins(
    { info: () => undefined, warn: () => undefined },
    { packages: ['@example/corp'], pluginApiEnabled: true, nodeEnv: 'test' },
    {
      importPackage: fixturePluginImporter({
        '@example/corp': { authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }) },
      }),
    }
  );
  return runtime.installed;
}

describe('the plugin operations (#600)', () => {
  // Acceptance criterion (unit half): enabling or configuring a plugin is a
  // security operation, which qauth:admin:write never reaches.
  it('makes enabling, configuring and disabling security operations with credential-path, reading a read', () => {
    const shape = Object.values(PLUGIN_OPERATION_IDS).map((id) => {
      const operation = OPERATION_REGISTRY.get(id);
      return [id, operation?.class, operation?.effects, operation?.permissions];
    });
    expect(shape).toEqual([
      ['plugins.list', 'read', [], ['plugins.read']],
      ['plugins.get', 'read', [], ['plugins.read']],
      ['plugins.secrets.seal', 'write', [], ['plugins.write']],
      ['plugins.update', 'security', ['credential-path'], ['plugins.security']],
      ['plugins.enable', 'security', ['credential-path'], ['plugins.security']],
      ['plugins.disable', 'security', ['credential-path'], ['plugins.security']],
    ]);
    const security = OPERATION_REGISTRY.permissions.get('plugins.security');
    expect(security?.class).toBe('security');
    expect(ADMIN_SCOPES.security).toBe('qauth:admin:security');
  });

  it('shows an approver which secret a configure request sets or clears, never its value', () => {
    const render = OPERATION_REGISTRY.get(PLUGIN_OPERATION_IDS.update)?.render;
    if (render === undefined) throw new Error('plugins.update has no renderer');
    const rendered = render({
      operationId: PLUGIN_OPERATION_IDS.update,
      method: 'POST',
      params: { realmId: '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b', plugin: 'corp' },
      query: {},
      body: {
        config: { issuer: 'https://idp.example', clientId: 'qauth' },
        secrets: { clientSecret: { sealed: SEALED }, oldKey: null },
      },
    });
    expect(rendered).toEqual({
      title: 'Replace the configuration of the sign-in plugin corp in the realm',
      fields: [
        { label: 'config.issuer', value: '"https://idp.example"' },
        { label: 'config.clientId', value: '"qauth"' },
        { label: 'secret clientSecret', value: 'set to a new sealed value (not shown)' },
        { label: 'secret oldKey', value: 'cleared' },
      ],
    });
    expect(JSON.stringify(rendered)).not.toContain(SEALED);
  });

  it('names the plugin an enable or a disable is for', () => {
    const request = {
      method: 'POST',
      params: { realmId: '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b', plugin: 'corp' },
      query: {},
      body: null,
    };
    expect(
      OPERATION_REGISTRY.get(PLUGIN_OPERATION_IDS.enable)?.render?.({
        ...request,
        operationId: PLUGIN_OPERATION_IDS.enable,
      })
    ).toEqual({ title: 'Enable the sign-in plugin corp in the realm' });
    expect(
      OPERATION_REGISTRY.get(PLUGIN_OPERATION_IDS.disable)?.render?.({
        ...request,
        operationId: PLUGIN_OPERATION_IDS.disable,
      })
    ).toEqual({ title: 'Disable the sign-in plugin corp in the realm' });
  });
});

describe('the configure body (#600)', () => {
  it('takes plain members under config and sealed secrets by path, set or cleared', async () => {
    const schema = pluginConfigBodySchema(await installed());
    expect(
      schema.safeParse({
        config: { issuer: 'https://idp.example', clientId: 'qauth' },
        secrets: { clientSecret: { sealed: SEALED } },
      }).success
    ).toBe(true);
    expect(schema.safeParse({ config: {}, secrets: { clientSecret: null } }).success).toBe(true);
  });

  it('refuses a secret in the clear, so the request an approval stores holds none', async () => {
    const schema = pluginConfigBodySchema(await installed());
    for (const value of [SECRET, { sealed: SECRET }, { sealed: SEALED, value: SECRET }]) {
      expect(schema.safeParse({ config: {}, secrets: { clientSecret: value } }).success).toBe(
        false
      );
    }
  });

  it("refuses an installed plugin's secret member under config, so no approval holds one in the clear", async () => {
    const schema = pluginConfigBodySchema(await installed());
    for (const config of [{ clientSecret: SECRET }, { clientSecret: SECRET, a: 1 }]) {
      const parsed = schema.safeParse({ config });
      expect(parsed.success).toBe(false);
      expect(parsed.error?.issues.map((issue) => issue.message)).toEqual([
        'config holds a secret member: seal it with plugins.secrets.seal and send it under secrets',
      ]);
    }
  });

  it.each([
    ['a member other than config and secrets', { config: {}, code: 'x' }],
    ['an empty sealed value', { config: {}, secrets: { clientSecret: { sealed: '' } } }],
    ['a secret that is not sealed', { config: {}, secrets: { clientSecret: 42 } }],
    ['a config that is not an object', { config: ['a'] }],
    ['a config too large', { config: { blob: 'x'.repeat(17 * 1024) } }],
  ])('refuses %s', async (_case, body) => {
    expect(pluginConfigBodySchema(await installed()).safeParse(body).success).toBe(false);
  });
});

describe('the plugin representation (#600)', () => {
  it('shows a plugin a realm never configured as off, with no config and no secret set', async () => {
    const [plugin] = await installed();
    expect(pluginResource(plugin, undefined)).toEqual({
      name: 'corp',
      type: 'corp_sso',
      package: '@example/corp',
      firstParty: false,
      contract: 'qauth-auth-method/1-rc.0',
      displayName: 'Fixture provider',
      enabled: false,
      config: {},
      secrets: [{ path: 'clientSecret', set: false }],
      version: 0,
    });
  });

  it('never shows a member the plugin now marks secret, even one stored as plain before', async () => {
    const [plugin] = await installed();
    const resource = pluginResource(plugin, {
      realmId: '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b',
      pluginId: 'corp',
      enabled: false,
      config: { clientId: 'qauth', clientSecret: SECRET },
      secrets: {},
      version: 2,
      createdAt: 0,
      updatedAt: 0,
    });
    expect(resource.config).toEqual({ clientId: 'qauth' });
    expect(JSON.stringify(resource)).not.toContain(SECRET);
  });

  it('says a secret holds a value and never shows it, nor its ciphertext', async () => {
    const [plugin] = await installed();
    const ciphertext = 'v1.kid-1.aXY.Y2lwaGVydGV4dA';
    const resource = pluginResource(plugin, {
      realmId: '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b',
      pluginId: 'corp',
      enabled: true,
      config: { issuer: 'https://idp.example', clientId: 'qauth' },
      secrets: { clientSecret: ciphertext },
      version: 3,
      createdAt: 0,
      updatedAt: 0,
    });
    expect(resource).toMatchObject({
      enabled: true,
      config: { issuer: 'https://idp.example', clientId: 'qauth' },
      secrets: [{ path: 'clientSecret', set: true }],
      version: 3,
    });
    expect(JSON.stringify(resource)).not.toContain(ciphertext);
  });
});

describe('the plugin routes in the admin OpenAPI document (#600)', () => {
  it("pass the API conventions against the server's own registry", async () => {
    const [{ default: Fastify }, { default: swagger }, zod, { openapiOptions }, pipeline] =
      await Promise.all([
        import('fastify'),
        import('@fastify/swagger'),
        import('fastify-type-provider-zod'),
        import('../../openapi-options'),
        import('../pipeline'),
      ]);
    const { checkApiConventions } = await import('../../api-conventions/openapi-conventions');
    const { authMethodPluginRuntime } = await import('../../helpers/auth-method-plugins');
    const { pluginRoutes } = await import('./routes');

    const app = Fastify({ logger: false });
    try {
      app.setValidatorCompiler(zod.validatorCompiler);
      app.setSerializerCompiler(zod.serializerCompiler);
      app.decorate('authMethodPlugins', authMethodPluginRuntime(await installed()));
      await app.register(swagger, openapiOptions);
      const uncounted: AdminRateLimitCheck = async () => ({ isAllowed: true, key: 'uncounted' });
      await app.register(pipeline.adminPipeline, {
        registry: OPERATION_REGISTRY,
        refusalsByAddress: uncounted,
        callsBySubject: uncounted,
        routes: async (scope) => {
          await scope.register(pluginRoutes);
        },
      });
      await app.ready();

      const document = app.swagger() as { paths: Record<string, unknown> };
      expect(Object.keys(document.paths).sort()).toEqual([
        '/admin/v1-rc.0/realms/{realmId}/plugins',
        '/admin/v1-rc.0/realms/{realmId}/plugins/{plugin}',
        '/admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/config',
        '/admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/disable',
        '/admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/enable',
        '/admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/secrets/seal',
      ]);
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(6);
    } finally {
      await app.close();
    }
  });
});
