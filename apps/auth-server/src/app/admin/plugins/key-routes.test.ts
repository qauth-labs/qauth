import { describe, expect, it } from 'vitest';

import { fixturePluginImporter, fixturePluginMethod } from '../../../testing/auth-method-plugins';
import { OPERATION_REGISTRY } from '../../helpers/admin-operations';
import { loadDeploymentAuthMethodPlugins } from '../../helpers/auth-method-plugins';
import type { AdminRateLimitCheck } from '../pipeline';
import { PLUGIN_KEY_OPERATION_IDS } from './key-operations';

/**
 * The client-assertion key operations of a provider plugin (#1073), without
 * a listener: their classes, what an approver is shown, and the routes in
 * the admin OpenAPI document. The routes behind the pipeline, the import and
 * the switch run against real containers in
 * `admin-plugin-keys.integration.test.ts`.
 */

/** A value as secrets.seal answers one. */
const SEALED = 'v1.kid-1.aXZhaXZhaXZhaXZh.Y2lwaGVydGV4dGNpcGhlcnRleHQ';
const REALM_ID = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b';

describe('the plugin key operations (#1073)', () => {
  // Acceptance criterion (unit half): the import is a security operation,
  // which qauth:admin:write never reaches.
  it('makes the import and the switch security operations with key-custody, under plugins.security', () => {
    const shape = Object.values(PLUGIN_KEY_OPERATION_IDS).map((id) => {
      const operation = OPERATION_REGISTRY.get(id);
      return [id, operation?.class, operation?.effects, operation?.permissions];
    });
    expect(shape).toEqual([
      ['plugins.keys.import', 'security', ['key-custody', 'credential-path'], ['plugins.security']],
      ['plugins.keys.activate', 'security', ['key-custody'], ['plugins.security']],
    ]);
    expect(OPERATION_REGISTRY.get(PLUGIN_KEY_OPERATION_IDS.import)?.secretMembers).toEqual([
      '/privateKey',
    ]);
    expect(
      OPERATION_REGISTRY.get(PLUGIN_KEY_OPERATION_IDS.activate)?.secretMembers
    ).toBeUndefined();
  });

  it('shows an approver the plugin and the key id of an import, never the sealed key', () => {
    const render = OPERATION_REGISTRY.get(PLUGIN_KEY_OPERATION_IDS.import)?.render;
    if (render === undefined) throw new Error('plugins.keys.import has no renderer');
    const rendered = render({
      operationId: PLUGIN_KEY_OPERATION_IDS.import,
      method: 'POST',
      params: { realmId: REALM_ID, plugin: 'apple' },
      query: {},
      body: { kid: 'ABC123DEFG', privateKey: { sealed: SEALED } },
    });
    expect(rendered).toEqual({
      title:
        'Import a provider-issued client-assertion key for the sign-in plugin apple in the realm',
      fields: [
        { label: 'key id (kid)', value: '"ABC123DEFG"' },
        { label: 'private key', value: 'a sealed value (not shown)' },
      ],
    });
    expect(JSON.stringify(rendered)).not.toContain(SEALED);
  });

  it('shows an approver the key a switch makes sign', () => {
    const render = OPERATION_REGISTRY.get(PLUGIN_KEY_OPERATION_IDS.activate)?.render;
    if (render === undefined) throw new Error('plugins.keys.activate has no renderer');
    expect(
      render({
        operationId: PLUGIN_KEY_OPERATION_IDS.activate,
        method: 'POST',
        params: { realmId: REALM_ID, plugin: 'apple' },
        query: {},
        body: { kid: 'ABC123DEFG' },
      })
    ).toEqual({
      title:
        'Switch the client assertions of the sign-in plugin apple to its next key in the realm',
      fields: [{ label: 'key id (kid) that signs from now on', value: '"ABC123DEFG"' }],
    });
  });
});

describe('the plugin key routes in the admin OpenAPI document (#1073)', () => {
  it("pass the API conventions against the server's own registry", async () => {
    const [{ default: Fastify }, { default: swagger }, zod, { adminOpenapiOptions }, pipeline] =
      await Promise.all([
        import('fastify'),
        import('@fastify/swagger'),
        import('fastify-type-provider-zod'),
        import('../openapi-options'),
        import('../pipeline'),
      ]);
    const { checkApiConventions } = await import('../../api-conventions/openapi-conventions');
    const { authMethodPluginRuntime } = await import('../../helpers/auth-method-plugins');
    const { pluginKeyRoutes } = await import('./key-routes');

    const runtime = await loadDeploymentAuthMethodPlugins(
      { info: () => undefined, warn: () => undefined },
      { packages: ['@example/corp'], pluginApiEnabled: true, nodeEnv: 'test' },
      {
        importPackage: fixturePluginImporter({
          '@example/corp': { authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }) },
        }),
      }
    );
    const app = Fastify({ logger: false });
    try {
      app.setValidatorCompiler(zod.validatorCompiler);
      app.setSerializerCompiler(zod.serializerCompiler);
      app.decorate('authMethodPlugins', authMethodPluginRuntime(runtime.installed));
      await app.register(swagger, adminOpenapiOptions);
      const uncounted: AdminRateLimitCheck = async () => ({ isAllowed: true, key: 'uncounted' });
      await app.register(pipeline.adminPipeline, {
        registry: OPERATION_REGISTRY,
        refusalsByAddress: uncounted,
        callsBySubject: uncounted,
        routes: async (scope) => {
          await scope.register(pluginKeyRoutes);
        },
      });
      await app.ready();

      const document = app.swagger() as { paths: Record<string, unknown> };
      expect(Object.keys(document.paths).sort()).toEqual([
        '/admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/keys',
        '/admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/keys/activate',
      ]);
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(2);
    } finally {
      await app.close();
    }
  });
});
