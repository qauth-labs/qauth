import { describe, expect, it } from 'vitest';

import { fixturePluginImporter, fixturePluginMethod } from '../../../testing/auth-method-plugins';
import { OPERATION_REGISTRY } from '../../helpers/admin-operations';
import { ADMIN_SCOPES } from '../../helpers/admin-scopes';
import { loadDeploymentAuthMethodPlugins } from '../../helpers/auth-method-plugins';
import type { AdminRateLimitCheck } from '../pipeline';
import { secretMemberSchemaProblem } from '../secrets/secret-members';
import { PLUGIN_OPERATION_IDS } from './operations';
import {
  newUrlDestinations,
  pluginConfigBodySchema,
  pluginResource,
  pluginSecretMember,
  pluginStateBodySchema,
} from './routes';

/**
 * The plugin operations of the admin API (#600), without a listener: their
 * classes, what an approver is shown, the body a configure request may send
 * and the representation. The routes behind the pipeline are exercised
 * against real containers in `auth-method-plugins-admin.integration.test.ts`.
 */

const SECRET = 'fixture-client-secret-value';
/** A value as secrets.seal answers one. */
const SEALED = 'v1.kid-1.aXZhaXZhaXZhaXZh.Y2lwaGVydGV4dGNpcGhlcnRleHQ';

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
      ['plugins.update', 'security', ['credential-path'], ['plugins.security']],
      ['plugins.enable', 'security', ['credential-path'], ['plugins.security']],
      ['plugins.disable', 'security', ['credential-path'], ['plugins.security']],
    ]);
    const security = OPERATION_REGISTRY.permissions.get('plugins.security');
    expect(security?.class).toBe('security');
    expect(ADMIN_SCOPES.security).toBe('qauth:admin:security');
  });

  // #984: the plugin operations take their secrets by the shared rule.
  it('declares the secrets of a configure secret members, sealed with secrets.seal', () => {
    expect(OPERATION_REGISTRY.get(PLUGIN_OPERATION_IDS.update)?.secretMembers).toEqual([
      '/secrets/*',
    ]);
    // Their own seal and its permission gave way to the shared one.
    expect(OPERATION_REGISTRY.get('plugins.secrets.seal')).toBeUndefined();
    expect(OPERATION_REGISTRY.get('secrets.seal')?.permissions).toEqual(['secrets.seal']);
    expect(OPERATION_REGISTRY.permissions.isGrantable('plugins.write')).toBe(false);
    expect(pluginSecretMember('clientSecret')).toBe('/secrets/clientSecret');
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
        version: 3,
        config: { issuer: 'https://idp.example', clientId: 'qauth' },
        secrets: { clientSecret: { sealed: SEALED }, oldKey: null },
      },
    });
    expect(rendered).toEqual({
      title: 'Replace the configuration of the sign-in plugin corp in the realm',
      fields: [
        { label: 'replaces the state of version', value: '3' },
        { label: 'config.issuer', value: '"https://idp.example"' },
        { label: 'config.clientId', value: '"qauth"' },
        { label: 'secret clientSecret', value: 'set to a new sealed value (not shown)' },
        { label: 'secret oldKey', value: 'cleared' },
      ],
    });
    expect(JSON.stringify(rendered)).not.toContain(SEALED);
  });

  it('names the plugin an enable or a disable is for, and the version of the state it acts on', () => {
    const request = {
      method: 'POST',
      params: { realmId: '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b', plugin: 'corp' },
      query: {},
      body: { version: 4 },
    };
    const version = [{ label: 'acts on the state of version', value: '4' }];
    expect(
      OPERATION_REGISTRY.get(PLUGIN_OPERATION_IDS.enable)?.render?.({
        ...request,
        operationId: PLUGIN_OPERATION_IDS.enable,
      })
    ).toEqual({ title: 'Enable the sign-in plugin corp in the realm', fields: version });
    expect(
      OPERATION_REGISTRY.get(PLUGIN_OPERATION_IDS.disable)?.render?.({
        ...request,
        operationId: PLUGIN_OPERATION_IDS.disable,
      })
    ).toEqual({ title: 'Disable the sign-in plugin corp in the realm', fields: version });
  });
});

describe('the enable and disable body (#600)', () => {
  it.each(['enable', 'disable'] as const)(
    'takes the version of the state a %s acts on, and nothing else',
    (action) => {
      const schema = pluginStateBodySchema(action);
      expect(schema.safeParse({ version: 0 }).success).toBe(true);
      expect(schema.safeParse({ version: 3 }).success).toBe(true);
      // The version is part of the request an approval binds.
      for (const body of [
        undefined,
        null,
        {},
        { version: -1 },
        { version: 1.5 },
        { version: 1, enabled: true },
      ]) {
        expect(schema.safeParse(body).success, JSON.stringify(body)).toBe(false);
      }
    }
  );
});

describe('the configure body (#600)', () => {
  it('takes plain members under config and sealed secrets by path, set or cleared', async () => {
    const schema = pluginConfigBodySchema(await installed());
    expect(
      schema.safeParse({
        version: 0,
        config: { issuer: 'https://idp.example', clientId: 'qauth' },
        secrets: { clientSecret: { sealed: SEALED } },
      }).success
    ).toBe(true);
    expect(
      schema.safeParse({ version: 2, config: {}, secrets: { clientSecret: null } }).success
    ).toBe(true);
    // The version it replaces is part of the request an approval binds.
    expect(schema.safeParse({ config: {}, secrets: { clientSecret: null } }).success).toBe(false);
  });

  it('holds every secret member to the sealed-value schema, as the boot check reads it', async () => {
    expect(
      secretMemberSchemaProblem(pluginConfigBodySchema(await installed()), '/secrets/*')
    ).toBeUndefined();
  });

  it('refuses a secret in the clear, so the request an approval stores holds none', async () => {
    const schema = pluginConfigBodySchema(await installed());
    for (const value of [SECRET, { sealed: SECRET }, { sealed: SEALED, value: SECRET }]) {
      expect(
        schema.safeParse({ version: 0, config: {}, secrets: { clientSecret: value } }).success
      ).toBe(false);
    }
  });

  it("refuses an installed plugin's secret member under config, so no approval holds one in the clear", async () => {
    const schema = pluginConfigBodySchema(await installed());
    for (const config of [{ clientSecret: SECRET }, { clientSecret: SECRET, a: 1 }]) {
      const parsed = schema.safeParse({ version: 0, config });
      expect(parsed.success).toBe(false);
      expect(parsed.error?.issues.map((issue) => issue.message)).toEqual([
        'config holds a secret member: seal it with secrets.seal and send it under secrets',
      ]);
    }
  });

  it.each([
    ['a member other than version, config and secrets', { version: 0, config: {}, code: 'x' }],
    [
      'an empty sealed value',
      { version: 0, config: {}, secrets: { clientSecret: { sealed: '' } } },
    ],
    ['a secret that is not sealed', { version: 0, config: {}, secrets: { clientSecret: 42 } }],
    ['a config that is not an object', { version: 0, config: ['a'] }],
    ['a config too large', { version: 0, config: { blob: 'x'.repeat(17 * 1024) } }],
    ['a negative version', { version: -1, config: {} }],
  ])('refuses %s', async (_case, body) => {
    expect(pluginConfigBodySchema(await installed()).safeParse(body).success).toBe(false);
  });
});

describe('a configure that changes where the plugin sends (#600)', () => {
  const before = {
    issuer: 'https://idp.example',
    tokenEndpoint: 'https://idp.example/token',
    clientId: 'qauth',
    mtls: { certUrls: ['https://certs.example/a'] },
  };

  it('names each URL member that is new or names another origin', () => {
    expect(
      newUrlDestinations(before, { ...before, tokenEndpoint: 'https://attacker.example/token' })
    ).toEqual(['tokenEndpoint']);
    expect(newUrlDestinations(before, { ...before, jwksUri: 'http://idp.example/jwks' })).toEqual([
      'jwksUri',
    ]);
    expect(
      newUrlDestinations(before, {
        ...before,
        mtls: { certUrls: ['https://certs.example/a', 'https://other.example/b'] },
      })
    ).toEqual(['mtls.certUrls[1]']);
    // A URL member that was not a URL before is new too.
    expect(
      newUrlDestinations(
        { ...before, clientId: 'qauth' },
        { ...before, clientId: 'https://x.example' }
      )
    ).toEqual(['clientId']);
    // Two endpoints swapped each name another origin.
    expect(
      newUrlDestinations(
        { a: 'https://one.example', b: 'https://two.example' },
        { a: 'https://two.example', b: 'https://one.example' }
      )
    ).toEqual(['a', 'b']);
  });

  it('lets a configure keep the origins, change a path or a plain member, or drop a URL', () => {
    expect(newUrlDestinations(before, before)).toEqual([]);
    expect(
      newUrlDestinations(before, {
        ...before,
        tokenEndpoint: 'https://idp.example/oauth2/token',
        issuer: 'https://idp.example/',
        clientId: 'other',
      })
    ).toEqual([]);
    const without: Record<string, unknown> = { ...before };
    delete without['tokenEndpoint'];
    expect(newUrlDestinations(before, without)).toEqual([]);
    // Not a destination: another scheme, or not a URL at all.
    expect(
      newUrlDestinations(before, { ...before, logo: 'data:image/png;base64,AA', note: 'see docs' })
    ).toEqual([]);
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
      configuredBy: null,
      mismatch: null,
      version: 0,
    });
  });

  it('never shows a member the plugin now marks secret, even one stored as plain before', async () => {
    const [plugin] = await installed();
    const resource = pluginResource(plugin, {
      realmId: '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b',
      pluginId: 'corp',
      pluginPackage: '@example/corp',
      pluginType: 'corp_sso',
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
      pluginPackage: '@example/corp',
      pluginType: 'corp_sso',
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
      configuredBy: { package: '@example/corp', type: 'corp_sso' },
      mismatch: null,
      version: 3,
    });
    expect(JSON.stringify(resource)).not.toContain(ciphertext);
  });

  // #949: a state another package or type wrote is not this plugin's.
  it.each([
    ['another package wrote', '@example/other-corp', 'corp_sso', 'package_changed'],
    ['this package wrote under another type', '@example/corp', 'corp_sso_v1', 'type_changed'],
    ['a release before #949 wrote', null, null, 'package_unrecorded'],
  ] as const)(
    'shows a state %s as off, holding no secret, and says why',
    async (_case, pluginPackage, pluginType, mismatch) => {
      const [plugin] = await installed();
      const resource = pluginResource(plugin, {
        realmId: '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b',
        pluginId: 'corp',
        pluginPackage,
        pluginType,
        enabled: true,
        config: { issuer: 'https://idp.example', clientId: 'qauth' },
        secrets: { clientSecret: 'v1.kid-1.aXY.Y2lwaGVydGV4dA' },
        version: 4,
        createdAt: 0,
        updatedAt: 0,
      });
      expect(resource).toMatchObject({
        name: 'corp',
        package: '@example/corp',
        type: 'corp_sso',
        enabled: false,
        config: { issuer: 'https://idp.example', clientId: 'qauth' },
        secrets: [{ path: 'clientSecret', set: false }],
        configuredBy: pluginPackage === null ? null : { package: pluginPackage, type: pluginType },
        mismatch,
        version: 4,
      });
    }
  );

  it('keeps the state of a new version of the same package, under the same type', async () => {
    const [plugin] = await installed();
    // What a version bump changes: the method, never the package or the type.
    const upgraded = {
      ...plugin,
      method: { ...plugin.method, display: { name: 'Fixture provider 2' } },
    };
    const resource = pluginResource(upgraded, {
      realmId: '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b',
      pluginId: 'corp',
      pluginPackage: '@example/corp',
      pluginType: 'corp_sso',
      enabled: true,
      config: { issuer: 'https://idp.example', clientId: 'qauth' },
      secrets: { clientSecret: 'v1.kid-1.aXY.Y2lwaGVydGV4dA' },
      version: 5,
      createdAt: 0,
      updatedAt: 0,
    });
    expect(resource).toMatchObject({
      displayName: 'Fixture provider 2',
      enabled: true,
      secrets: [{ path: 'clientSecret', set: true }],
      mismatch: null,
    });
  });
});

describe('the plugin routes in the admin OpenAPI document (#600)', () => {
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
    const { pluginRoutes } = await import('./routes');

    const app = Fastify({ logger: false });
    try {
      app.setValidatorCompiler(zod.validatorCompiler);
      app.setSerializerCompiler(zod.serializerCompiler);
      app.decorate('authMethodPlugins', authMethodPluginRuntime(await installed()));
      await app.register(swagger, adminOpenapiOptions);
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
      ]);
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(5);
    } finally {
      await app.close();
    }
  });
});
