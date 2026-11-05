import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { fixturePluginImporter, fixturePluginMethod } from '../../testing/auth-method-plugins';
import { supplyRequestRealm, testRealm } from '../../testing/request-realm';
import { loadDeploymentAuthMethodPlugins } from '../helpers/auth-method-plugins';
import upstreamRoutes from './upstream';

vi.mock('../../config/env', () => ({
  env: { NODE_ENV: 'test', LOGIN_RATE_LIMIT: 5, LOGIN_RATE_WINDOW: 900 },
}));

/** A realm with no generic OpenID Connect provider (#639). */
const NO_PROVIDERS = {
  realmUpstreamProviders: { listByRealm: async () => [], find: async () => undefined },
};

/**
 * Which AuthMethods `routes/upstream.ts` mounts (#600): the installed
 * plugins' only. A built-in AuthMethod in the registry has no plugin row,
 * and behind the plugin gate would answer 404 forever; #714 mounts it with
 * its own context.
 */
describe('the plugin route mount (#600)', () => {
  it("mounts the installed plugins' routes, and no built-in AuthMethod's", async () => {
    const runtime = await loadDeploymentAuthMethodPlugins(
      { info: () => undefined, warn: () => undefined },
      { packages: ['@example/corp'], pluginApiEnabled: true, nodeEnv: 'test' },
      {
        importPackage: fixturePluginImporter({
          '@example/corp': { authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }) },
        }),
      }
    );
    const builtIn = fixturePluginMethod({ type: 'oidc_corp', id: 'oidc' });
    const app = Fastify({ logger: false });
    try {
      app.decorate('authMethodPlugins', runtime);
      app.decorate('providerRegistry', {
        authMethods: () => [...runtime.installed.map((plugin) => plugin.method), builtIn],
      } as never);
      await app.register(upstreamRoutes);
      await app.ready();

      expect(app.hasRoute({ method: 'GET', url: '/upstream/corp_sso/callback' })).toBe(true);
      expect(app.hasRoute({ method: 'POST', url: '/upstream/corp_sso/callback' })).toBe(true);
      expect(app.hasRoute({ method: 'GET', url: '/upstream/oidc_corp/callback' })).toBe(false);
      expect(app.hasRoute({ method: 'POST', url: '/upstream/oidc_corp/callback' })).toBe(false);
    } finally {
      await app.close();
    }
  });

  it('mounts no plugin route when no plugin is installed, whatever the registry holds', async () => {
    const { authMethodPluginRuntime } = await import('../helpers/auth-method-plugins');
    const app = Fastify({ logger: false });
    try {
      app.decorate('authMethodPlugins', authMethodPluginRuntime([]));
      app.decorate('providerRegistry', {
        authMethods: () => [fixturePluginMethod({ type: 'oidc_corp', id: 'oidc' })],
      } as never);
      await app.register(upstreamRoutes);
      await app.ready();

      expect(app.hasRoute({ method: 'GET', url: '/upstream/oidc_corp/callback' })).toBe(false);
    } finally {
      await app.close();
    }
  });
});

/**
 * The generic OpenID Connect providers' callbacks (#639): one route per
 * declared route under `/upstream/:type`, resolved per request to the
 * realm's provider of that type.
 */
describe("the realm's OpenID Connect providers' callbacks (#639)", () => {
  async function familyApp(repositories: unknown) {
    const { authMethodPluginRuntime } = await import('../helpers/auth-method-plugins');
    const app = Fastify({ logger: false });
    app.decorate('authMethodPlugins', authMethodPluginRuntime([]));
    app.decorate('providerRegistry', { authMethods: () => [] } as never);
    app.decorate('repositories', repositories as never);
    supplyRequestRealm(app, testRealm({ id: 'realm-1' }));
    await app.register(upstreamRoutes);
    await app.ready();
    return app;
  }

  it('mounts the callback and its form_post bounce once, for every type', async () => {
    const app = await familyApp(NO_PROVIDERS);
    try {
      expect(app.hasRoute({ method: 'GET', url: '/upstream/:type/callback' })).toBe(true);
      expect(app.hasRoute({ method: 'POST', url: '/upstream/:type/callback' })).toBe(true);
    } finally {
      await app.close();
    }
  });

  it('answers as a path no route serves for a type the realm has not, or has off', async () => {
    const find = vi.fn(async (_realmId: string, type: string) =>
      type === 'oidc_off' ? { type, enabled: false } : undefined
    );
    const app = await familyApp({ realmUpstreamProviders: { listByRealm: async () => [], find } });
    try {
      for (const type of ['oidc_none', 'oidc_off', 'corp_sso', 'OIDC_X']) {
        const response = await app.inject({
          method: 'GET',
          url: `/upstream/${type}/callback?code=c&state=s`,
        });
        expect(response.statusCode, type).toBe(404);
        expect(response.json().code, type).toBe('not_found');
      }
      // Only the OpenID Connect types are looked up, in the request's realm.
      expect(find.mock.calls).toEqual([
        ['realm-1', 'oidc_none'],
        ['realm-1', 'oidc_off'],
      ]);
    } finally {
      await app.close();
    }
  });
});
