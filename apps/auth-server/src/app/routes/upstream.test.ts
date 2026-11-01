import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import { fixturePluginImporter, fixturePluginMethod } from '../../testing/auth-method-plugins';
import { loadDeploymentAuthMethodPlugins } from '../helpers/auth-method-plugins';
import upstreamRoutes from './upstream';

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

  it('mounts nothing when no plugin is installed, whatever the registry holds', async () => {
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
