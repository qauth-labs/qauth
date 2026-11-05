import { describe, expect, it } from 'vitest';

import { scenario } from '../examples/minimal-plugin/src/fake-provider';
import * as plugin from '../examples/minimal-plugin/src/index';
import { AUTH_METHOD_PLUGIN_EXPORT, isAuthMethod } from './index';
import { checkAuthMethod } from './testing/index';

/**
 * The minimal plugin (`examples/minimal-plugin`) is what the docs point a
 * plugin's author at, so it must keep passing the kit. Its own test runs with
 * Node's runner in its own repository; the npm release's smoke test builds it
 * there against the packed tarball (scripts/sdk-release/smoke.mjs). This runs
 * the same check against the sources.
 */
describe('the minimal example plugin', () => {
  it('exports its method as authMethod', () => {
    expect(AUTH_METHOD_PLUGIN_EXPORT).toBe('authMethod');
    expect(isAuthMethod(plugin[AUTH_METHOD_PLUGIN_EXPORT])).toBe(true);
  });

  it('meets the AuthMethod contract', async () => {
    const report = await checkAuthMethod(plugin.authMethod, scenario);

    expect(report.checks).toEqual(
      expect.arrayContaining(['static', 'start', 'callback', 'pkce', 'declined', 'egress-only'])
    );
  });
});
