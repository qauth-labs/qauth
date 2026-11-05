import { randomBytes } from 'node:crypto';
import { mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { AUTH_METHOD_CONTRACT, UPSTREAM_STEP_URN } from '@qauth-labs/fastify-plugin-federation';

/**
 * TEST SUPPORT — a plugin installed as an npm package (#1009), not a
 * workspace project.
 *
 * The other fixtures hand the loader an importer over modules in memory. This
 * one writes a package into the workspace's `node_modules`, as `npm install`
 * leaves a published plugin: a `package.json` with an `exports` map and a
 * compiled ES module that imports Zod by its bare name, with the server's Zod
 * as its installed peer. The loader then reaches it the way a deployment's
 * does, through its own `import()` of the name in `AUTH_METHOD_PLUGINS`.
 *
 * The module is plain JavaScript, as a published plugin ships: Node does not
 * strip types under `node_modules`. It carries the contract's values as a
 * bundled plugin does, written out from the SDK when the package is written.
 *
 * Each install has a name of its own, so suites running at once never share
 * a package, and `remove()` deletes it.
 */

/** The workspace root, from `apps/auth-server/src/testing`. */
const WORKSPACE_ROOT = resolve(__dirname, '../../../..');

/** The installed plugin's method `type`, its route segment. */
export const INSTALLED_PLUGIN_TYPE = 'installed_sso';

/** The installed plugin's method `id`, the admin API's name for it. */
export const INSTALLED_PLUGIN_ID = 'installed-sso';

/** A plugin package written into `node_modules`. */
export interface InstalledFixturePlugin {
  /** Its npm name, the value `AUTH_METHOD_PLUGINS` lists. */
  readonly packageName: string;
  /** Deletes the package. */
  remove(): Promise<void>;
}

/** The plugin's compiled entry point: what a plugin's `dist/index.js` is. */
function pluginModule(): string {
  return `import { z } from 'zod';

const configSchema = z.object({
  issuer: z.url(),
  clientId: z.string().min(1).max(64),
  clientSecret: z.string().min(1).max(256).meta({ writeOnly: true }),
});

export const authMethod = {
  contract: ${JSON.stringify(AUTH_METHOD_CONTRACT)},
  type: ${JSON.stringify(INSTALLED_PLUGIN_TYPE)},
  id: ${JSON.stringify(INSTALLED_PLUGIN_ID)},
  display: { name: 'Installed fixture provider' },
  configSchema,
  steps: [${JSON.stringify(UPSTREAM_STEP_URN)}],
  routes: [
    {
      kind: 'callback',
      method: 'GET',
      path: '/callback',
      handle: async () => ({ kind: 'failed', reason: 'invalid_response' }),
    },
  ],
  start: async () => ({
    redirectTo: 'https://provider.example/authorize',
    transaction: {},
    binding: 'installed-fixture-binding-0123456789',
  }),
  verify: async () => {
    throw new Error('the fixture verifies nothing');
  },
  extractAttributes: () => [],
};
`;
}

/** Write a fixture plugin package into the workspace's `node_modules`. */
export async function installFixturePluginPackage(): Promise<InstalledFixturePlugin> {
  const packageName = `qauth-plugin-installed-fixture-${randomBytes(6).toString('hex')}`;
  const directory = join(WORKSPACE_ROOT, 'node_modules', packageName);
  // The Zod the server itself imports, so the plugin's schema is built with
  // it: the peer dependency a deployment installs once.
  const zod = await realpath(join(WORKSPACE_ROOT, 'libs/server/federation/node_modules/zod'));

  await mkdir(join(directory, 'dist'), { recursive: true });
  await mkdir(join(directory, 'node_modules'));
  await symlink(zod, join(directory, 'node_modules', 'zod'), 'dir');
  await writeFile(
    join(directory, 'package.json'),
    `${JSON.stringify(
      {
        name: packageName,
        version: '0.1.0',
        type: 'module',
        exports: { '.': { import: './dist/index.js' } },
        peerDependencies: { zod: '^4.6.7' },
      },
      null,
      2
    )}\n`
  );
  await writeFile(join(directory, 'dist', 'index.js'), pluginModule());

  return {
    packageName,
    remove: () => rm(directory, { recursive: true, force: true }),
  };
}
