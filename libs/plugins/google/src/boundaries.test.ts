import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve, sep } from 'node:path';

import * as ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * The Nx constraints of `.oxlintrc.json` for the sign-in method plugins
 * (#671), run on sample sources placed, by path, in each plugin package and
 * in its would-be consumers.
 *
 * - A `scope:plugin` project reaches only the federation library, the
 *   generic upstream client (`type:plugin-base`) and the plugin SDK: never
 *   the app (`apps/`), a Fastify plugin, the database, the config or the key
 *   library.
 * - No project imports a plugin: the plugin runtime imports it by name.
 * - No plugin source names an app: the Nx rule refuses a path into `apps/`,
 *   but resolves no app by its package name (an app is no import target), so
 *   a scan of every plugin source refuses both.
 */

const WORKSPACE_ROOT = resolve(__dirname, '../../../..');
const PLUGINS = ['google', 'microsoft', 'apple'] as const;
const inPlugin = (plugin: string) =>
  join(WORKSPACE_ROOT, `libs/plugins/${plugin}/src/lib/sample.ts`);

const PLUGIN_RULE = 'A project tagged with "scope:plugin" can only depend on libs tagged with';
const RELATIVE_RULE = 'Projects cannot be imported by a relative or absolute path';

/**
 * What the test loads, through `require` because Oxlint and @nx/oxlint
 * publish their entry points under `exports` subpaths. Typed with only the
 * members used here.
 */
const requireFromHere = createRequire(__filename);
type TestFn = (text: string, fn: () => void) => void;
const { RuleTester } = requireFromHere('oxlint/plugins-dev') as {
  RuleTester: {
    new (): {
      run(name: string, rule: unknown, tests: { valid: object[]; invalid: object[] }): void;
    };
    describe: TestFn;
    it: TestFn;
    itOnly: TestFn;
  };
};
const nxBoundaries = (
  requireFromHere('@nx/oxlint/boundaries-plugin') as {
    default: { rules: Record<string, unknown> };
  }
).default;
const { readCachedProjectGraph } = requireFromHere('nx/src/devkit-exports') as {
  readCachedProjectGraph(): unknown;
};
const { readFileMapCache } = requireFromHere('nx/src/devkit-internals') as {
  readFileMapCache(): unknown;
};

/** Whether both caches the rule needs are there; it skips every file without either. */
function nxCachesPresent(): boolean {
  try {
    readCachedProjectGraph();
  } catch {
    return false;
  }
  return readFileMapCache() !== null;
}

/**
 * The `@nx/enforce-module-boundaries` options of `.oxlintrc.json`, which has
 * comments, read the way TypeScript reads a tsconfig.
 */
function boundaryOptions(): unknown {
  const path = join(WORKSPACE_ROOT, '.oxlintrc.json');
  const { config, error } = ts.parseConfigFileTextToJson(path, readFileSync(path, 'utf8'));
  if (error) throw new Error(ts.flattenDiagnosticMessageText(error.messageText, '\n'));
  const overrides = (config as { overrides: Array<{ files: string[]; rules?: object }> }).overrides;
  const [block] = overrides.filter(
    (override) => override.rules && '@nx/enforce-module-boundaries' in override.rules
  );
  expect(block.files).toContain('**/*.ts');
  return (block.rules as Record<string, [string, unknown]>)['@nx/enforce-module-boundaries'][1];
}

/** `text` as a regular expression that matches it literally. */
function literally(text: string): RegExp {
  return new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
}

describe('the boundaries of a sign-in method plugin', () => {
  // The rule reads the project graph and the file map Nx caches. A run of Nx
  // leaves both; a plain `vitest run` (CI's coverage job) may not, and then the
  // rule skips every file, so build them first.
  beforeAll(() => {
    if (!nxCachesPresent()) {
      execFileSync('pnpm', ['exec', 'nx', 'show', 'projects'], {
        cwd: WORKSPACE_ROOT,
        stdio: 'ignore',
      });
    }
  }, 120_000);

  // Oxlint's RuleTester runs Nx's rule through the same JS-plugin API as
  // `nx lint`, with the options of `.oxlintrc.json`.
  RuleTester.describe = describe;
  RuleTester.it = (text, fn) => it(text, fn, 30_000);
  RuleTester.itOnly = it.only;

  const options = [boundaryOptions()];

  const refused = (name: string, code: string, path: string, rule: string) => ({
    name,
    code,
    filename: path,
    options,
    errors: [{ message: literally(rule) }],
  });

  /** What a plugin may not import, and the rule that refuses it. */
  const FORBIDDEN: readonly (readonly [what: string, code: string, rule: string])[] = [
    [
      'a file of apps/ by its path',
      "import { FIRST_PARTY_AUTH_METHOD_PLUGINS } from '../../../../../apps/auth-server/src/app/helpers/auth-method-plugins';\nexport { FIRST_PARTY_AUTH_METHOD_PLUGINS };\n",
      RELATIVE_RULE,
    ],
    [
      'a Fastify plugin',
      "import { createTestSigner } from '@qauth-labs/fastify-plugin-signer';\nexport { createTestSigner };\n",
      PLUGIN_RULE,
    ],
    [
      'the database',
      "import { createDatabase } from '@qauth-labs/infra-db';\nexport { createDatabase };\n",
      PLUGIN_RULE,
    ],
    [
      'the key library',
      "import { isKeyCustodyError } from '@qauth-labs/server-keys';\nexport { isKeyCustodyError };\n",
      PLUGIN_RULE,
    ],
    [
      'the config library',
      "import { pluginsEnvSchema } from '@qauth-labs/server-config';\nexport { pluginsEnvSchema };\n",
      PLUGIN_RULE,
    ],
  ];

  new RuleTester().run(
    '@nx/enforce-module-boundaries',
    nxBoundaries.rules['enforce-module-boundaries'],
    {
      valid: PLUGINS.map((plugin) => ({
        name: `lets the ${plugin} plugin import the upstream client, the federation library and the plugin SDK`,
        code:
          "import { createUpstreamOidcPresetMethod } from '@qauth-labs/server-upstream-oidc';\n" +
          "import { completeUpstreamStep } from '@qauth-labs/server-federation';\n" +
          "import { AUTH_METHOD_CONTRACT } from '@qauth-labs/plugin-sdk';\n" +
          'export const used = [createUpstreamOidcPresetMethod, completeUpstreamStep, AUTH_METHOD_CONTRACT];\n',
        filename: inPlugin(plugin),
        options,
      })),
      invalid: [
        ...PLUGINS.flatMap((plugin) =>
          FORBIDDEN.map(([what, code, rule]) =>
            refused(
              `refuses an import of ${what} in the ${plugin} plugin`,
              code,
              inPlugin(plugin),
              rule
            )
          )
        ),
        // Nx reports the first constraint that fails: the app layer's own
        // rule for the auth server, the plugin rule for another plugin.
        refused(
          'refuses an import of a plugin in apps/auth-server/src/app/sample.ts',
          "import { authMethod } from '@qauth-labs/plugin-google';\nexport { authMethod };\n",
          join(WORKSPACE_ROOT, 'apps/auth-server/src/app/sample.ts'),
          'A project tagged with "scope:app" can only depend on'
        ),
        refused(
          'refuses an import of one plugin in another',
          "import { authMethod } from '@qauth-labs/plugin-google';\nexport { authMethod };\n",
          inPlugin('apple'),
          PLUGIN_RULE
        ),
      ],
    }
  );
});

const APPS = join(WORKSPACE_ROOT, 'apps');

/** The npm names of the workspace's apps. */
function appPackages(): readonly string[] {
  return readdirSync(APPS).flatMap((dir) => {
    try {
      const manifest = JSON.parse(readFileSync(join(APPS, dir, 'package.json'), 'utf8')) as {
        name?: unknown;
      };
      return typeof manifest.name === 'string' ? [manifest.name] : [];
    } catch {
      return [];
    }
  });
}

/**
 * The imports of `text`, a file at `path`, that reach `apps/`: an app's
 * package (or a path in it), or a relative or absolute path into the
 * directory. Static and dynamic imports, re-exports and `require` calls.
 */
function appImports(text: string, path: string, packages: readonly string[]): string[] {
  const { importedFiles } = ts.preProcessFile(text, true, true);
  return importedFiles
    .map((file) => file.fileName)
    .filter((specifier) => {
      if (packages.some((name) => specifier === name || specifier.startsWith(`${name}/`))) {
        return true;
      }
      if (!specifier.startsWith('.') && !specifier.startsWith('/')) return false;
      const target = resolve(dirname(path), specifier);
      return target === APPS || target.startsWith(`${APPS}${sep}`);
    });
}

/** Every TypeScript file under `directory`. */
function sourcesUnder(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return entry.name === 'node_modules' ? [] : sourcesUnder(path);
    return entry.name.endsWith('.ts') ? [path] : [];
  });
}

describe('no plugin imports from apps/ (#671)', () => {
  const packages = appPackages();

  it('knows the auth server among the apps', () => {
    expect(packages).toContain('@qauth-labs/auth-server');
  });

  it.each(PLUGINS)('finds no import of an app in the %s plugin', (plugin) => {
    const sources = sourcesUnder(join(WORKSPACE_ROOT, 'libs/plugins', plugin));
    expect(sources.length).toBeGreaterThan(0);
    for (const path of sources) {
      expect({ path, imports: appImports(readFileSync(path, 'utf8'), path, packages) }).toEqual({
        path,
        imports: [],
      });
    }
  });

  it.each([
    "import { x } from '@qauth-labs/auth-server';",
    "export * from '@qauth-labs/auth-server/src/app/helpers/auth-method-plugins';",
    "const app = await import('@qauth-labs/wire-suite');",
    "const app = require('../../../../../apps/auth-server/src/main');",
    "import '../../../../../apps/migration-runner/src/main';",
  ])('would find %s', (code) => {
    expect(appImports(code, inPlugin('google'), packages)).toHaveLength(1);
  });
});
