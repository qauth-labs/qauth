import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';

import * as ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * The Nx constraints of `.oxlintrc.json` for a KEK adapter (ADR-019
 * Decision 9, #577), run on sample sources placed, by path, in this package
 * and in its would-be consumers.
 *
 * - A `type:kek-adapter` project reaches only the key library and the core and
 *   shared layers.
 * - No project depends on one: `KEK_PROVIDER` loads it by name at run time,
 *   so the auth server and the signer's wiring ship without it.
 */

const WORKSPACE_ROOT = resolve(__dirname, '../../../../..');
const IN_ADAPTER = join(WORKSPACE_ROOT, 'libs/keys/aws-kms/src/lib/sample.ts');

const ADAPTER_RULE = 'A project tagged with "type:kek-adapter" can only depend on libs tagged with';
const SERVER_RULE = 'A project tagged with "scope:server" can only depend on libs tagged with';
const NO_DEPENDENTS_RULE = 'can not depend on libs tagged with "type:kek-adapter"';

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

describe('the boundaries of a KEK adapter', () => {
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

  const IMPORT_ADAPTER =
    "import { createKekProvider } from '@qauth-labs/keys-aws-kms';\nexport { createKekProvider };\n";

  new RuleTester().run(
    '@nx/enforce-module-boundaries',
    nxBoundaries.rules['enforce-module-boundaries'],
    {
      valid: [
        {
          name: 'lets the adapter import the key library, its custody entry point and the shared errors',
          code:
            "import { isKeyCustodyError } from '@qauth-labs/server-keys';\n" +
            "import { encodeKeyAad } from '@qauth-labs/server-keys/custody';\n" +
            "import { InvalidConfigurationError } from '@qauth-labs/shared-errors';\n" +
            'export const used = [isKeyCustodyError, encodeKeyAad, InvalidConfigurationError];\n',
          filename: IN_ADAPTER,
          options,
        },
      ],
      invalid: [
        refused(
          'refuses an import of the config library in the adapter',
          "import { kekEnvSchema } from '@qauth-labs/server-config';\nexport { kekEnvSchema };\n",
          IN_ADAPTER,
          ADAPTER_RULE
        ),
        refused(
          'refuses an import of another server library in the adapter',
          "import * as egress from '@qauth-labs/server-egress';\nexport { egress };\n",
          IN_ADAPTER,
          ADAPTER_RULE
        ),
        refused(
          'refuses an import of the database in the adapter',
          "import { createDatabase } from '@qauth-labs/infra-db';\nexport { createDatabase };\n",
          IN_ADAPTER,
          SERVER_RULE
        ),
        ...[
          'libs/fastify/plugins/signer/src/lib/sample.ts',
          'libs/server/jwt/src/lib/sample.ts',
        ].map((path) =>
          refused(
            `refuses a dependency on the adapter in ${path}`,
            IMPORT_ADAPTER,
            join(WORKSPACE_ROOT, path),
            NO_DEPENDENTS_RULE
          )
        ),
        // Nx reports the first constraint that fails: the app layer's own rule
        // for the auth server, and the cycle for the key library.
        refused(
          'refuses a dependency on the adapter in apps/auth-server/src/app/sample.ts',
          IMPORT_ADAPTER,
          join(WORKSPACE_ROOT, 'apps/auth-server/src/app/sample.ts'),
          'A project tagged with "scope:app" can only depend on'
        ),
        refused(
          'refuses a dependency on the adapter in libs/server/keys/src/lib/sample.ts',
          IMPORT_ADAPTER,
          join(WORKSPACE_ROOT, 'libs/server/keys/src/lib/sample.ts'),
          'Circular dependency between "server-keys" and "keys-aws-kms"'
        ),
      ],
    }
  );
});
