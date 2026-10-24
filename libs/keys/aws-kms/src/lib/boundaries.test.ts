import { resolve } from 'node:path';

import { ESLint } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * The Nx constraints of `eslint.config.mjs` for a KEK adapter (ADR-019
 * Decision 9, #577), linted on sample sources placed, by path, in this package
 * and in its would-be consumers.
 *
 * - A `type:kek-adapter` project reaches only the key library and the core and
 *   shared layers.
 * - No project depends on one: `KEK_PROVIDER` loads it by name at run time,
 *   so the auth server and the signer's wiring ship without it.
 */

const WORKSPACE_ROOT = `${resolve(__dirname, '../../../../..')}/`;
const IN_ADAPTER = 'libs/keys/aws-kms/src/lib/sample.ts';

const ADAPTER_RULE = 'A project tagged with "type:kek-adapter" can only depend on libs tagged with';
const SERVER_RULE = 'A project tagged with "scope:server" can only depend on libs tagged with';
const NO_DEPENDENTS_RULE = 'can not depend on libs tagged with "type:kek-adapter"';

let eslint: ESLint;

beforeAll(() => {
  eslint = new ESLint({ cwd: WORKSPACE_ROOT });
});

async function boundaryMessages(code: string, path: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: `${WORKSPACE_ROOT}${path}` });
  return result.messages
    .filter((message) => message.ruleId === '@nx/enforce-module-boundaries')
    .map((message) => message.message);
}

describe('the boundaries of a KEK adapter', () => {
  it('lets the adapter import the key library, its custody entry point and the shared errors', async () => {
    const code =
      "import { isKeyCustodyError } from '@qauth-labs/server-keys';\n" +
      "import { encodeKeyAad } from '@qauth-labs/server-keys/custody';\n" +
      "import { InvalidConfigurationError } from '@qauth-labs/shared-errors';\n" +
      'export const used = [isKeyCustodyError, encodeKeyAad, InvalidConfigurationError];\n';

    expect(await boundaryMessages(code, IN_ADAPTER)).toEqual([]);
  }, 30_000);

  it.each([
    [
      'the config library',
      "import { kekEnvSchema } from '@qauth-labs/server-config';\nexport { kekEnvSchema };\n",
      ADAPTER_RULE,
    ],
    [
      'another server library',
      "import * as egress from '@qauth-labs/server-egress';\nexport { egress };\n",
      ADAPTER_RULE,
    ],
    [
      'the database',
      "import { createDatabase } from '@qauth-labs/infra-db';\nexport { createDatabase };\n",
      SERVER_RULE,
    ],
  ])(
    'refuses an import of %s in the adapter',
    async (_what, code, rule) => {
      expect(await boundaryMessages(code, IN_ADAPTER)).toEqual([expect.stringContaining(rule)]);
    },
    30_000
  );

  const IMPORT_ADAPTER =
    "import { createKekProvider } from '@qauth-labs/keys-aws-kms';\nexport { createKekProvider };\n";

  it.each(['libs/fastify/plugins/signer/src/lib/sample.ts', 'libs/server/jwt/src/lib/sample.ts'])(
    'refuses a dependency on the adapter in %s',
    async (path) => {
      expect(await boundaryMessages(IMPORT_ADAPTER, path)).toEqual([
        expect.stringContaining(NO_DEPENDENTS_RULE),
      ]);
    },
    30_000
  );

  // Nx reports the first constraint that fails: the app layer's own rule for
  // the auth server, and the cycle for the key library.
  it.each([
    ['apps/auth-server/src/app/sample.ts', 'A project tagged with "scope:app" can only depend on'],
    [
      'libs/server/keys/src/lib/sample.ts',
      'Circular dependency between "server-keys" and "keys-aws-kms"',
    ],
  ])(
    'refuses a dependency on the adapter in %s',
    async (path, rule) => {
      expect(await boundaryMessages(IMPORT_ADAPTER, path)).toEqual([expect.stringContaining(rule)]);
    },
    30_000
  );
});
