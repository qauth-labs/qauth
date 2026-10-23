import { resolve } from 'node:path';

import { ESLint } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * The key custody guard of `eslint.config.mjs` (issue #464): only the signer's
 * wiring may import `@qauth-labs/server-keys/custody`, the KEK provider and
 * envelope API. The workspace's own ESLint configuration lints sample sources
 * placed, by path, in different projects.
 */

const WORKSPACE_ROOT = `${resolve(__dirname, '../../../../..')}/`;

const GUARD_RULES = new Set(['no-restricted-imports', 'no-restricted-syntax']);

let eslint: ESLint;

beforeAll(() => {
  eslint = new ESLint({ cwd: WORKSPACE_ROOT });
});

/** The guard's messages for `code`, linted as if it were the file at `path`. */
async function guardMessages(code: string, path: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: `${WORKSPACE_ROOT}${path}` });
  return result.messages
    .filter((message) => message.ruleId !== null && GUARD_RULES.has(message.ruleId))
    .map((message) => message.message);
}

const OUTSIDE = [
  'libs/fastify/plugins/jwt/src/lib/sample.ts',
  'libs/server/jwt/src/lib/sample.ts',
  'libs/fastify/plugins/db/src/lib/sample.ts',
  'apps/auth-server/src/app/routes/sample.ts',
];

const WIRING = [
  'libs/fastify/plugins/signer/src/lib/sample.ts',
  'libs/server/keys/src/lib/sample.ts',
];

const FORBIDDEN: [string, string][] = [
  ['the KEK provider', "import { loadKekProvider } from '@qauth-labs/server-keys/custody';\n"],
  [
    'the envelope API',
    "import { openKeyMaterial, sealKeyMaterial } from '@qauth-labs/server-keys/custody';\n",
  ],
  [
    'a type of the KEK provider',
    "import type { KekProvider } from '@qauth-labs/server-keys/custody';\n",
  ],
  ['a re-export', "export { createInProcessSigner } from '@qauth-labs/server-keys/custody';\n"],
  [
    'a deep import past the entry point',
    "import { openKeyMaterial } from '@qauth-labs/server-keys/src/lib/envelope';\n",
  ],
  ['a dynamic import', "export const custody = import('@qauth-labs/server-keys/custody');\n"],
  [
    'a dynamic import of a template literal',
    'export const custody = import(`@qauth-labs/server-keys/custody`);\n',
  ],
  [
    'a type-level import',
    "export type Provider = import('@qauth-labs/server-keys/custody').KekProvider;\n",
  ],
  [
    'an import through createRequire',
    "import { createRequire } from 'node:module';\n" +
      "export const custody = createRequire(__filename)('@qauth-labs/server-keys/custody');\n",
  ],
  [
    'an import-equals declaration',
    "import custody = require('@qauth-labs/server-keys/custody');\nexport { custody };\n",
  ],
];

describe('key custody import guard', () => {
  it.each(OUTSIDE.flatMap((path) => FORBIDDEN.map(([what, code]) => [path, what, code])))(
    'fails lint in %s for %s',
    async (path, _what, code) => {
      const messages = await guardMessages(code, path);

      expect(messages).toHaveLength(1);
      expect(messages[0]).toContain("Only the signer's wiring imports the KEK provider");
    },
    30_000
  );

  it('fails lint for a require() in a CommonJS file', async () => {
    const messages = await guardMessages(
      "module.exports = require('@qauth-labs/server-keys/custody');\n",
      'libs/fastify/plugins/jwt/sample.cjs'
    );

    expect(messages).toHaveLength(1);
  });

  it.each(WIRING.flatMap((path) => FORBIDDEN.map(([what, code]) => [path, what, code])))(
    'lets %s import %s',
    async (path, _what, code) => {
      expect(await guardMessages(code, path)).toEqual([]);
    }
  );

  it.each(OUTSIDE)('lets %s import the Signer interface', async (path) => {
    const code =
      "import { isSignerError, type Signer, SIGNER_POLICY } from '@qauth-labs/server-keys';\n" +
      'export const policy: [typeof SIGNER_POLICY, typeof isSignerError, Signer?] = [SIGNER_POLICY, isSignerError];\n';

    expect(await guardMessages(code, path)).toEqual([]);
  });
});
