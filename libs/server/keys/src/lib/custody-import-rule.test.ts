import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import * as ts from 'typescript';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * The key custody guard of `.oxlintrc.json` (issue #464): only the signer's
 * wiring and the KEK adapter packages may import
 * `@qauth-labs/server-keys/custody`, the KEK provider and envelope API. Oxlint
 * lints sample sources placed, by path, in different projects, with the
 * guard's block of the workspace configuration.
 *
 * Oxlint reads only files on disk, so the samples go to a temporary directory
 * laid out like the workspace, next to a configuration holding the guard block
 * exactly as `.oxlintrc.json` has it and the local plugin it uses. The rest of
 * the workspace configuration stays out: its other plugins resolve only from
 * the workspace, and the Nx boundaries rule needs the project graph. The first
 * test checks that nothing else in it configures the guard's rules.
 */

const WORKSPACE_ROOT = resolve(__dirname, '../../../../..');
const OXLINT = join(
  dirname(createRequire(__filename).resolve('oxlint/package.json')),
  'bin',
  'oxlint'
);

const GUARD_RULES = ['no-restricted-imports', 'qauth/no-restricted-syntax'];

interface OxlintConfig {
  plugins?: string[];
  jsPlugins?: string[];
  rules?: Record<string, unknown>;
  overrides?: Array<{ files: string[]; excludeFiles?: string[]; rules?: Record<string, unknown> }>;
}

interface Diagnostic {
  message: string;
  help?: string;
  code: string;
  filename: string;
}

/** `.oxlintrc.json`, which has comments, read the way TypeScript reads a tsconfig. */
function workspaceConfig(): OxlintConfig {
  const path = join(WORKSPACE_ROOT, '.oxlintrc.json');
  const { config, error } = ts.parseConfigFileTextToJson(path, readFileSync(path, 'utf8'));
  if (error) throw new Error(ts.flattenDiagnosticMessageText(error.messageText, '\n'));
  return config as OxlintConfig;
}

const configures = (rules: Record<string, unknown> | undefined) =>
  GUARD_RULES.some((rule) => rules !== undefined && rule in rules);

const OUTSIDE = [
  'libs/fastify/plugins/jwt/src/lib/sample.ts',
  'libs/server/jwt/src/lib/sample.ts',
  'libs/fastify/plugins/db/src/lib/sample.ts',
  'apps/auth-server/src/app/routes/sample.ts',
];

const WIRING = [
  'libs/fastify/plugins/signer/src/lib/sample.ts',
  'libs/server/keys/src/lib/sample.ts',
  // A KEK adapter implements the provider and runs in the signer's process.
  'libs/keys/aws-kms/src/lib/sample.ts',
  'libs/keys/vault/src/lib/sample.ts',
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

const SIGNER_IMPORT =
  "import { isSignerError, type Signer, SIGNER_POLICY } from '@qauth-labs/server-keys';\n" +
  'export const policy: [typeof SIGNER_POLICY, typeof isSignerError, Signer?] = [SIGNER_POLICY, isSignerError];\n';

const COMMONJS_SAMPLE = 'libs/fastify/plugins/jwt/sample.cjs';

/** Every sample, keyed by the workspace path it is linted as. */
const SAMPLES = new Map<string, string>();

/** The path a FORBIDDEN entry is written to under `path`'s directory. */
function samplePath(path: string, index: number): string {
  return path.replace(/sample\.ts$/, `sample-${index}.ts`);
}

for (const path of [...OUTSIDE, ...WIRING]) {
  FORBIDDEN.forEach(([, code], index) => SAMPLES.set(samplePath(path, index), code));
}
for (const path of OUTSIDE) SAMPLES.set(samplePath(path, FORBIDDEN.length), SIGNER_IMPORT);
SAMPLES.set(COMMONJS_SAMPLE, "module.exports = require('@qauth-labs/server-keys/custody');\n");

let sandbox: string;
const messagesByPath = new Map<string, string[]>();
const reportedRules = new Set<string>();

beforeAll(() => {
  const config = workspaceConfig();
  const [guard] = (config.overrides ?? []).filter((override) => configures(override.rules));
  sandbox = mkdtempSync(join(tmpdir(), 'qauth-custody-guard-'));

  // The guard block as it is, and the local plugins with their paths made
  // absolute, since the configuration no longer sits at the workspace root.
  const sandboxConfig: OxlintConfig & { categories: Record<string, string> } = {
    plugins: config.plugins,
    jsPlugins: (config.jsPlugins ?? [])
      .filter((plugin) => plugin.startsWith('.'))
      .map((plugin) => join(WORKSPACE_ROOT, plugin)),
    categories: { correctness: 'off' },
    overrides: [guard],
  };
  writeFileSync(join(sandbox, '.oxlintrc.json'), JSON.stringify(sandboxConfig));
  for (const [path, code] of SAMPLES) {
    mkdirSync(dirname(join(sandbox, path)), { recursive: true });
    writeFileSync(join(sandbox, path), code);
  }

  const run = spawnSync(
    process.execPath,
    [OXLINT, '-c', '.oxlintrc.json', '--format=json', ...SAMPLES.keys()],
    { cwd: sandbox, encoding: 'utf8' }
  );
  let report: { diagnostics: Diagnostic[] };
  try {
    report = JSON.parse(run.stdout) as { diagnostics: Diagnostic[] };
  } catch {
    throw new Error(`Oxlint did not report: ${run.stdout}${run.stderr}`);
  }
  for (const path of SAMPLES.keys()) messagesByPath.set(path, []);
  for (const diagnostic of report.diagnostics) {
    // `eslint(no-restricted-imports)`, `qauth(no-restricted-syntax)`.
    const [, plugin, rule] = /^(.+)\((.+)\)$/.exec(diagnostic.code) ?? [];
    reportedRules.add(plugin === 'eslint' ? rule : `${plugin}/${rule}`);
    // Oxlint's `no-restricted-imports` prints the configured message as help.
    messagesByPath
      .get(diagnostic.filename)
      ?.push([diagnostic.message, diagnostic.help].filter(Boolean).join(' '));
  }
}, 30_000);

afterAll(() => {
  if (sandbox) rmSync(sandbox, { recursive: true, force: true });
});

describe('key custody import guard', () => {
  it('is one block of the workspace configuration, and nothing else sets its rules', () => {
    const config = workspaceConfig();
    const blocks = (config.overrides ?? []).filter((override) => configures(override.rules));

    expect(configures(config.rules)).toBe(false);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].excludeFiles).toEqual([
      'libs/server/keys/**',
      'libs/fastify/plugins/signer/**',
      'libs/keys/aws-kms/**',
      'libs/keys/vault/**',
    ]);
  });

  it('reports through the guard rules only', () => {
    expect([...reportedRules].sort()).toEqual(GUARD_RULES);
  });

  it.each(
    OUTSIDE.flatMap((path) =>
      FORBIDDEN.map(([what], index) => [path, what, samplePath(path, index)])
    )
  )('fails lint in %s for %s', (_path, _what, sample) => {
    const messages = messagesByPath.get(sample);

    expect(messages).toHaveLength(1);
    expect(messages?.[0]).toContain("Only the signer's wiring imports the KEK provider");
  });

  it('fails lint for a require() in a CommonJS file', () => {
    expect(messagesByPath.get(COMMONJS_SAMPLE)).toHaveLength(1);
  });

  it.each(
    WIRING.flatMap((path) =>
      FORBIDDEN.map(([what], index) => [path, what, samplePath(path, index)])
    )
  )('lets %s import %s', (_path, _what, sample) => {
    expect(messagesByPath.get(sample)).toEqual([]);
  });

  it.each(OUTSIDE)('lets %s import the Signer interface', (path) => {
    expect(messagesByPath.get(samplePath(path, FORBIDDEN.length))).toEqual([]);
  });
});
