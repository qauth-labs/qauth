import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import * as ts from 'typescript';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * The realm-by-host guard of `.oxlintrc.json` (ADR-019 Decision 1, issue
 * #487): `getOrCreateDefaultRealm` may not come back anywhere, and
 * `DEFAULT_REALM_NAME` may be read only by the boot step (`app.ts`) and the
 * operator's key command (`keys-create.ts`). Every request takes its realm from
 * `request.realm`.
 *
 * Oxlint reads only files on disk, so the samples go to a temporary directory
 * laid out like the workspace, next to a configuration holding the guard's
 * blocks exactly as `.oxlintrc.json` has them. The rest of the workspace
 * configuration stays out: its JS plugins resolve only from the workspace, and
 * the Nx boundaries rule needs the project graph. The first test checks that
 * nothing else in it configures the guard's rules, so the blocks tested here
 * are the ones that apply.
 */

const WORKSPACE_ROOT = resolve(__dirname, '../../../..');
const OXLINT = join(
  dirname(createRequire(__filename).resolve('oxlint/package.json')),
  'bin',
  'oxlint'
);

const GUARD_RULES = ['id-denylist', 'no-restricted-properties'];

interface OxlintConfig {
  plugins?: string[];
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

/** Where request-time code lives: routes, helpers, a library, a test. */
const ANYWHERE = [
  'apps/auth-server/src/app/routes/oauth/sample.ts',
  'apps/auth-server/src/app/helpers/sample.ts',
  'libs/fastify/plugins/jwt/src/lib/sample.ts',
  'apps/auth-server/src/app/routes/oauth/sample.test.ts',
];

/** The boot step and the operator's key command, which may read the setting. */
const BOOT = ['apps/auth-server/src/app/app.ts', 'apps/auth-server/src/keys-create.ts'];

interface Sample {
  readonly kind: 'helper' | 'setting' | 'allowed';
  readonly what: string;
  readonly code: string;
}

const SAMPLES: readonly Sample[] = [
  {
    kind: 'helper',
    what: 'an import of getOrCreateDefaultRealm',
    code: "import { getOrCreateDefaultRealm } from './realm';\nexport { getOrCreateDefaultRealm };\n",
  },
  {
    kind: 'helper',
    what: 'a declaration of getOrCreateDefaultRealm',
    code: 'export async function getOrCreateDefaultRealm(): Promise<void> {}\n',
  },
  {
    kind: 'helper',
    what: 'a mock of getOrCreateDefaultRealm',
    code: "import { vi } from 'vitest';\nvi.mock('./realm', () => ({ getOrCreateDefaultRealm: vi.fn() }));\n",
  },
  {
    kind: 'setting',
    what: 'a property read of DEFAULT_REALM_NAME',
    code: "import { env } from './env';\nexport const name = env.DEFAULT_REALM_NAME;\n",
  },
  {
    kind: 'setting',
    what: 'a computed read of DEFAULT_REALM_NAME',
    code: "import { env } from './env';\nexport const name = env['DEFAULT_REALM_NAME'];\n",
  },
  {
    kind: 'setting',
    what: 'a destructuring read of DEFAULT_REALM_NAME',
    code: "import { env } from './env';\nconst { DEFAULT_REALM_NAME } = env;\nexport { DEFAULT_REALM_NAME };\n",
  },
  {
    kind: 'setting',
    what: 'a read of process.env.DEFAULT_REALM_NAME',
    code: 'export const name = process.env.DEFAULT_REALM_NAME;\n',
  },
  {
    // A key of that name in an object literal (a schema, a test's environment) is not a read.
    kind: 'allowed',
    what: 'DEFAULT_REALM_NAME as an object key',
    code: "export const environment = { DEFAULT_REALM_NAME: 'master' };\n",
  },
];

/** The path a sample is linted as: a numbered sibling, or the boot file itself. */
function samplePath(path: string, index: number): string {
  return BOOT.includes(path) ? path : path.replace(/sample(\.test)?\.ts$/, `sample-${index}$1.ts`);
}

let sandbox: string;
/** Messages per `${sample index}|${path}`. */
const messages = new Map<string, string[]>();
const reportedRules = new Set<string>();

/**
 * Lint every sample. A boot file holds one sample at a time, so each sample
 * gets its own directory, laid out like the workspace, with the guard's
 * blocks as they are.
 */
beforeAll(() => {
  const config = workspaceConfig();
  const sandboxConfig: OxlintConfig & { categories: Record<string, string> } = {
    plugins: config.plugins,
    categories: { correctness: 'off' },
    overrides: (config.overrides ?? []).filter((override) => configures(override.rules)),
  };
  sandbox = mkdtempSync(join(tmpdir(), 'qauth-default-realm-guard-'));

  SAMPLES.forEach((sample, index) => {
    const root = join(sandbox, String(index));
    const paths = [...ANYWHERE, ...BOOT].map((path) => samplePath(path, index));
    mkdirSync(root);
    writeFileSync(join(root, '.oxlintrc.json'), JSON.stringify(sandboxConfig));
    for (const path of paths) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), sample.code);
      messages.set(`${index}|${path}`, []);
    }

    const run = spawnSync(
      process.execPath,
      [OXLINT, '-c', '.oxlintrc.json', '--format=json', ...paths],
      { cwd: root, encoding: 'utf8' }
    );
    let report: { diagnostics: Diagnostic[] };
    try {
      report = JSON.parse(run.stdout) as { diagnostics: Diagnostic[] };
    } catch {
      throw new Error(`Oxlint did not report: ${run.stdout}${run.stderr}`);
    }
    for (const diagnostic of report.diagnostics) {
      // `eslint(id-denylist)`, `eslint(no-restricted-properties)`.
      const [, , rule] = /^(.+)\((.+)\)$/.exec(diagnostic.code) ?? [];
      reportedRules.add(rule);
      messages
        .get(`${index}|${diagnostic.filename}`)
        ?.push([diagnostic.message, diagnostic.help].filter(Boolean).join(' '));
    }
  });
}, 60_000);

afterAll(() => {
  if (sandbox) rmSync(sandbox, { recursive: true, force: true });
});

/** `[path, what, key]` rows for `it.each`, for the samples of `kind` linted at `paths`. */
function cases(paths: readonly string[], kind: Sample['kind']): [string, string, string][] {
  return paths.flatMap((path) =>
    SAMPLES.flatMap((sample, index) =>
      sample.kind === kind
        ? [[path, sample.what, `${index}|${samplePath(path, index)}`] as [string, string, string]]
        : []
    )
  );
}

describe('realm-by-host lint guard (#487)', () => {
  it('is two blocks of the workspace configuration, and nothing else sets its rules', () => {
    const config = workspaceConfig();
    const blocks = (config.overrides ?? []).filter((override) => configures(override.rules));

    expect(configures(config.rules)).toBe(false);
    expect(blocks.map((block) => Object.keys(block.rules ?? {}))).toEqual([
      ['id-denylist'],
      ['no-restricted-properties'],
    ]);
    expect(blocks[0].excludeFiles).toBeUndefined();
    expect(blocks[1].excludeFiles).toEqual(BOOT);
  });

  it('reports through the guard rules only', () => {
    expect([...reportedRules].sort()).toEqual(GUARD_RULES);
  });

  it.each(cases([...ANYWHERE, ...BOOT], 'helper'))('fails lint in %s for %s', (_p, _w, key) => {
    const found = messages.get(key) ?? [];

    expect(found.length).toBeGreaterThan(0);
    expect(found.every((message) => message.includes("'getOrCreateDefaultRealm'"))).toBe(true);
  });

  it.each(cases(ANYWHERE, 'setting'))('fails lint in %s for %s', (_p, _w, key) => {
    const found = messages.get(key);

    expect(found).toHaveLength(1);
    expect(found?.[0]).toContain('DEFAULT_REALM_NAME only names the default realm at boot');
  });

  it.each(cases(BOOT, 'setting'))('lets %s make %s', (_p, _w, key) => {
    expect(messages.get(key)).toEqual([]);
  });

  it.each(cases([...ANYWHERE, ...BOOT], 'allowed'))('lets %s use %s', (_p, _w, key) => {
    expect(messages.get(key)).toEqual([]);
  });
});
