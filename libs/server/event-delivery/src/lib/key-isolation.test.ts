import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, relative, resolve, sep } from 'node:path';

import * as ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * The delivery role holds no private key (ADR-019 Decisions 8 and 9, issue
 * #460): no module it imports, directly or through another, loads one.
 *
 * Two checks, both of which a deliberate import fails:
 *
 * 1. The import graph. Every module reachable from the library's source,
 *    through relative imports and workspace packages alike, is the library
 *    itself, a `libs/shared` library or an external package other than a key
 *    library. Key-loading code — the key custody library and its signer
 *    wiring, the config library (which reads the key variables), core-crypto
 *    (which imports keys), server-jwt and its plugin, the auth server — is
 *    named in the failure.
 * 2. The Nx constraint of `.oxlintrc.json`: a project tagged
 *    `type:event-delivery` depends only on `scope:shared` libraries.
 */

const WORKSPACE_ROOT = resolve(__dirname, '../../../../..');
const LIBRARY_ROOT = resolve(__dirname, '../..');

/** Workspace projects that load, read or hold private keys or the KEK. */
const KEY_LOADING_PROJECTS: Readonly<Record<string, string>> = {
  'libs/server/keys': 'the key custody library (KEK provider, envelope, signer)',
  'libs/fastify/plugins/signer': "the signer's wiring",
  'libs/server/config': 'the config library, which reads the key variables',
  'libs/core/crypto': 'core-crypto, which imports and generates keys',
  'libs/core/crypto-native': 'the native crypto backend',
  'libs/server/jwt': 'server-jwt, which signs with a loaded key',
  'libs/fastify/plugins/jwt': "server-jwt's plugin",
  'apps/auth-server': 'the auth server, whose env module reads the key variables',
};

/** External packages that import or use private keys. */
const KEY_LIBRARIES: ReadonlySet<string> = new Set(['jose']);

const COMPILER_OPTIONS: ts.CompilerOptions = {
  module: ts.ModuleKind.CommonJS,
  moduleResolution: ts.ModuleResolutionKind.Node10,
  target: ts.ScriptTarget.ES2022,
  resolveJsonModule: true,
};

/** Every workspace package, by name: its directory and package.json. */
function workspacePackages(): Map<string, { dir: string; manifest: Record<string, unknown> }> {
  const packages = new Map<string, { dir: string; manifest: Record<string, unknown> }>();
  const visit = (dir: string, depth: number): void => {
    const manifestPath = join(dir, 'package.json');
    if (existsSync(manifestPath) && dir !== WORKSPACE_ROOT) {
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
      if (typeof manifest['name'] === 'string') packages.set(manifest['name'], { dir, manifest });
      return;
    }
    if (depth === 0) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory() && entry.name !== 'node_modules' && !entry.name.startsWith('.')) {
        visit(join(dir, entry.name), depth - 1);
      }
    }
  };
  visit(join(WORKSPACE_ROOT, 'libs'), 4);
  visit(join(WORKSPACE_ROOT, 'apps'), 1);
  return packages;
}

const PACKAGES = workspacePackages();

/** The source file a workspace import names, through `typesVersions`, `exports` or `main`. */
function resolveWorkspaceImport(specifier: string): string | undefined {
  const match = /^(@qauth-labs\/[^/]+)(?:\/(.+))?$/.exec(specifier);
  if (!match) return undefined;
  const found = PACKAGES.get(match[1]);
  if (!found) return undefined;
  const subpath = match[2];
  const { dir, manifest } = found;
  if (subpath === undefined) {
    const main = typeof manifest['main'] === 'string' ? manifest['main'] : 'src/index.ts';
    return join(dir, main);
  }
  const typesVersions = manifest['typesVersions'] as
    | Record<string, Record<string, string[]>>
    | undefined;
  const mapped = typesVersions?.['*']?.[subpath]?.[0];
  if (mapped) return join(dir, mapped);
  const exported = (manifest['exports'] as Record<string, unknown> | undefined)?.[`./${subpath}`];
  if (typeof exported === 'string') return join(dir, exported);
  // A deep path past the entry point: the file itself, if it is there.
  for (const candidate of [`${subpath}.ts`, join(subpath, 'index.ts'), subpath]) {
    if (existsSync(join(dir, candidate))) return join(dir, candidate);
  }
  return undefined;
}

/** The workspace project a file belongs to, as a root-relative directory. */
function projectOf(file: string): string | undefined {
  let best: string | undefined;
  for (const { dir } of PACKAGES.values()) {
    if ((file === dir || file.startsWith(dir + sep)) && (!best || dir.length > best.length))
      best = dir;
  }
  return best === undefined ? undefined : relative(WORKSPACE_ROOT, best).split(sep).join('/');
}

/** The package an external module belongs to: the path after its last `node_modules`. */
function externalPackageOf(file: string): string {
  const parts = file.split(`${sep}node_modules${sep}`).pop()?.split(sep) ?? [];
  return parts[0]?.startsWith('@') ? `${parts[0]}/${parts[1]}` : (parts[0] ?? file);
}

interface Violation {
  /** The import chain, from the start to the offending module. */
  readonly chain: readonly string[];
  readonly reason: string;
}

/**
 * Walk the imports reachable from `entries`, each a file name and its text,
 * and return what reaches key-loading code or leaves the allowed layers.
 */
function violations(entries: ReadonlyArray<{ file: string; text: string }>): Violation[] {
  const found: Violation[] = [];
  const seen = new Set<string>();
  const queue: Array<{ file: string; text?: string; chain: string[] }> = entries.map((entry) => ({
    file: entry.file,
    text: entry.text,
    chain: [relative(WORKSPACE_ROOT, entry.file)],
  }));

  while (queue.length > 0) {
    const { file, text, chain } = queue.shift() as { file: string; text?: string; chain: string[] };
    if (seen.has(file)) continue;
    seen.add(file);
    const source = text ?? readFileSync(file, 'utf8');
    const { importedFiles } = ts.preProcessFile(source, true, true);

    for (const { fileName: specifier } of importedFiles) {
      const link = [...chain, specifier];
      if (/^(node:|[a-z_]+$)/.test(specifier) && !specifier.startsWith('@')) {
        // A Node built-in, or an external package without a scope.
        if (KEY_LIBRARIES.has(specifier)) {
          found.push({ chain: link, reason: `${specifier} is a key library` });
        }
        if (specifier.startsWith('node:')) continue;
      }
      const target =
        resolveWorkspaceImport(specifier) ??
        ts.resolveModuleName(specifier, file, COMPILER_OPTIONS, ts.sys).resolvedModule
          ?.resolvedFileName;
      if (target === undefined) {
        found.push({
          chain: link,
          reason: 'the import does not resolve, so the walk cannot follow it',
        });
        continue;
      }
      if (target.includes(`${sep}node_modules${sep}`)) {
        const name = externalPackageOf(target);
        if (KEY_LIBRARIES.has(name))
          found.push({ chain: link, reason: `${name} is a key library` });
        continue;
      }
      const project = projectOf(target);
      if (project !== undefined && project in KEY_LOADING_PROJECTS) {
        found.push({ chain: link, reason: `${project} is ${KEY_LOADING_PROJECTS[project]}` });
        continue;
      }
      const allowed =
        project === relative(WORKSPACE_ROOT, LIBRARY_ROOT).split(sep).join('/') ||
        project?.startsWith('libs/shared/') === true;
      if (!allowed) {
        found.push({
          chain: link,
          reason: `${project ?? target} is outside the delivery role's layers`,
        });
        continue;
      }
      queue.push({ file: target, chain: link });
    }
  }
  return found;
}

/** Every shipped source file of the library: what a consumer of it can load. */
function shippedSources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === 'testing' ? [] : shippedSources(path);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [path] : [];
  });
}

const DELIBERATE = join(LIBRARY_ROOT, 'src/lib/deliberate.ts');

describe('the delivery role has no import path to key-loading code', () => {
  it('reaches only itself, the shared layer and external packages that hold no key', () => {
    const sources = shippedSources(join(LIBRARY_ROOT, 'src'));
    expect(sources).toContain(join(LIBRARY_ROOT, 'src/index.ts'));
    expect(violations(sources.map((file) => ({ file, text: readFileSync(file, 'utf8') })))).toEqual(
      []
    );
  });

  it.each([
    [
      'the KEK provider and envelope',
      "import { loadKekProvider } from '@qauth-labs/server-keys/custody';\n",
      'libs/server/keys',
    ],
    [
      'the signer interface package',
      "import type { Signer } from '@qauth-labs/server-keys';\n",
      'libs/server/keys',
    ],
    [
      'a deep path into key custody',
      "import { openKeyMaterial } from '@qauth-labs/server-keys/src/lib/envelope';\n",
      'libs/server/keys',
    ],
    [
      'the config library',
      "import { resolveVerifierSigningKeyPem } from '@qauth-labs/server-config';\n",
      'libs/server/config',
    ],
    ['core-crypto', "import * as crypto from '@qauth-labs/core-crypto';\n", 'libs/core/crypto'],
    [
      'the signer plugin',
      "export const signer = import('@qauth-labs/fastify-plugin-signer');\n",
      'libs/fastify/plugins/signer',
    ],
    ['jose, through require', "const jose = require('jose');\nexport { jose };\n", 'jose'],
  ])('fails for a deliberate import of %s', (_label, text, culprit) => {
    const found = violations([{ file: DELIBERATE, text }]);
    expect(found.length).toBeGreaterThan(0);
    expect(found[0].reason).toContain(culprit);
    expect(found[0].chain[0]).toBe('libs/server/event-delivery/src/lib/deliberate.ts');
  });

  it('fails for a path that reaches key-loading code through another workspace library', () => {
    // fastify-plugin-db reaches infra-db, which is outside the role's layers.
    const found = violations([
      {
        file: DELIBERATE,
        text: "import { databasePlugin } from '@qauth-labs/fastify-plugin-db';\n",
      },
    ]);
    expect(found.map((violation) => violation.reason)).toEqual([
      "libs/fastify/plugins/db is outside the delivery role's layers",
    ]);
  });
});

/**
 * What the second check loads, through `require` because this library's
 * TypeScript settings (CommonJS, `node` resolution) cannot see the `exports`
 * subpaths Oxlint and @nx/oxlint publish their entry points under. Typed with
 * only the members used here.
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

describe('the Nx constraint of the delivery role', () => {
  // The rule reads the project graph Nx caches. A run of Nx leaves one; a
  // plain `vitest run` (CI's coverage job) may not, and then the rule skips
  // every file, so build it first.
  beforeAll(() => {
    try {
      readCachedProjectGraph();
    } catch {
      execFileSync('pnpm', ['exec', 'nx', 'show', 'projects'], {
        cwd: WORKSPACE_ROOT,
        stdio: 'ignore',
      });
    }
  }, 120_000);

  // Oxlint's RuleTester runs Nx's rule through the same JS-plugin API as
  // `nx lint`, on the deliberate file, with the options of `.oxlintrc.json`.
  RuleTester.describe = describe;
  RuleTester.it = (text, fn) => it(text, fn, 30_000);
  RuleTester.itOnly = it.only;

  const options = [boundaryOptions()];
  const DELIVERY_RULE =
    'A project tagged with "type:event-delivery" can only depend on libs tagged with "scope:shared"';
  // infra-db is outside the server layer as well, and that rule speaks first.
  const SERVER_RULE = 'A project tagged with "scope:server" can only depend on libs tagged with';

  const refused = (name: string, code: string, rule: string) => ({
    name: `refuses a deliberate import of ${name}`,
    code,
    filename: DELIBERATE,
    options,
    errors: [{ message: literally(rule) }],
  });

  new RuleTester().run(
    '@nx/enforce-module-boundaries',
    nxBoundaries.rules['enforce-module-boundaries'],
    {
      valid: [
        {
          name: 'allows the shared layer',
          code: "import type { EventEnvelope } from '@qauth-labs/shared-events';\nexport type E = EventEnvelope;\n",
          filename: DELIBERATE,
          options,
        },
      ],
      invalid: [
        refused(
          'server-keys',
          "import type { Signer } from '@qauth-labs/server-keys';\nexport type S = Signer;\n",
          DELIVERY_RULE
        ),
        refused(
          'server-config',
          "import { env } from '@qauth-labs/server-config';\nexport { env };\n",
          DELIVERY_RULE
        ),
        refused(
          'core-crypto',
          "import * as crypto from '@qauth-labs/core-crypto';\nexport { crypto };\n",
          DELIVERY_RULE
        ),
        refused(
          'infra-db',
          "import { createDatabase } from '@qauth-labs/infra-db';\nexport { createDatabase };\n",
          SERVER_RULE
        ),
      ],
    }
  );
});
