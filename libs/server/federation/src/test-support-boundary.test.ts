import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, parse, posix, relative, resolve, sep } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * Test-support material must not live in, or be reachable from, `src/`.
 *
 * This library's test suites need a working SD-JWT VC issuer and holder —
 * something that mints real credentials with real signatures. That is exactly
 * the kind of module that must never sit next to the validator it exists to
 * attack: `src/` is the package's shipped source (`package.json` `main` is
 * `src/index.ts`), so a credential minter placed there is one careless import
 * away from being production code, and a future edit finds it ready-made.
 *
 * It therefore lives in the lib-level `testing/` directory, OUTSIDE `src/`, and
 * these two rules keep it there:
 *
 *  1. no module under `src/` is test-support material; and
 *  2. no production module under `src/` reaches outside `src/` for a relative
 *     import — which is what makes `testing/` unreachable rather than merely
 *     inconvenient.
 *
 * Placement is not something a unit test of the validator can assert, so it is
 * asserted here directly against the tree.
 */
const PACKAGE_NAME = '@qauth-labs/server-federation';

/**
 * Locate this library's root from the working directory.
 *
 * `import.meta.url` would be the obvious way, but the library typechecks under
 * `module: commonjs`, where it is a compile error. So: walk up from the cwd
 * (Vitest's root is the project directory), and also try the workspace-relative
 * path, accepting only a directory whose `package.json` names THIS package —
 * a wrong guess fails loudly instead of scanning an empty tree.
 */
function findLibRoot(): string {
  const candidates: string[] = [];

  for (let directory = resolve(process.cwd()); ; directory = dirname(directory)) {
    candidates.push(directory, join(directory, 'libs', 'server', 'federation'));
    if (directory === parse(directory).root) break;
  }

  for (const candidate of candidates) {
    const manifest = join(candidate, 'package.json');

    if (!existsSync(manifest)) continue;

    const { name } = JSON.parse(readFileSync(manifest, 'utf8')) as { name?: string };

    if (name === PACKAGE_NAME) return candidate;
  }

  throw new Error(`could not locate ${PACKAGE_NAME} from ${process.cwd()}`);
}

const LIB_ROOT = findLibRoot();
const SRC_ROOT = join(LIB_ROOT, 'src');

/** Every `.ts` file under a directory, recursively. */
function typeScriptFilesUnder(directory: string): string[] {
  const found: string[] = [];

  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);

    if (entry.isDirectory()) {
      found.push(...typeScriptFilesUnder(path));
      continue;
    }

    if (entry.isFile() && entry.name.endsWith('.ts')) found.push(path);
  }

  return found;
}

/** Relative-to-the-lib POSIX path, so a failure message names the file. */
function libRelative(path: string): string {
  return relative(LIB_ROOT, path).split(sep).join(posix.sep);
}

const sourceFiles = typeScriptFilesUnder(SRC_ROOT);
const productionFiles = sourceFiles.filter((path) => !path.endsWith('.test.ts'));

/** Relative import specifiers of one module (`import`, `export`, `import(...)`). */
function relativeImportsOf(path: string): string[] {
  const source = readFileSync(path, 'utf8');
  const specifiers: string[] = [];

  for (const match of source.matchAll(/(?:from|import)\s*\(?\s*['"](\.[^'"]*)['"]/g)) {
    specifiers.push(match[1]);
  }

  return specifiers;
}

describe('test-support boundary', () => {
  it('finds the source tree it is asserting about', () => {
    // A walk that silently found nothing would make every rule below vacuous.
    expect(sourceFiles.length).toBeGreaterThan(20);
    expect(productionFiles.length).toBeGreaterThan(10);
  });

  it('keeps credential-minting fixtures out of the shipped source tree', () => {
    const misplaced = sourceFiles
      .filter((path) => /\.(fixture|fixtures|mock|mocks|test-support)\.ts$/.test(path))
      .map(libRelative);

    expect(misplaced).toEqual([]);
  });

  it('never lets a production module reach outside src/ for an import', () => {
    const escapes: string[] = [];

    for (const path of productionFiles) {
      for (const specifier of relativeImportsOf(path)) {
        const target = resolve(dirname(path), specifier);

        if (target === SRC_ROOT || target.startsWith(SRC_ROOT + sep)) continue;

        escapes.push(`${libRelative(path)} -> ${specifier}`);
      }
    }

    expect(escapes).toEqual([]);
  });
});
