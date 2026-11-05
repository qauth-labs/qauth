import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

/**
 * The package's three entry points (#1009). The main one and `/host` are what
 * the server runs, so neither reaches the test kit, which replaces the global
 * `fetch` while it runs; `/testing` is where the kit lives. None imports
 * another QAuth package: a plugin installs this one alone, beside the Zod its
 * server runs (a peer dependency).
 */

const LIBRARY_ROOT = fileURLToPath(new URL('..', import.meta.url));

/** Every import of the modules reachable from `entry`, with the file that makes it. */
function reachable(entry: string): {
  files: string[];
  bare: { file: string; specifier: string }[];
} {
  const bare: { file: string; specifier: string }[] = [];
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.shift() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    const { importedFiles } = ts.preProcessFile(readFileSync(file, 'utf8'), true, true);
    for (const { fileName: specifier } of importedFiles) {
      if (!specifier.startsWith('.')) {
        bare.push({ file: relative(LIBRARY_ROOT, file), specifier });
        continue;
      }
      // The sources import `./x.js` for Node's ESM resolution; the file is `x.ts`.
      const base = resolve(dirname(file), specifier.replace(/\.js$/, ''));
      const next = [`${base}.ts`, join(base, 'index.ts')].find((candidate) =>
        existsSync(candidate)
      );
      if (next === undefined) throw new Error(`${file} imports ${specifier}, which is not a file`);
      queue.push(next);
    }
  }
  return { files: [...seen].map((file) => relative(LIBRARY_ROOT, file)).sort(), bare };
}

const ENTRIES = {
  main: join(LIBRARY_ROOT, 'src/index.ts'),
  host: join(LIBRARY_ROOT, 'src/host.ts'),
  testing: join(LIBRARY_ROOT, 'src/testing/index.ts'),
};

describe('the entry points', () => {
  it.each([
    ['main', ENTRIES.main],
    ['/host', ENTRIES.host],
  ])('%s reaches no module of the test kit', (_name, entry) => {
    const { files } = reachable(entry);

    expect(files.length).toBeGreaterThan(1);
    expect(files.filter((file) => file.startsWith('src/testing/'))).toEqual([]);
  });

  it('/testing holds the kit and its fetch guard', () => {
    expect(reachable(ENTRIES.testing).files).toEqual(
      expect.arrayContaining(['src/testing/contract-kit.ts', 'src/testing/fetch-guard.ts'])
    );
  });

  it.each(Object.entries(ENTRIES))(
    '%s imports only Node built-ins and Zod, never another QAuth package',
    (_name, entry) => {
      const outside = reachable(entry).bare.filter(
        ({ specifier }) => !specifier.startsWith('node:') && specifier !== 'zod'
      );

      expect(outside).toEqual([]);
    }
  );
});

describe('the package manifest', () => {
  const manifest = JSON.parse(readFileSync(join(LIBRARY_ROOT, 'package.json'), 'utf8')) as {
    exports?: Record<string, string>;
    dependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
    peerDependenciesMeta?: Record<string, { optional?: boolean }>;
  };

  it('has the main, /host and /testing entry points', () => {
    expect(Object.keys(manifest.exports ?? {}).sort()).toEqual(
      ['.', './host', './package.json', './testing'].sort()
    );
  });

  it("makes Zod a required peer dependency, the server's own copy, and depends on nothing else", () => {
    expect(manifest.peerDependencies).toEqual({ zod: expect.any(String) });
    expect(manifest.peerDependenciesMeta?.['zod']?.optional).not.toBe(true);
    expect(manifest.dependencies ?? {}).toEqual({});
  });
});
