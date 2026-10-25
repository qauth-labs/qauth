import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

/**
 * The verifier is a plain library (issue #479): the auth server, the admin
 * API, `resource-guard` and the Authority Tree all import it, and none of them
 * should get Fastify, a Redis client or another workspace package with it.
 *
 * Every module reachable from the package entry point, through its relative
 * imports, imports nothing but `jose` and Node's `node:crypto`, and the
 * package's runtime dependencies are `jose` and `tslib` alone.
 */

const LIBRARY_ROOT = resolve(__dirname, '../..');
const ENTRY = join(LIBRARY_ROOT, 'src/index.ts');

/** What the library's own code may import from outside itself. */
const ALLOWED_IMPORTS: ReadonlySet<string> = new Set(['jose', 'node:crypto']);

/** Every bare import of the modules reachable from `entry`, with the file that makes it. */
function bareImports(entry: string): Array<{ file: string; specifier: string }> {
  const found: Array<{ file: string; specifier: string }> = [];
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.shift() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    const { importedFiles } = ts.preProcessFile(readFileSync(file, 'utf8'), true, true);
    for (const { fileName: specifier } of importedFiles) {
      if (!specifier.startsWith('.')) {
        found.push({ file: relative(LIBRARY_ROOT, file), specifier });
        continue;
      }
      const base = resolve(dirname(file), specifier);
      const next = [`${base}.ts`, join(base, 'index.ts')].find((candidate) =>
        existsSync(candidate)
      );
      if (next === undefined) throw new Error(`${file} imports ${specifier}, which is not a file`);
      queue.push(next);
    }
  }
  return found;
}

describe('the DPoP verifier library', () => {
  it('imports no Fastify, no Redis client and no workspace package', () => {
    const imports = bareImports(ENTRY);

    expect(imports.length).toBeGreaterThan(0);
    expect(imports.filter(({ specifier }) => !ALLOWED_IMPORTS.has(specifier))).toEqual([]);
  });

  it('depends at run time on jose and tslib alone', () => {
    const manifest = JSON.parse(readFileSync(join(LIBRARY_ROOT, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    };

    expect(Object.keys(manifest.dependencies ?? {}).sort()).toEqual(['jose', 'tslib']);
    expect(manifest.peerDependencies).toBeUndefined();
  });

  it('would notice an import of Fastify', () => {
    const { importedFiles } = ts.preProcessFile(
      "import fp from 'fastify-plugin';\nimport type { FastifyRequest } from 'fastify';",
      true,
      true
    );
    expect(importedFiles.map(({ fileName }) => fileName)).toEqual(['fastify-plugin', 'fastify']);
  });
});
