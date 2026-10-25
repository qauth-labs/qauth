import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

import * as ts from 'typescript';
import { describe, expect, it, vi } from 'vitest';

/**
 * The root entry is the framework-agnostic core (#595): a host that does not
 * use Fastify installs the package without it, since `fastify` is an optional
 * peer dependency that only `@qauth-labs/resource-guard/fastify` needs.
 */

const LIBRARY_ROOT = resolve(__dirname, '..');

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

describe('the root entry', () => {
  it('reaches no Fastify module through its imports', () => {
    const imports = bareImports(join(LIBRARY_ROOT, 'src/index.ts'));

    expect(imports.length).toBeGreaterThan(0);
    expect(imports.filter(({ specifier }) => specifier.startsWith('fastify'))).toEqual([]);
  });

  it('imports and constructs the core while fastify cannot be loaded', async () => {
    vi.doMock('fastify', () => {
      throw new Error('the root entry loaded fastify');
    });
    vi.doMock('fastify-plugin', () => {
      throw new Error('the root entry loaded fastify-plugin');
    });
    try {
      const entry = await import('./index');
      const guard = new entry.ResourceGuard({
        resource: 'https://memory.mcp.example.com',
        authorizationServer: 'https://auth.example.com',
      });
      expect(guard.resource).toBe('https://memory.mcp.example.com');
    } finally {
      vi.doUnmock('fastify');
      vi.doUnmock('fastify-plugin');
    }
  });
});

describe('the /fastify entry', () => {
  it('is where the Fastify plugin lives', () => {
    const imports = bareImports(join(LIBRARY_ROOT, 'src/fastify.ts'));

    expect(imports.map(({ specifier }) => specifier)).toEqual(
      expect.arrayContaining(['fastify', 'fastify-plugin'])
    );
  });
});

describe('the package manifest', () => {
  const manifest = JSON.parse(readFileSync(join(LIBRARY_ROOT, 'package.json'), 'utf8')) as {
    exports?: Record<string, string>;
    dependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
    peerDependenciesMeta?: Record<string, { optional?: boolean }>;
  };

  it('has the root and /fastify entry points', () => {
    expect(Object.keys(manifest.exports ?? {})).toEqual(expect.arrayContaining(['.', './fastify']));
  });

  it('makes fastify an optional peer dependency, and nothing else', () => {
    expect(Object.keys(manifest.peerDependencies ?? {})).toEqual(['fastify']);
    expect(manifest.peerDependenciesMeta?.['fastify']?.optional).toBe(true);
    expect(manifest.dependencies?.['fastify']).toBeUndefined();
  });
});
