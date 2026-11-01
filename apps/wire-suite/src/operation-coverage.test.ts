import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { EXPERIMENTAL_OPERATIONS } from './fixtures/experimental';

/**
 * Every OAuth and discovery operation the server publishes has a wire test
 * (#519): each `/oauth/*` and `/.well-known/*` operation of the published
 * OpenAPI document is called by at least one `*.wire.test.ts`, through a
 * `call('METHOD /path', …)` or `operationUrl('METHOD /path', …)` literal, or
 * is experimental, and `suites/experimental/` checks that a default
 * deployment answers it as a route that does not exist.
 *
 * Reads the document as a file and the suites as text; it sends no request,
 * so it runs with the unit suite and fails a pull request that adds such an
 * operation without a wire test.
 */

const SOURCE_ROOT = dirname(fileURLToPath(import.meta.url));
const SUITES_ROOT = join(SOURCE_ROOT, 'suites');
const OPENAPI_DOCUMENT = join(SOURCE_ROOT, '../../docs-site/public/openapi.json');

/** The paths whose every operation needs a wire test. */
const COVERED_PREFIXES = ['/oauth/', '/.well-known/'];

const HTTP_METHODS = ['get', 'put', 'post', 'delete', 'patch', 'head', 'options'];

/** `call('POST /oauth/token'` or `operationUrl('GET /oauth/authorize'`, with either quote. */
const OPERATION_LITERAL =
  /\b(?:call|operationUrl)\(\s*(['"`])((?:GET|POST|PUT|PATCH|DELETE) \/[^'"`]*)\1/g;

/** Every operation of the published document, as `METHOD /path`. */
function publishedOperations(): string[] {
  const document = JSON.parse(readFileSync(OPENAPI_DOCUMENT, 'utf8')) as {
    paths: Record<string, Record<string, unknown>>;
  };
  return Object.entries(document.paths).flatMap(([path, item]) =>
    Object.keys(item)
      .filter((key) => HTTP_METHODS.includes(key))
      .map((method) => `${method.toUpperCase()} ${path}`)
  );
}

function wireTestFiles(directory: string = SUITES_ROOT): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return wireTestFiles(path);
    return entry.name.endsWith('.wire.test.ts') ? [path] : [];
  });
}

/** The operations each wire test file calls by literal, keyed by the operation. */
function calledOperations(): Map<string, string[]> {
  const called = new Map<string, string[]>();
  for (const file of wireTestFiles()) {
    const source = readFileSync(file, 'utf8');
    for (const match of source.matchAll(OPERATION_LITERAL)) {
      const files = called.get(match[2]) ?? [];
      files.push(relative(SOURCE_ROOT, file));
      called.set(match[2], files);
    }
  }
  return called;
}

function isCovered(operation: string): boolean {
  const path = operation.slice(operation.indexOf(' ') + 1);
  return COVERED_PREFIXES.some((prefix) => path.startsWith(prefix));
}

describe('wire coverage of the published OAuth and discovery operations', () => {
  it('finds the operations and the wire tests it compares', () => {
    expect(publishedOperations()).toContain('POST /oauth/token');
    expect(wireTestFiles().length).toBeGreaterThan(5);
    expect(calledOperations().size).toBeGreaterThan(5);
  });

  it('has a wire test for every /oauth/* and /.well-known/* operation of the published document', () => {
    const called = calledOperations();
    const experimental = new Set(EXPERIMENTAL_OPERATIONS);

    const missing = publishedOperations()
      .filter(isCovered)
      .filter((operation) => !called.has(operation) && !experimental.has(operation));

    expect(missing, 'operations no wire test calls').toEqual([]);
  });

  it('names only operations the published document has', () => {
    const published = new Set(publishedOperations());

    const unknown = [...calledOperations().keys()].filter((operation) => !published.has(operation));

    expect(unknown, 'call() literals that name no published operation').toEqual([]);
  });

  it('checks every experimental operation in the experimental suite', () => {
    const source = readFileSync(
      join(SUITES_ROOT, 'experimental/experimental-hidden.wire.test.ts'),
      'utf8'
    );

    expect(source).toMatch(/\bEXPERIMENTAL_OPERATIONS\.map\(/);
  });
});
