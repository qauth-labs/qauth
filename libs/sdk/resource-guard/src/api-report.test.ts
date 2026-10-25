import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

/**
 * `api-report.md` lists every name each entry point exports (#595). An export
 * added, removed or renamed without the report changing fails here, so a change
 * to the public API always shows in review as a change to that file.
 */

const LIBRARY_ROOT = fileURLToPath(new URL('..', import.meta.url));
const REPORT = join(LIBRARY_ROOT, 'api-report.md');

const ENTRIES: Record<string, string> = {
  '@qauth-labs/resource-guard': 'src/index.ts',
  '@qauth-labs/resource-guard/fastify': 'src/fastify.ts',
};

/** The names an entry exports, each marked `(type)` when it has no run-time value. */
function exportedNames(entry: string): string[] {
  const file = join(LIBRARY_ROOT, entry);
  const program = ts.createProgram([file], {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    strict: true,
    noEmit: true,
    skipLibCheck: true,
    types: ['node'],
  });
  const checker = program.getTypeChecker();
  const source = program.getSourceFile(file);
  if (source === undefined) throw new Error(`${entry} is not part of the program`);
  const module = checker.getSymbolAtLocation(source);
  if (module === undefined) throw new Error(`${entry} is not a module`);
  return checker
    .getExportsOfModule(module)
    .map((symbol) => {
      const target =
        symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
      return target.flags & ts.SymbolFlags.Value ? symbol.name : `${symbol.name} (type)`;
    })
    .sort();
}

/** The names `api-report.md` lists under each entry's heading. */
function reportedNames(): Record<string, string[]> {
  const report: Record<string, string[]> = {};
  let entry: string | undefined;
  for (const line of readFileSync(REPORT, 'utf8').split('\n')) {
    const heading = /^## `([^`]+)`/.exec(line);
    if (heading) {
      entry = heading[1];
      report[entry] = [];
      continue;
    }
    const item = /^- `([^`]+)`( \(type\))?$/.exec(line);
    if (item && entry !== undefined) report[entry].push(`${item[1]}${item[2] ?? ''}`);
  }
  for (const names of Object.values(report)) names.sort();
  return report;
}

describe('the API report', () => {
  it('lists the same entry points the package exports', () => {
    const manifest = JSON.parse(readFileSync(join(LIBRARY_ROOT, 'package.json'), 'utf8')) as {
      exports: Record<string, string>;
    };
    const fromManifest = Object.keys(manifest.exports)
      .filter((key) => key !== './package.json')
      .map((key) => `@qauth-labs/resource-guard${key === '.' ? '' : key.slice(1)}`)
      .sort();

    expect(Object.keys(reportedNames()).sort()).toEqual(fromManifest);
    expect(Object.keys(ENTRIES).sort()).toEqual(fromManifest);
  });

  it.each(Object.entries(ENTRIES))('matches what %s exports', (name, entry) => {
    expect(exportedNames(entry)).toEqual(reportedNames()[name]);
  });
});
