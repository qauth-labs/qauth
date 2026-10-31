import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { EXPERIMENTAL_ITEMS } from '@qauth-labs/shared-stability';
import { describe, expect, it } from 'vitest';

import * as federation from '../index';
import { AUTH_METHOD_CONTRACT, AUTH_METHOD_STABILITY } from './contract';

/**
 * The contract is experimental (ADR-018 §4), and says so in three places: in
 * code (`AUTH_METHOD_STABILITY`, readable at run time and tied to the
 * experimental-feature registry), in the types (every exported declaration of
 * this module carries `@experimental` in its TSDoc, which editors and API
 * extractors show), and in the docs (the registry item names its page, which
 * `@qauth-labs/shared-stability` checks carries `experimental: true`).
 */
const MODULE_DIRECTORY = __dirname;

/** Each exported declaration of a module, with the doc comment right above it. */
function exportedDeclarations(source: string): { name: string; doc: string }[] {
  const lines = source.split('\n');
  const found: { name: string; doc: string }[] = [];
  lines.forEach((line, index) => {
    const match =
      /^export (?:declare )?(?:async )?(?:abstract )?(?:const|function|class|interface|type|enum) (\w+)/.exec(
        line
      );
    if (match === null) return;
    let end = index - 1;
    while (end >= 0 && lines[end].trim() === '') end -= 1;
    let doc = '';
    if (end >= 0 && lines[end].trim().endsWith('*/')) {
      let start = end;
      while (start >= 0 && !lines[start].trim().startsWith('/**')) start -= 1;
      doc = lines.slice(Math.max(start, 0), end + 1).join('\n');
    }
    found.push({ name: match[1], doc });
  });
  return found;
}

describe('the AuthMethod contract is marked experimental', () => {
  const files = readdirSync(MODULE_DIRECTORY).filter(
    (file) => file.endsWith('.ts') && !file.endsWith('.test.ts') && file !== 'index.ts'
  );

  it('finds the modules it is asserting about', () => {
    expect(files.sort()).toEqual([
      'auth-method.interface.ts',
      'context.ts',
      'contract-kit.ts',
      'contract.ts',
      'engine.ts',
      'errors.ts',
      'validate.ts',
    ]);
  });

  it('in the types: every exported declaration carries @experimental', () => {
    const unmarked: string[] = [];
    let declarations = 0;
    for (const file of files) {
      for (const { name, doc } of exportedDeclarations(
        readFileSync(join(MODULE_DIRECTORY, file), 'utf8')
      )) {
        declarations += 1;
        if (!/@experimental\b/.test(doc)) unmarked.push(`${file}: ${name}`);
      }
    }
    expect(declarations).toBeGreaterThan(50);
    expect(unmarked).toEqual([]);
  });

  it('in code: the contract names its stability and its registry item', () => {
    expect(AUTH_METHOD_STABILITY).toEqual({
      stability: 'experimental',
      experimentalItem: 'plugin-api',
    });
    expect(AUTH_METHOD_CONTRACT).toMatch(/-rc\.\d+$/);
    expect(federation.AUTH_METHOD_STABILITY).toBe(AUTH_METHOD_STABILITY);
  });

  it('in the docs: the registry item names a docs page', () => {
    const item = EXPERIMENTAL_ITEMS.find(
      (entry) => entry.id === AUTH_METHOD_STABILITY.experimentalItem
    );
    expect(item?.stable).toBe(false);
    expect(item?.docsPage).toBe('/extend/auth-method-contract/');
  });
});
