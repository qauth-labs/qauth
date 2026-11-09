import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { AUTH_METHOD_CONTRACT, AUTH_METHOD_CONTRACT_VERSION } from './index';

/**
 * The contract is experimental (ADR-018 §4): every exported declaration of
 * this package carries `@experimental` in its TSDoc, which editors and API
 * extractors show, and its version is a release candidate until QAuth 1.0.0
 * (ADR-018 §5). The server ties the contract to the experimental-feature
 * registry's item `plugin-api` (`AUTH_METHOD_STABILITY` in
 * `@qauth-labs/server-federation`); this package imports no other QAuth
 * package, so it cannot.
 */
const SOURCE = fileURLToPath(new URL('.', import.meta.url));
const MODULE_DIRECTORIES = [join(SOURCE, 'lib'), join(SOURCE, 'testing')];

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
  const files = MODULE_DIRECTORIES.flatMap((directory) =>
    readdirSync(directory)
      .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts') && file !== 'index.ts')
      .map((file) => join(directory, file))
  );

  it('finds the modules it is asserting about', () => {
    expect(files.map((file) => file.slice(file.lastIndexOf('src'))).sort()).toEqual([
      'src/lib/auth-method.ts',
      'src/lib/context.ts',
      'src/lib/contract.ts',
      'src/lib/credential-provider.ts',
      'src/lib/engine.ts',
      'src/lib/errors.ts',
      'src/lib/parameters.ts',
      'src/lib/upstream-oidc-preset.ts',
      'src/lib/validate.ts',
      'src/testing/contract-kit.ts',
      'src/testing/fetch-guard.ts',
      'src/testing/preset-kit.ts',
    ]);
  });

  it('in the types: every exported declaration carries @experimental', () => {
    const unmarked: string[] = [];
    let declarations = 0;
    for (const file of files) {
      for (const { name, doc } of exportedDeclarations(readFileSync(file, 'utf8'))) {
        declarations += 1;
        if (!/@experimental\b/.test(doc)) unmarked.push(`${file}: ${name}`);
      }
    }
    expect(declarations).toBeGreaterThan(50);
    expect(unmarked).toEqual([]);
  });

  it('in its version: a release candidate until QAuth 1.0.0', () => {
    expect(AUTH_METHOD_CONTRACT_VERSION).toMatch(/^1-rc\.\d+$/);
    expect(AUTH_METHOD_CONTRACT).toBe(`qauth-auth-method/${AUTH_METHOD_CONTRACT_VERSION}`);
  });
});
