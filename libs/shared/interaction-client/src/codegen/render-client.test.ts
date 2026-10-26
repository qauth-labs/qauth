import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { CLIENT_PATH, DOCUMENT_PATH } from './paths';
import { methodName, renderClient, typeOf } from './render-client';

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');
const read = (path: string) => readFileSync(join(REPO_ROOT, path), 'utf8');

/** Oxfmt's command line, which formats with the repository's `.oxfmtrc.json`. */
const OXFMT = join(
  dirname(createRequire(__filename).resolve('oxfmt/package.json')),
  'bin',
  'oxfmt'
);

describe('the generated Interaction API client', () => {
  // The acceptance criterion: the typed client is generated from the document,
  // and CI fails when the committed client is out of date. The typecheck target
  // then builds it (its inputs include the document).
  it('equals what the generator writes from the published document', () => {
    const document = JSON.parse(read(DOCUMENT_PATH));
    const generated = execFileSync(
      process.execPath,
      [OXFMT, `--stdin-filepath=${join(REPO_ROOT, CLIENT_PATH)}`],
      { cwd: REPO_ROOT, input: renderClient(document, DOCUMENT_PATH), encoding: 'utf8' }
    );
    expect(
      read(CLIENT_PATH),
      `${CLIENT_PATH} is stale: run \`pnpm exec nx run shared-interaction-client:generate\` and commit the result`
    ).toBe(generated);
  });

  it('declares one type per component and one method per operation', () => {
    const document = JSON.parse(read(DOCUMENT_PATH)) as {
      components: { schemas: Record<string, unknown> };
      paths: Record<string, Record<string, { operationId: string }>>;
    };
    const client = read(CLIENT_PATH);
    for (const name of Object.keys(document.components.schemas)) {
      expect(client, name).toMatch(new RegExp(`export (?:interface|type) ${name}\\b`));
    }
    for (const item of Object.values(document.paths)) {
      for (const operation of Object.values(item)) {
        expect(client).toContain(`${methodName(operation.operationId)}: (`);
      }
    }
  });
});

describe('the generator', () => {
  it('names a method after its operationId', () => {
    expect(methodName('interactions.get')).toBe('interactionsGet');
    expect(methodName('interactions.personal.get')).toBe('interactionsPersonalGet');
  });

  it('types the constructs the contract uses', () => {
    expect(typeOf({ $ref: '#/components/schemas/Step' }, 'x')).toBe('Step');
    expect(typeOf({ const: 'pow' }, 'x')).toBe("'pow'");
    expect(typeOf({ type: 'integer', enum: [6, 8] }, 'x')).toBe('6 | 8');
    expect(typeOf({ type: 'string', 'x-extensible-enum': ['a', 'b'] }, 'x')).toBe(
      "'a' | 'b' | (string & {})"
    );
    expect(typeOf({ type: 'array', items: { type: 'string' } }, 'x')).toBe('string[]');
    expect(typeOf({ type: 'object', properties: {} }, 'x')).toBe('Record<string, never>');
    expect(
      typeOf(
        { type: 'object', properties: { a: { type: 'boolean' } }, required: ['a'] },
        'x'
      ).replace(/\s+/g, ' ')
    ).toBe('{ a: boolean; }');
  });

  it('refuses what it cannot type, instead of widening it to unknown', () => {
    expect(() => typeOf({ type: 'string', maxLenght: 3 }, 'x')).toThrow(
      /does not know the keyword/
    );
    expect(() => typeOf({ allOf: [] }, 'x')).toThrow(/does not know the keyword allOf/);
    expect(() => typeOf({ $ref: 'other.json#/x' }, 'x')).toThrow(/unsupported reference/);
    expect(() => typeOf({}, 'x')).toThrow(/cannot type/);
  });
});
