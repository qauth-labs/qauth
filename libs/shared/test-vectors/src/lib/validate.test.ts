import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { VECTOR_SCHEMA_ID } from './format';
import {
  listVectorFiles,
  parseVectorFile,
  validateVectorFile,
  validateVectorFileOnDisk,
  validateVectorTree,
  vectorIdForPath,
} from './validate';

/** A small valid file; each test breaks one thing in a copy. */
function validFile(): Record<string, unknown> {
  return {
    schema: VECTOR_SCHEMA_ID,
    id: 'example/area',
    description: 'What the cases test.',
    source: 'RFC 0000 §1',
    cases: [
      { id: 'first', input: { a: 1 }, expected: { b: 2 } },
      { id: 'second', input: {}, expected: { b: 3 }, notes: 'Why it exists.' },
    ],
  };
}

const messages = (value: unknown, options = {}) =>
  validateVectorFile(value, options).map((p) => `${p.path}: ${p.message}`);

describe('validateVectorFile', () => {
  it('accepts a valid file', () => {
    expect(validateVectorFile(validFile())).toEqual([]);
  });

  it.each(['schema', 'id', 'description', 'source', 'cases'])(
    'rejects a file without its %s member',
    (member) => {
      const file = validFile();
      delete file[member];
      expect(messages(file)).toEqual([expect.stringMatching(new RegExp(`^${member}: `))]);
    }
  );

  it.each(['id', 'input', 'expected'])('rejects a case without its %s member', (member) => {
    const file = validFile();
    delete (file['cases'] as Record<string, unknown>[])[1][member];
    expect(messages(file)).toEqual([
      expect.stringMatching(new RegExp(`^cases\\[1\\]\\.${member}: `)),
    ]);
  });

  it.each(['qauth-vectors/2', 'qauth-vectors/0', 'QAUTH-VECTORS/1', ''])(
    'rejects the schema id %j',
    (schema) => {
      expect(messages({ ...validFile(), schema })).toEqual([
        expect.stringMatching(/^schema: .*qauth-vectors\/1/),
      ]);
    }
  );

  it('rejects a duplicate case id and names the first use', () => {
    const file = validFile();
    (file['cases'] as Record<string, unknown>[])[1]['id'] = 'first';
    expect(messages(file)).toEqual([
      'cases[1].id: duplicate case id "first" (first used by cases[0])',
    ]);
  });

  it('rejects an unknown top-level member', () => {
    expect(messages({ ...validFile(), version: 2 })).toEqual([
      expect.stringMatching(/^: .*"version"/),
    ]);
  });

  it('rejects an unknown member in a case', () => {
    const file = validFile();
    (file['cases'] as Record<string, unknown>[])[0]['expect'] = {};
    expect(messages(file)).toEqual([expect.stringMatching(/^cases\[0\]: .*"expect"/)]);
  });

  it('rejects a file with no cases', () => {
    expect(messages({ ...validFile(), cases: [] })).toEqual([expect.stringMatching(/^cases: /)]);
  });

  it.each(['example', 'Example/Area', 'example/area/', '../example/area', 'example//area'])(
    'rejects the file id %j',
    (id) => {
      expect(messages({ ...validFile(), id })).toEqual([expect.stringMatching(/^id: /)]);
    }
  );

  it.each(['First', 'with space', 'with_underscore', '-leading', ''])(
    'rejects the case id %j',
    (id) => {
      const file = validFile();
      (file['cases'] as Record<string, unknown>[])[0]['id'] = id;
      expect(messages(file)).toEqual([expect.stringMatching(/^cases\[0\]\.id: /)]);
    }
  );

  it.each(['description', 'source'])('rejects a blank %s', (member) => {
    expect(messages({ ...validFile(), [member]: '   ' })).toEqual([
      expect.stringMatching(new RegExp(`^${member}: `)),
    ]);
  });

  it('rejects input and expected that are not objects', () => {
    const file = validFile();
    const cases = file['cases'] as Record<string, unknown>[];
    cases[0]['input'] = 'text';
    cases[1]['expected'] = [1];
    expect(messages(file)).toEqual([
      expect.stringMatching(/^cases\[0\]\.input: /),
      expect.stringMatching(/^cases\[1\]\.expected: /),
    ]);
  });

  it('requires every JWK, at any depth, to carry a throwaway-test- kid', () => {
    const file = validFile();
    const cases = file['cases'] as Record<string, unknown>[];
    cases[0]['input'] = {
      jwks: {
        keys: [
          { kty: 'OKP', kid: 'throwaway-test-1' },
          { kty: 'OKP', kid: 'prod-1' },
        ],
      },
    };
    cases[1]['expected'] = { key: { kty: 'EC' } };
    expect(messages(file)).toEqual([
      expect.stringMatching(/^cases\[0\]\.input\.jwks\.keys\[1\]\.kid: .*throwaway-test-/),
      expect.stringMatching(/^cases\[1\]\.expected\.key\.kid: /),
    ]);
  });

  it('rejects an id that does not match the file path', () => {
    expect(messages(validFile(), { expectedId: 'example/other' })).toEqual([
      'id: id "example/area" does not match the file\'s path; expected "example/other"',
    ]);
    expect(validateVectorFile(validFile(), { expectedId: 'example/area' })).toEqual([]);
  });

  it.each([null, 'text', [], 42])('rejects %j as a file', (value) => {
    expect(validateVectorFile(value).length).toBeGreaterThan(0);
  });
});

describe('parseVectorFile', () => {
  it('returns a valid file unchanged', () => {
    const file = validFile();
    expect(parseVectorFile(file)).toBe(file);
  });

  it('throws with every problem listed', () => {
    const file = { ...validFile(), schema: 'qauth-vectors/2', extra: true };
    expect(() => parseVectorFile(file, { label: 'example/area' })).toThrow(
      /^example\/area is not a valid vector file:\n {2}schema: .*\n {2}\(file\): .*"extra"/
    );
  });
});

describe('the vector tree on disk', () => {
  let root: string | undefined;
  afterEach(() => {
    if (root) rmSync(root, { recursive: true, force: true });
    root = undefined;
  });

  function tree(files: Record<string, string>): string {
    root = mkdtempSync(join(tmpdir(), 'qauth-vectors-'));
    mkdirSync(join(root, 'test-vectors', 'schema'), { recursive: true });
    for (const [path, content] of Object.entries(files)) {
      mkdirSync(join(root, 'test-vectors', path, '..'), { recursive: true });
      writeFileSync(join(root, 'test-vectors', path), content);
    }
    return root;
  }

  it('lists every .json file except project.json and schema/, sorted', () => {
    const dir = tree({
      'project.json': '{}',
      'schema/vector-file.schema.json': '{}',
      'b/two.json': '{}',
      'a/one.json': '{}',
      'a/deeper/three.json': '{}',
      'a/notes.md': '',
    });
    expect(listVectorFiles(dir)).toEqual(['a/deeper/three.json', 'a/one.json', 'b/two.json']);
  });

  it('checks each file against its path and reports what is not JSON', () => {
    const dir = tree({
      'example/area.json': JSON.stringify(validFile()),
      'example/moved.json': JSON.stringify(validFile()),
      'example/broken.json': '{ not json',
    });
    const reports = validateVectorTree(dir);
    expect(reports.map((r) => [r.file, r.problems.map((p) => p.path)])).toEqual([
      ['test-vectors/example/area.json', []],
      ['test-vectors/example/broken.json', ['']],
      ['test-vectors/example/moved.json', ['id']],
    ]);
    expect(reports[1].problems[0].message).toMatch(/^not JSON: /);
  });

  it('maps a file path to its id', () => {
    expect(vectorIdForPath('pkce/s256.json')).toBe('pkce/s256');
    expect(vectorIdForPath(join('a', 'b', 'c.json'))).toBe('a/b/c');
  });

  it('validates a single file on disk', () => {
    const dir = tree({ 'example/area.json': JSON.stringify(validFile()) });
    expect(validateVectorFileOnDisk('example/area.json', dir).problems).toEqual([]);
  });
});
