import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { VECTOR_SCHEMA_ID } from './format';
import { loadVectors } from './load';
import { findRepositoryRoot } from './validate';

describe('loadVectors', () => {
  let root: string | undefined;
  afterEach(() => {
    if (root) rmSync(root, { recursive: true, force: true });
    root = undefined;
  });

  function treeWith(id: string, value: unknown): string {
    root = mkdtempSync(join(tmpdir(), 'qauth-vectors-'));
    mkdirSync(join(root, 'test-vectors', 'schema'), { recursive: true });
    mkdirSync(join(root, 'test-vectors', id, '..'), { recursive: true });
    writeFileSync(join(root, 'test-vectors', `${id}.json`), JSON.stringify(value));
    return root;
  }

  it('reads a committed file by id, typed by the caller', () => {
    const vectors = loadVectors<{ code_verifier: string }, { accepted: boolean }>('pkce/s256');
    expect(vectors.id).toBe('pkce/s256');
    expect(vectors.schema).toBe(VECTOR_SCHEMA_ID);
    const appendixB = vectors.cases.find((c) => c.id === 'rfc7636-appendix-b');
    expect(appendixB?.input.code_verifier).toBe('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
    expect(appendixB?.expected.accepted).toBe(true);
  });

  it('finds the repository root by walking up from the package', () => {
    expect(findRepositoryRoot()).toBe(join(__dirname, '..', '..', '..', '..', '..'));
    expect(() => findRepositoryRoot(tmpdir())).toThrow(/no test-vectors\/schema\/ directory/);
  });

  it.each(['pkce', '../pkce/s256', 'pkce/s256.json', 'PKCE/S256'])(
    'refuses the malformed id %j before touching the disk',
    (id) => {
      expect(() => loadVectors(id)).toThrow(/is not a vector file id/);
    }
  );

  it('throws for a missing file', () => {
    expect(() => loadVectors('pkce/does-not-exist')).toThrow(/ENOENT/);
  });

  it('throws for a file the validator rejects, naming its problems', () => {
    const dir = treeWith('example/area', {
      schema: VECTOR_SCHEMA_ID,
      id: 'example/elsewhere',
      description: 'd',
      source: 's',
      cases: [{ id: 'one', input: {}, expected: {} }],
    });
    expect(() => loadVectors('example/area', { root: dir })).toThrow(
      /^example\/area is not a valid vector file:\n {2}id: id "example\/elsewhere" does not match/
    );
  });
});
