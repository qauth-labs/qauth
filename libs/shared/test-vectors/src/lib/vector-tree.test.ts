import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { loadVectors } from './load';
import {
  findRepositoryRoot,
  listVectorFiles,
  validateVectorTree,
  vectorIdForPath,
} from './validate';

const root = findRepositoryRoot();

describe('the committed vector files', () => {
  it('are all valid', () => {
    const reports = validateVectorTree(root);
    expect(reports.length).toBeGreaterThan(0);
    expect(reports.filter((r) => r.problems.length > 0)).toEqual([]);
  });

  /** Every `*.test.ts` under apps/ and libs/, outside node_modules and dist. */
  function testFiles(dir: string): string[] {
    const found: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) found.push(...testFiles(path));
      else if (entry.name.endsWith('.test.ts')) found.push(path);
    }
    return found;
  }

  it('are each loaded by at least one test', () => {
    const loaded = new Set<string>();
    for (const file of [...testFiles(join(root, 'apps')), ...testFiles(join(root, 'libs'))]) {
      for (const match of readFileSync(file, 'utf8').matchAll(
        /\bloadVectors\b[^(]*\(\s*['"]([^'"]+)['"]/g
      )) {
        loaded.add(match[1]);
      }
    }
    const ids = listVectorFiles(root).map(vectorIdForPath);
    expect(ids.filter((id) => !loaded.has(id))).toEqual([]);
  });
});

/**
 * `test-vectors/examples/pkce-s256.mjs` shows the format is language-neutral:
 * a short script with Node's standard library alone, run by the plain `node`
 * binary with no TypeScript loader, passes every PKCE case.
 */
describe('the plain Node example', () => {
  const script = join(root, 'test-vectors', 'examples', 'pkce-s256.mjs');
  const source = readFileSync(script, 'utf8');
  const scratch = mkdtempSync(join(tmpdir(), 'qauth-vectors-example-'));
  afterAll(() => rmSync(scratch, { recursive: true, force: true }));

  // No NODE_OPTIONS, so no loader or hook a parent process set reaches it.
  const run = (...args: string[]) =>
    spawnSync(process.execPath, [script, ...args], {
      encoding: 'utf8',
      env: { ...process.env, NODE_OPTIONS: '' },
    });

  it('is under 50 lines and imports only Node built-ins', () => {
    expect(source.trimEnd().split('\n').length).toBeLessThan(50);
    const imports = [...source.matchAll(/^import .* from '([^']+)';$/gm)].map((m) => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    expect(imports.filter((specifier) => !specifier.startsWith('node:'))).toEqual([]);
  });

  it('passes every case of pkce/s256', () => {
    const { cases } = loadVectors('pkce/s256');
    const result = run();
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`${cases.length}/${cases.length} cases passed`);
    for (const { id } of cases) expect(result.stdout).toContain(`pass ${id}\n`);
  });

  it('fails a case whose expected value is flipped', () => {
    const file = JSON.parse(readFileSync(join(root, 'test-vectors', 'pkce', 's256.json'), 'utf8'));
    file.cases[0].expected.accepted = !file.cases[0].expected.accepted;
    const flipped = join(scratch, 's256.json');
    writeFileSync(flipped, JSON.stringify(file));
    const result = run(flipped);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain(`FAIL ${file.cases[0].id}: got `);
    expect(result.stdout).toContain(`${file.cases.length - 1}/${file.cases.length} cases passed`);
  });

  it('refuses a file in another format version', () => {
    const other = join(scratch, 'other.json');
    writeFileSync(other, JSON.stringify({ schema: 'qauth-vectors/2', cases: [] }));
    const result = run(other);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('unsupported vector format "qauth-vectors/2"');
  });
});
