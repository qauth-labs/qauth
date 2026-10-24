/**
 * Guard for `scripts/experimental-status.mjs`, the promotion report of the
 * experimental-feature registry (#476, ADR-018 §5).
 *
 * The script ends in `process.exitCode = await main(...)`, so it cannot be
 * imported without running it. It is exercised the way a maintainer runs it:
 * spawned as a child process, against the real registry or a fixture written
 * to a temporary directory with `--registry`. The assertions are on exit
 * codes and on what it prints.
 *
 * The checks themselves are unit-tested in `libs/shared/stability`; this file
 * holds the script to them, and holds that Node loads the TypeScript registry
 * with no warning on stderr.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'experimental-status.mjs');

const EXIT_OK = 0;
const EXIT_FAILED = 1;
const EXIT_INPUT = 2;

const workspaces: string[] = [];

afterAll(() => {
  for (const dir of workspaces) rmSync(dir, { recursive: true, force: true });
});

function run(args: readonly string[]) {
  const result = spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NODE_OPTIONS: '' },
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

/** Write `items` as a registry fixture and return its path. */
function fixture(items: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'experimental-status-'));
  workspaces.push(dir);
  const path = join(dir, 'registry.json');
  writeFileSync(path, JSON.stringify(items));
  return path;
}

const none = { evidence: [] };

/** A built, stable item with evidence for every condition. */
const stableItem = (conditions: Record<string, { evidence: string[] }> = {}) => ({
  id: 'sample-feature',
  title: 'A sample feature',
  description: 'A feature for this test.',
  adr: 'docs/adr/018-1-0-scope-and-stability.md',
  surface: 'server',
  switchKey: 'SAMPLE_FEATURE_ENABLED',
  switchValue: 'true',
  requires: [],
  spec: { name: 'A sample RFC', url: 'https://www.rfc-editor.org/rfc/rfc9449', status: 'rfc' },
  built: true,
  stable: true,
  conditions: {
    'spec-final': { evidence: ['RFC 9449'] },
    'external-beta': { evidence: ['#900'] },
    'external-audit': {
      evidence: ['docs/adr/018-1-0-scope-and-stability.md#8-assurance-before-10'],
    },
    'conformance-tests': { evidence: ['scripts/experimental-status.test.ts'] },
    ...conditions,
  },
});

describe('experimental-status on the registry', () => {
  // The task list of #476: the script prints the four conditions per item.
  it('prints the four conditions of every item, and which may become stable', () => {
    const result = run([]);

    expect(result.status).toBe(EXIT_OK);
    for (const id of [
      'fipa-challenge-endpoint',
      'node-first-party',
      'oid4vp-1.0-base',
      'attestation-client-auth',
      'pass-through-leg',
      'plugin-api',
    ]) {
      const block = result.stdout.split('\n\n').find((part) => part.startsWith(`${id}: `));
      expect(block, id).toBeDefined();
      expect(block?.match(/^ {2}\[[ x]\] [1-4]\. /gm), id).toHaveLength(4);
    }
    expect(result.stdout.trimEnd().split('\n').at(-1)).toBe('May become stable: none.');
  });

  it('loads the TypeScript registry without a warning', () => {
    expect(run([]).stderr).toBe('');
  });

  it('passes --check-stable', () => {
    const result = run(['--check-stable']);

    expect(result.status).toBe(EXIT_OK);
    expect(result.stdout).toContain(
      '--check-stable: every stable item has evidence for all four conditions.'
    );
  });
});

describe('experimental-status --check-stable', () => {
  // The acceptance criteria of #476: it fails when `stable: true` and a
  // condition lacks evidence, and passes when all four have evidence.
  it.each(['spec-final', 'external-beta', 'external-audit', 'conformance-tests'])(
    'fails a stable item whose condition %s lacks evidence',
    (condition) => {
      const item = stableItem({ [condition]: none });

      const result = run(['--registry', fixture([item]), '--check-stable']);

      expect(result.status).toBe(EXIT_FAILED);
      expect(result.stderr).toContain(
        `sample-feature: stable, but condition ${condition} has no evidence`
      );
    }
  );

  it('passes a stable item with evidence for all four conditions', () => {
    const result = run(['--registry', fixture([stableItem()]), '--check-stable']);

    expect(result.stderr).toBe('');
    expect(result.status).toBe(EXIT_OK);
  });

  it('fails a stable item whose evidence names a path that does not exist', () => {
    const item = stableItem({ 'conformance-tests': { evidence: ['scripts/no-such-test.ts'] } });

    const result = run(['--registry', fixture([item]), '--check-stable']);

    expect(result.status).toBe(EXIT_FAILED);
    expect(result.stderr).toContain(
      'sample-feature: stable, but the evidence of conformance-tests: scripts/no-such-test.ts does not exist'
    );
  });

  it.each([
    ['a section the file does not have', 'docs/adr/018-1-0-scope-and-stability.md#8-assurance'],
    ['a directory', 'docs/adr'],
  ])('fails a stable item whose evidence names %s', (_label, evidence) => {
    const item = stableItem({ 'external-audit': { evidence: [evidence] } });

    const result = run(['--registry', fixture([item]), '--check-stable']);

    expect(result.status).toBe(EXIT_FAILED);
    expect(result.stderr).toContain(`the evidence of external-audit: ${evidence} does not exist`);
  });

  it('fails an item whose ADR link names a file that does not exist', () => {
    const item = { ...stableItem(), adr: 'docs/adr/099-nothing-here.md' };

    const result = run(['--registry', fixture([item]), '--check-stable']);

    expect(result.status).toBe(EXIT_FAILED);
    expect(result.stderr).toContain(
      'sample-feature: the ADR link docs/adr/099-nothing-here.md names a file that does not exist'
    );
  });

  it('only prints, and exits 0, without --check-stable', () => {
    const result = run(['--registry', fixture([stableItem({ 'external-beta': none })])]);

    expect(result.status).toBe(EXIT_OK);
    expect(result.stdout).toContain('  [ ] 2. It has seen external use in a beta.');
  });
});

describe('experimental-status input errors', () => {
  it.each([
    ['an unknown argument', ['--check']],
    ['--registry with no file', ['--registry']],
    ['a registry that does not exist', ['--registry', join(tmpdir(), 'no-such-registry.json')]],
  ])('exits 2 on %s', (_label, args) => {
    expect(run(args).status).toBe(EXIT_INPUT);
  });

  it('exits 2 on a registry that is not an array', () => {
    expect(run(['--registry', fixture({ items: [] })]).status).toBe(EXIT_INPUT);
  });

  // A proposed registry is JSON: a missing field, or `"stable": "false"`,
  // which JSON reads as a truthy string, is a registry of the wrong shape.
  it.each([
    ['an empty item', [{}], 'item 1: requires must be an array of strings'],
    [
      'stable written as a string',
      [{ ...stableItem(), stable: 'false' }],
      'sample-feature: stable must be true or false',
    ],
  ])('exits 2 on %s, naming the problem, with or without --check-stable', (_label, items, line) => {
    for (const args of [[], ['--check-stable']]) {
      const result = run(['--registry', fixture(items), ...args]);
      expect(result.status).toBe(EXIT_INPUT);
      expect(result.stderr).toContain(line);
      expect(result.stdout).toBe('');
    }
  });
});
