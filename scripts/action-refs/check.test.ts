/**
 * Guard for `scripts/action-refs/check.mjs`, the CLI of the pinned-reference
 * rule (#796). It is run the way CI runs it, spawned as a child process, on a
 * fixture directory written for each case. The assertions are on exit codes
 * and on what it prints; the rule itself is unit-tested in `lib.test.ts`.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'check.mjs');

const EXIT_OK = 0;
const EXIT_REFUSED = 1;
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

/** Write `files` (name to contents) into a fresh directory and return it. */
function fixture(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'action-refs-'));
  workspaces.push(dir);
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  return dir;
}

const pinned = ['jobs:', '  build:', '    steps:', '      - uses: actions/checkout@v7', ''];

describe('action-refs on a workflow directory', () => {
  it('passes workflows whose every uses: is pinned', () => {
    const result = run([fixture({ 'a.yml': pinned.join('\n'), 'b.yaml': pinned.join('\n') })]);

    expect(result.stderr).toBe('');
    expect(result.status).toBe(EXIT_OK);
    expect(result.stdout).toBe('action-refs: 2 references in 2 workflow files, all pinned\n');
  });

  // The acceptance criterion of #796: a pull request that adds a `uses:` at a
  // branch name fails, with an annotation on the line that added it.
  it('fails a workflow that adds a uses: at a branch, and names its file and line', () => {
    const text = [...pinned.slice(0, -1), '      - uses: some-org/some-action@main', ''];

    const result = run([fixture({ 'ci.yml': text.join('\n') })]);

    expect(result.status).toBe(EXIT_REFUSED);
    expect(result.stderr).toMatch(
      /^::error file=.*ci\.yml,line=5::uses: some-org\/some-action@main names "main"/m
    );
    expect(result.stderr).toContain('action-refs: 1 of 2 references refused');
  });

  it('reads only .yml and .yaml files', () => {
    const dir = fixture({ 'a.yml': pinned.join('\n'), 'notes.txt': '- uses: x@main\n' });

    expect(run([dir]).status).toBe(EXIT_OK);
  });
});

describe('action-refs input errors', () => {
  it.each([
    ['no directory', []],
    ['an option', ['--all']],
    ['two directories', ['one', 'two']],
    ['a directory that does not exist', [join(tmpdir(), 'action-refs-no-such-directory')]],
  ])('exits 2 on %s', (_label, args) => {
    expect(run(args).status).toBe(EXIT_INPUT);
  });

  it('exits 2 on a directory with no workflow file', () => {
    const result = run([fixture({ 'README.md': '# none here\n' })]);

    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toContain('holds no workflow file');
  });
});
