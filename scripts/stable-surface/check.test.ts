/**
 * Guard for `scripts/stable-surface/check.mjs`, the CLI over `lib.mjs`
 * (#451): its arguments, its exit codes and its job summary. Run as CI runs
 * it, as a child process, against a copy of the second-surface fixture
 * repository. Only the steps that need no network run here; the break step
 * downloads oasdiff, and is exercised by the stable-surface CI job.
 */
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'check.mjs');

const workspaces: string[] = [];
afterAll(() => {
  for (const dir of workspaces) rmSync(dir, { recursive: true, force: true });
});

function fixtureRepo() {
  const root = mkdtempSync(join(tmpdir(), 'stable-surface-cli-'));
  workspaces.push(root);
  cpSync(join(HERE, '__fixtures__', 'second-surface'), root, { recursive: true });
  expect(spawnSync('node', ['generate.mjs'], { cwd: root }).status).toBe(0);
  return root;
}

function check(...args: string[]) {
  const env = { ...process.env };
  delete env.GITHUB_STEP_SUMMARY;
  delete env.GITHUB_ACTIONS;
  const result = spawnSync('node', [SCRIPT, ...args], { encoding: 'utf8', env });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

describe('stable-surface check CLI', () => {
  it('prints its usage', () => {
    const { status, stdout } = check('--help');
    expect(status).toBe(0);
    expect(stdout).toContain('--only <steps>');
  });

  it.each([
    [['--bogus'], 'unknown argument: --bogus'],
    [['--only', 'drift,lint'], 'unknown step "lint"'],
    [['--baseline'], '--baseline requires a value'],
  ])('exits 2 on bad arguments: %j', (args, message) => {
    const { status, stderr } = check(...args);
    expect(status).toBe(2);
    expect(stderr).toContain(message);
  });

  it('exits 0 when the surfaces match their generators and every operation is tagged', () => {
    const root = fixtureRepo();
    const summary = join(root, 'summary.md');
    const { status, stdout } = check('--root', root, '--only', 'drift,tags', '--summary', summary);
    expect(status).toBe(0);
    expect(stdout).toContain('stable-surface: running node generate.mjs');
    expect(readFileSync(summary, 'utf8')).toContain(
      '| events | `stable-surface/events.schema.json` | stable | none | n/a | not run |'
    );
  });

  it('exits 1 on drift and on a missing stability tag', () => {
    const root = fixtureRepo();
    const openapi = join(root, 'source', 'openapi.json');
    const doc = JSON.parse(readFileSync(openapi, 'utf8'));
    delete doc.paths['/things'].get['x-qauth-stability'];
    writeFileSync(openapi, JSON.stringify(doc));
    const { status, stdout } = check('--root', root, '--only', 'drift,tags', '--no-summary');
    expect(status).toBe(1);
    expect(stdout).toContain(
      'error: stable-surface/openapi.json: stable-surface/openapi.json differs from what'
    );
    expect(stdout).toContain(
      'error: stable-surface/openapi.json: GET /things has no x-qauth-stability'
    );
  });

  it('exits 2 on an invalid registry', () => {
    const root = fixtureRepo();
    writeFileSync(join(root, 'stable-surface', 'surfaces.json'), '{"surfaces": [{"name": "x"}]}');
    const { status, stderr } = check('--root', root, '--only', 'tags', '--no-summary');
    expect(status).toBe(2);
    expect(stderr).toContain('stable-surface/surfaces.json is invalid');
  });
});
