/**
 * Guard for `scripts/dependency-audit/summary.mjs`, the CLI that prints the
 * dependency audit's job summary (#795). It is run the way CI runs it,
 * spawned as a child process, on a report file written for each case. The
 * assertions are on exit codes and on what it prints; the parsing and the
 * rendering are unit-tested in `lib.test.ts`.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'summary.mjs');

const EXIT_OK = 0;
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

/** Write `text` to a report file in a fresh directory and return its path. */
function reportFile(text: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'dependency-audit-'));
  workspaces.push(dir);
  const path = join(dir, 'audit.json');
  writeFileSync(path, text);
  return path;
}

const HIGH = {
  findings: [{ version: '1.16.1', paths: ['.>@nx/web>http-server>http-proxy>follow-redirects'] }],
  title: 'follow-redirects: custom credentials can follow redirects',
  module_name: 'follow-redirects',
  vulnerable_versions: '>=1.16.0 <=1.16.1',
  patched_versions: '>=1.16.2',
  severity: 'high',
  github_advisory_id: 'GHSA-mrwp-f3q8-3g9p',
  url: 'https://example.test/advisories/GHSA-mrwp-f3q8-3g9p',
};

describe('dependency-audit summary on a report file', () => {
  it('prints the summary and exits 0 when the report holds a high advisory', () => {
    const result = run([reportFile(JSON.stringify({ advisories: { 1: HIGH }, metadata: {} }))]);

    expect(result.stderr).toBe('');
    expect(result.status).toBe(EXIT_OK);
    expect(result.stdout).toMatch(/^## Dependency audit\n/);
    expect(result.stdout).toContain('| high | `follow-redirects` | `1.16.1` | `>=1.16.2` |');
  });

  it('prints that there is no advisory when the report holds none', () => {
    const result = run([reportFile(JSON.stringify({ advisories: {}, metadata: {} }))]);

    expect(result.status).toBe(EXIT_OK);
    expect(result.stdout).toContain('`pnpm audit` reports no advisory.');
  });

  it('exits 2 and says so in the summary when the report is a registry error', () => {
    const path = reportFile(JSON.stringify({ error: { code: 'ERR_PNPM_AUDIT_BAD_RESPONSE' } }));

    const result = run([path]);

    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toBe(`dependency-audit: ${path} is an error, not an audit report\n`);
    expect(result.stdout).toBe(
      [
        '## Dependency audit',
        '',
        "The report of `pnpm audit --json` could not be read: it is an error, not an audit report. The audit step's own log says why.",
        '',
      ].join('\n')
    );
  });

  it('exits 2 when the report is empty, as when pnpm printed nothing', () => {
    const result = run([reportFile('')]);

    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stdout).toContain('could not be read: it is not JSON.');
  });

  it('exits 2 when the file does not exist', () => {
    const path = join(tmpdir(), 'dependency-audit-missing', 'audit.json');

    const result = run([path]);

    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stderr).toBe(`dependency-audit: ${path} cannot be read (ENOENT)\n`);
  });

  it.each([
    ['no argument', []],
    ['two arguments', ['a.json', 'b.json']],
    ['an option', ['--json']],
  ])('exits 2 with the usage on %s', (_label, args) => {
    const result = run(args);

    expect(result.status).toBe(EXIT_INPUT);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe(
      'dependency-audit: usage: node scripts/dependency-audit/summary.mjs <report.json>\n'
    );
  });
});
