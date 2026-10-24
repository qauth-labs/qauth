import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { readUpgradeConfig, serverPath, UpgradeConfigError } from './config';

const PROJECT_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** A complete environment; each test removes or changes what it is about. */
const COMPLETE = {
  QAUTH_UPGRADE_ALLOW_WRITES: '1',
  QAUTH_BASE_URL: 'http://localhost:3000',
  QAUTH_UPGRADE_DATABASE_URL: 'postgresql://qauth:secret@localhost:5432/qauth',
  QAUTH_UPGRADE_STATE: '/tmp/upgrade-test/state.json',
  QAUTH_UPGRADE_MAIL_URL: 'http://localhost:8025',
} as const;

function without(name: keyof typeof COMPLETE): Record<string, string> {
  const env: Record<string, string> = { ...COMPLETE };
  delete env[name];
  return env;
}

describe('upgrade-test configuration', () => {
  it('reads the base URL, the database, the state file and the mail API', () => {
    expect(readUpgradeConfig(COMPLETE)).toEqual({
      baseUrl: 'http://localhost:3000',
      databaseUrl: 'postgresql://qauth:secret@localhost:5432/qauth',
      statePath: '/tmp/upgrade-test/state.json',
      mailUrl: 'http://localhost:8025',
    });
  });

  describe('refuses to start without QAUTH_UPGRADE_ALLOW_WRITES=1', () => {
    it.each([
      ['unset', undefined],
      ['empty', ''],
      ['"true"', 'true'],
      ['" 1"', ' 1'],
    ])('when it is %s', (_label, value) => {
      const env = { ...COMPLETE, QAUTH_UPGRADE_ALLOW_WRITES: value };
      expect(() => readUpgradeConfig(env)).toThrow(UpgradeConfigError);
      expect(() => readUpgradeConfig(env)).toThrow(/QAUTH_UPGRADE_ALLOW_WRITES=1/);
    });

    it('before it reads anything else', () => {
      expect(() => readUpgradeConfig({})).toThrow(/QAUTH_UPGRADE_ALLOW_WRITES=1/);
    });

    it('as a whole run: the upgrade config exits non-zero and runs no step', () => {
      // Observed the way CI and a developer would meet it. Every URL points at
      // a closed port, so without the guard the steps would still fail, but on
      // connection errors from tests that ran; the assertions tell them apart.
      const require = createRequire(import.meta.url);
      const vitest = join(dirname(require.resolve('vitest/package.json')), 'vitest.mjs');
      const env: NodeJS.ProcessEnv = { ...process.env, ...without('QAUTH_UPGRADE_ALLOW_WRITES') };
      env['QAUTH_BASE_URL'] = 'http://127.0.0.1:9';
      env['QAUTH_UPGRADE_DATABASE_URL'] = 'postgresql://qauth:x@127.0.0.1:9/qauth';
      env['QAUTH_UPGRADE_MAIL_URL'] = 'http://127.0.0.1:9';
      delete env['QAUTH_UPGRADE_ALLOW_WRITES'];
      delete env['VITEST'];
      delete env['VITEST_POOL_ID'];
      delete env['VITEST_WORKER_ID'];

      const run = spawnSync(
        process.execPath,
        [vitest, 'run', '--config', 'vitest.upgrade.config.ts', '--project', 'smoke'],
        { cwd: PROJECT_ROOT, env, encoding: 'utf8', timeout: 60_000 }
      );
      const output = `${run.stdout}\n${run.stderr}`;

      expect(run.status, output).not.toBe(0);
      expect(output).toContain('upgrade-test: refusing to start');
      expect(output).not.toMatch(/Tests\s+\d+\s+(passed|failed)/);
    }, 60_000);
  });

  it.each([
    'QAUTH_BASE_URL',
    'QAUTH_UPGRADE_DATABASE_URL',
    'QAUTH_UPGRADE_STATE',
    'QAUTH_UPGRADE_MAIL_URL',
  ] as const)('refuses to start without %s', (name) => {
    expect(() => readUpgradeConfig(without(name))).toThrow(`${name} is not set`);
  });

  it.each([
    ['a relative URL', 'localhost:3000'],
    ['a non-http scheme', 'ftp://localhost:3000'],
    ['a query', 'http://localhost:3000?tenant=a'],
    ['a fragment', 'http://localhost:3000#top'],
  ])('refuses a base URL with %s', (_label, value) => {
    expect(() => readUpgradeConfig({ ...COMPLETE, QAUTH_BASE_URL: value })).toThrow(
      UpgradeConfigError
    );
  });

  it('refuses a database URL that is not postgresql://', () => {
    expect(() =>
      readUpgradeConfig({ ...COMPLETE, QAUTH_UPGRADE_DATABASE_URL: 'mysql://localhost/qauth' })
    ).toThrow(/postgresql:\/\//);
  });

  it('refuses a mail URL that is not http(s)', () => {
    expect(() =>
      readUpgradeConfig({ ...COMPLETE, QAUTH_UPGRADE_MAIL_URL: 'smtp://mail:1025' })
    ).toThrow(/QAUTH_UPGRADE_MAIL_URL/);
  });
});

describe('serverPath', () => {
  it('appends a path to a base with or without a terminating slash', () => {
    expect(serverPath('http://localhost:3000', '/health')).toBe('http://localhost:3000/health');
    expect(serverPath('http://localhost:3000/', '/health')).toBe('http://localhost:3000/health');
  });

  it('refuses a relative path', () => {
    expect(() => serverPath('http://localhost:3000', 'health')).toThrow(/absolute path/);
  });
});
