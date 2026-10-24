import { describe, expect, it } from 'vitest';

import { parseRunnerArgs, RUNNER_EXIT, RUNNER_USAGE, runRunner } from './cli';

/**
 * The runner's command line without a database (issue #474). The container
 * suite, `runner.integration.test.ts`, runs the built program against one.
 */

const argv = (...args: string[]) => ['node', 'main.js', ...args];

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { out: (l: string) => out.push(l), err: (l: string) => err.push(l) } };
}

describe('parseRunnerArgs', () => {
  it('runs with no arguments', () => {
    expect(parseRunnerArgs(argv())).toEqual({ check: false, help: false });
  });

  it('reads --check, --help and --migrations-folder', () => {
    expect(parseRunnerArgs(argv('--check', '--migrations-folder=/m'))).toEqual({
      check: true,
      help: false,
      migrationsFolder: '/m',
    });
    expect(parseRunnerArgs(argv('-h'))?.help).toBe(true);
  });

  it('refuses an unknown flag and an empty folder', () => {
    expect(parseRunnerArgs(argv('--force'))).toBeNull();
    expect(parseRunnerArgs(argv('--migrations-folder='))).toBeNull();
    expect(parseRunnerArgs(argv('check'))).toBeNull();
  });
});

describe('runRunner without a database', () => {
  it('prints the usage and exits 2 on an unknown flag', async () => {
    const { err, io } = capture();
    await expect(runRunner(argv('--dry-run'), {}, '/m', io)).resolves.toBe(RUNNER_EXIT.usage);
    expect(err).toEqual([RUNNER_USAGE]);
  });

  it('prints the usage and exits 0 for --help', async () => {
    const { out, io } = capture();
    await expect(runRunner(argv('--help'), {}, '/m', io)).resolves.toBe(RUNNER_EXIT.current);
    expect(out).toEqual([RUNNER_USAGE]);
  });

  it('exits 2 without DATABASE_URL, in both modes', async () => {
    for (const args of [argv(), argv('--check')]) {
      const { err, io } = capture();
      await expect(runRunner(args, {}, '/m', io)).resolves.toBe(RUNNER_EXIT.usage);
      expect(err).toEqual(['DATABASE_URL must be set in the environment.']);
    }
  });

  it('exits 3 when the migrations folder cannot be read, naming it', async () => {
    const { err, io } = capture();
    const env = { DATABASE_URL: 'postgresql://u:p@127.0.0.1:1/db' };
    await expect(runRunner(argv(), env, '/nonexistent/drizzle', io)).resolves.toBe(
      RUNNER_EXIT.cannotRun
    );
    expect(err).toEqual([
      'Cannot run the migrations: Cannot read the migration journal ' +
        '/nonexistent/drizzle/meta/_journal.json: ' +
        "ENOENT: no such file or directory, open '/nonexistent/drizzle/meta/_journal.json'",
    ]);
  });
});
