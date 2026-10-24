import {
  checkMigrations,
  describeDatabaseError,
  describePending,
  type MigrationEntry,
  MigrationJournalError,
  MigrationRunError,
  runMigrations,
} from '@qauth-labs/infra-db/migrations';

/**
 * The migration runner's command line (issue #474, ADR-018 §5): parse the
 * arguments, run or check, print what happened and choose the exit code.
 * `main.ts` only wires it to the process.
 */

/** The runner's exit codes, so a deployment tells a failed run from one that could not start. */
export const RUNNER_EXIT = Object.freeze({
  /** Every migration is applied: this run applied the pending ones, or none were. */
  current: 0,
  /** A migration failed and the run rolled back; with `--check`, migrations are pending. */
  failedOrPending: 1,
  /** The arguments are wrong, or `DATABASE_URL` is not set; nothing was read. */
  usage: 2,
  /** The run could not start: the database unreachable, or the migrations folder unreadable. */
  cannotRun: 3,
} as const);

export const RUNNER_USAGE =
  'Usage: node main.js [--check] [--migrations-folder=<dir>]\n' +
  '       Applies the pending QAuth database migrations to DATABASE_URL, under a lock:\n' +
  '       a second runner waits, then finds nothing to do.\n' +
  '       --check                    report the pending migrations and change nothing\n' +
  '       --migrations-folder=<dir>  apply the migrations of <dir> instead of the ones\n' +
  '                                  shipped beside this program\n' +
  '       Exits 0 when the database is current, 1 when a migration failed (the run rolled\n' +
  '       back) or, with --check, when migrations are pending, 2 on a usage error and 3\n' +
  '       when the run could not start.';

export interface RunnerArgs {
  readonly check: boolean;
  readonly help: boolean;
  readonly migrationsFolder?: string;
}

/** Parse `process.argv`. Null on an unknown or malformed flag. */
export function parseRunnerArgs(argv: readonly string[]): RunnerArgs | null {
  let check = false;
  let help = false;
  let migrationsFolder: string | undefined;
  for (const arg of argv.slice(2)) {
    if (arg === '--check') check = true;
    else if (arg === '--help' || arg === '-h') help = true;
    else if (arg.startsWith('--migrations-folder=')) {
      migrationsFolder = arg.slice('--migrations-folder='.length);
      if (migrationsFolder === '') return null;
    } else return null;
  }
  return { check, help, ...(migrationsFolder === undefined ? {} : { migrationsFolder }) };
}

/** Where the runner writes. */
export interface RunnerIo {
  out(line: string): void;
  err(line: string): void;
}

/** Why the run or the check could not start, in one line. */
function reasonOf(error: unknown): string {
  return error instanceof MigrationJournalError ? error.message : describeDatabaseError(error);
}

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

function aheadNote(unknownApplied: number): string {
  return unknownApplied === 0
    ? ''
    : ` The database also has ${plural(unknownApplied, 'migration')} newer than this ` +
        "runner's, from a newer release; nothing was done about them.";
}

function pendingLine(pending: readonly MigrationEntry[], known: number): string {
  return `The database lacks ${pending.length} of ${plural(known, 'migration')}: ${describePending(pending)}.`;
}

/**
 * Run the command: apply the pending migrations, or with `--check` report
 * them. Returns the exit code.
 */
export async function runRunner(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  defaultMigrationsFolder: string,
  io: RunnerIo
): Promise<number> {
  const args = parseRunnerArgs(argv);
  if (args === null) {
    io.err(RUNNER_USAGE);
    return RUNNER_EXIT.usage;
  }
  if (args.help) {
    io.out(RUNNER_USAGE);
    return RUNNER_EXIT.current;
  }
  const connectionString = env['DATABASE_URL'];
  if (!connectionString) {
    io.err('DATABASE_URL must be set in the environment.');
    return RUNNER_EXIT.usage;
  }
  const target = {
    connectionString,
    migrationsFolder: args.migrationsFolder ?? defaultMigrationsFolder,
  };

  if (args.check) {
    try {
      const status = await checkMigrations(target);
      if (status.pending.length > 0) {
        io.out(
          `${pendingLine(status.pending, status.known)} ` +
            'Run the migration runner without --check to apply them.'
        );
        return RUNNER_EXIT.failedOrPending;
      }
      io.out(
        `The database is current: all ${plural(status.known, 'migration')} are applied.` +
          aheadNote(status.unknownApplied)
      );
      return RUNNER_EXIT.current;
    } catch (error) {
      io.err(`Cannot check the migrations: ${reasonOf(error)}`);
      return RUNNER_EXIT.cannotRun;
    }
  }

  const started = performance.now();
  try {
    const report = await runMigrations({ ...target, log: io.out });
    if (report.applied.length === 0) {
      io.out(
        `The database is current: all ${plural(report.known, 'migration')} are applied. ` +
          'Nothing to do.' +
          aheadNote(report.unknownApplied)
      );
    } else {
      io.out(
        `Applied ${plural(report.applied.length, 'migration')} in ` +
          `${Math.round(performance.now() - started)} ms. The database is current.` +
          aheadNote(report.unknownApplied)
      );
    }
    return RUNNER_EXIT.current;
  } catch (error) {
    if (error instanceof MigrationRunError) {
      io.err(error.message);
      io.err('The run rolled back: no migration of this run was applied.');
      return RUNNER_EXIT.failedOrPending;
    }
    io.err(`Cannot run the migrations: ${reasonOf(error)}`);
    return RUNNER_EXIT.cannotRun;
  }
}
