import {
  checkMigrations,
  describeDatabaseError,
  describePending,
  type MigrationEntry,
  MigrationJournalError,
  MigrationRunError,
  runMigrations,
} from '@qauth-labs/infra-db/migrations';
import {
  describeSystemClientResult,
  provisionSystemClientAt,
  SYSTEM_CLIENT_ENV,
  systemClientConfigFromEnv,
} from '@qauth-labs/infra-db/system-client';

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
  /**
   * Every migration is applied, but the system client configured by the
   * `SYSTEM_CLIENT_*` environment could not be provisioned (#631).
   */
  systemClientFailed: 4,
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
  '       when the run could not start.\n' +
  '\n' +
  "       With SYSTEM_CLIENT_REDIRECT_URI set (the developer portal's callback), a run also\n" +
  '       provisions the system client once the migrations are applied: private_key_jwt\n' +
  "       with the portal's public keys, SYSTEM_CLIENT_JWKS_URI or SYSTEM_CLIENT_JWKS (one\n" +
  '       of them), the first-party profile web_redirect and that callback. SYSTEM_CLIENT_ID\n' +
  '       (default system) and DEFAULT_REALM_NAME (default master) name the row, as on the\n' +
  '       auth server. A realm the auth server has not created yet is reported and\n' +
  '       skipped. Exits 4 when the migrations are applied but the system client could\n' +
  '       not be provisioned.';

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
  // Read before anything runs, so a half-written configuration changes
  // nothing (#631).
  const systemClient = systemClientConfigFromEnv(env);
  if (systemClient.configured === 'invalid') {
    for (const problem of systemClient.problems) io.err(`System client: ${problem}`);
    io.err(
      `Set ${SYSTEM_CLIENT_ENV.redirectUri} with exactly one of ${SYSTEM_CLIENT_ENV.jwksUri} and ` +
        `${SYSTEM_CLIENT_ENV.jwks}, or none of them. Nothing was done.`
    );
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
  } catch (error) {
    if (error instanceof MigrationRunError) {
      io.err(error.message);
      io.err('The run rolled back: no migration of this run was applied.');
      return RUNNER_EXIT.failedOrPending;
    }
    io.err(`Cannot run the migrations: ${reasonOf(error)}`);
    return RUNNER_EXIT.cannotRun;
  }

  if (systemClient.configured !== true) return RUNNER_EXIT.current;
  return provisionTheSystemClient(connectionString, systemClient.realm, systemClient.spec, io);
}

/**
 * ADR-017 phase F0 (#631): provision the developer portal's system client from
 * the `SYSTEM_CLIENT_*` environment, once the migrations are applied. A realm
 * the auth server has not created yet (a new deployment, whose auth server
 * boots after this runner) is reported and skipped: the run still succeeds,
 * and the next run provisions it.
 */
async function provisionTheSystemClient(
  connectionString: string,
  realm: string,
  spec: Parameters<typeof provisionSystemClientAt>[2],
  io: RunnerIo
): Promise<number> {
  try {
    const result = await provisionSystemClientAt(connectionString, realm, spec);
    const line = describeSystemClientResult(result);
    if (result.status === 'refused') {
      io.err(line);
      return RUNNER_EXIT.systemClientFailed;
    }
    if (result.status === 'realm_not_found') io.err(line);
    else io.out(line);
    return RUNNER_EXIT.current;
  } catch (error) {
    io.err(
      `The migrations are applied, but the system client could not be provisioned: ${describeDatabaseError(error)}`
    );
    return RUNNER_EXIT.systemClientFailed;
  }
}
