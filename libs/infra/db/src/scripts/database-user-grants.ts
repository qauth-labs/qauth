/**
 * The operator's `db:grants` command (issue #498, ADR-019 Decisions 8 and 9):
 * give each service role's database user exactly the grants of its roles.
 *
 * The logic lives here, apart from the CLI in `grant-database-users.ts`, so it
 * can be tested without running the script. The migration runner applies the
 * same grants after its migrations (`apps/migration-runner/src/cli.ts`).
 */
import {
  applyDatabaseUserGrants,
  checkDatabaseUserGrants,
  DATABASE_ROLES,
  DATABASE_USER_ENV,
  DatabaseUserGrantsError,
  databaseUserGrantStatements,
  databaseUsersFromEnv,
  describeDatabaseUserGrants,
} from '../lib/database-users';
import { describeDatabaseError } from '../lib/migrations/runner';

export interface DatabaseUserGrantsArgs {
  /** Report how the users' privileges differ from their grants, and change nothing. */
  readonly check: boolean;
  /** Print the statements, and connect nowhere. */
  readonly print: boolean;
  readonly help: boolean;
}

export const DATABASE_USER_GRANTS_USAGE =
  'Usage: grant-database-users.ts [--check | --print]\n' +
  "       Gives each service role's database user exactly the grants of its roles,\n" +
  '       revoking whatever else it held on the tables, in one transaction. The users\n' +
  `       are named by ${DATABASE_ROLES.map((role) => DATABASE_USER_ENV[role]).join(', ')};\n` +
  '       name one user for the roles that run in one process. QAuth creates no database\n' +
  '       user and sets no password: create them first. Set DATABASE_URL to the owner of\n' +
  "       the tables, the migration runner's user. With none of the DB_USER_* variables\n" +
  '       set (a single deployment, whose one user holds every grant), it does nothing.\n' +
  '       --check  report how the users differ from their grants, and change nothing\n' +
  '       --print  print the statements, and connect nowhere\n' +
  '       Exits 0 when the grants are applied or current (or nothing is to do), 1 when\n' +
  '       they were refused or, with --check, differ, 2 on a usage error and 3 when it\n' +
  '       could not run.';

/** The exit codes. Nx turns every non-zero one into 1. */
export const DATABASE_USER_GRANTS_EXIT = Object.freeze({
  done: 0,
  refusedOrDiffer: 1,
  usage: 2,
  cannotRun: 3,
} as const);

/** Parse `process.argv`. Null on an unknown flag, or on both `--check` and `--print`. */
export function parseDatabaseUserGrantsArgs(
  argv: readonly string[]
): DatabaseUserGrantsArgs | null {
  let check = false;
  let print = false;
  let help = false;
  for (const arg of argv.slice(2)) {
    if (arg === '--check') check = true;
    else if (arg === '--print') print = true;
    else if (arg === '--help' || arg === '-h') help = true;
    else return null;
  }
  if (check && print) return null;
  return { check, print, help };
}

/** Where the command writes. */
export interface DatabaseUserGrantsIo {
  out(line: string): void;
  err(line: string): void;
}

/** Run the command; returns the exit code. */
export async function runDatabaseUserGrants(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
  io: DatabaseUserGrantsIo
): Promise<number> {
  const args = parseDatabaseUserGrantsArgs(argv);
  if (args === null) {
    io.err(DATABASE_USER_GRANTS_USAGE);
    return DATABASE_USER_GRANTS_EXIT.usage;
  }
  if (args.help) {
    io.out(DATABASE_USER_GRANTS_USAGE);
    return DATABASE_USER_GRANTS_EXIT.done;
  }

  const config = databaseUsersFromEnv(env);
  if (config.configured === 'invalid') {
    for (const problem of config.problems) io.err(problem);
    io.err('Nothing was granted.');
    return DATABASE_USER_GRANTS_EXIT.usage;
  }
  if (config.configured === false) {
    io.out(
      'None of the DB_USER_* variables is set: every role connects as the one database user, ' +
        'which owns the tables and holds every grant. Nothing to do.'
    );
    return DATABASE_USER_GRANTS_EXIT.done;
  }
  if (args.print) {
    for (const statement of databaseUserGrantStatements(config.users)) io.out(`${statement};`);
    return DATABASE_USER_GRANTS_EXIT.done;
  }

  const connectionString = env['DATABASE_URL'];
  if (!connectionString) {
    io.err('DATABASE_URL must be set in the environment, to the owner of the tables.');
    return DATABASE_USER_GRANTS_EXIT.usage;
  }

  if (args.check) {
    try {
      const problems = await checkDatabaseUserGrants({ connectionString }, config.users);
      if (problems.length > 0) {
        io.out('The database users do not hold exactly the grants of their roles:');
        for (const problem of problems) io.out(`  - ${problem}`);
        return DATABASE_USER_GRANTS_EXIT.refusedOrDiffer;
      }
      io.out('Every database user holds exactly the grants of its roles.');
      return DATABASE_USER_GRANTS_EXIT.done;
    } catch (error) {
      io.err(`Cannot check the grants: ${describeDatabaseError(error)}`);
      return DATABASE_USER_GRANTS_EXIT.cannotRun;
    }
  }

  try {
    const report = await applyDatabaseUserGrants({ connectionString }, config.users);
    io.out('Granted each database user exactly the grants of its roles:');
    for (const line of describeDatabaseUserGrants(report)) io.out(`  ${line}`);
    return DATABASE_USER_GRANTS_EXIT.done;
  } catch (error) {
    if (error instanceof DatabaseUserGrantsError) {
      io.err(error.message);
      io.err('Nothing was changed.');
      return DATABASE_USER_GRANTS_EXIT.refusedOrDiffer;
    }
    io.err(`Cannot apply the grants: ${describeDatabaseError(error)}. Nothing was changed.`);
    return DATABASE_USER_GRANTS_EXIT.cannotRun;
  }
}
