import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { Client } from 'pg';

import { type MigrationEntry, QAUTH_MIGRATIONS_FOLDER, readMigrationJournal } from './journal';
import {
  describePending,
  type MigrationQueryable,
  MIGRATIONS_TABLE,
  type MigrationStatus,
  readMigrationStatus,
} from './status';

/**
 * The migration runner's work (issue #474, ADR-018 §5): apply the pending
 * migrations under a lock, so a second runner waits and then finds nothing
 * to do. The program in `apps/migration-runner` is a thin command line over
 * this.
 *
 * It calls drizzle's own `migrate()`, which applies every pending migration
 * in ONE transaction: a failure rolls the whole run back.
 */

/**
 * The name of the Postgres advisory lock a run holds, as the key
 * `hashtextextended(name, 0)`, the form of the repository's other locks. A
 * step that must not run beside a migration, such as several nodes starting
 * together, takes the same lock.
 */
export const MIGRATION_LOCK_NAME = 'qauth:migrations';

/** How long to wait for a connection unless the caller says otherwise. */
const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

/** The name the runner's session shows in `pg_stat_activity`. */
const APPLICATION_NAME = 'qauth-migration-runner';

/**
 * Take the migration lock on a session, waiting while another session holds
 * it. `onWait` is called once, before the wait, when the lock is taken.
 */
export async function acquireMigrationLock(
  db: MigrationQueryable,
  onWait?: () => void
): Promise<void> {
  const { rows } = await db.query(
    'SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS locked',
    [MIGRATION_LOCK_NAME]
  );
  if (rows[0]?.['locked'] === true) return;
  onWait?.();
  await db.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', [MIGRATION_LOCK_NAME]);
}

/** Release the migration lock a session holds. Closing the session releases it too. */
export async function releaseMigrationLock(db: MigrationQueryable): Promise<void> {
  await db.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [MIGRATION_LOCK_NAME]);
}

/** Where to connect and what to apply. */
export interface MigrationTarget {
  /** A `postgresql://` URL. */
  readonly connectionString: string;
  /** The generated migrations folder; this source tree's unless set. */
  readonly migrationsFolder?: string;
  /** How long to wait for a connection, in milliseconds. Ten seconds unless set. */
  readonly connectTimeoutMs?: number;
}

/** Options for {@link runMigrations}. */
export interface RunMigrationsOptions extends MigrationTarget {
  /** Where progress lines go: the lock wait and each migration with its duration. */
  readonly log?: (line: string) => void;
  /** The clock in milliseconds, for a test. */
  readonly now?: () => number;
}

/** A migration a run applied. */
export interface AppliedMigration {
  readonly tag: string;
  /** How long its statements ran, in milliseconds. */
  readonly durationMs: number;
}

/** What a run did. */
export interface MigrationRunReport {
  /** The migrations the folder holds. */
  readonly known: number;
  /** The migrations applied, oldest first. Empty when the database was current. */
  readonly applied: readonly AppliedMigration[];
  /** Applied migrations newer than the folder's newest: the database is ahead. */
  readonly unknownApplied: number;
  /** Whether the run waited for another runner's lock. */
  readonly waitedForLock: boolean;
}

/** A run that failed after it connected. Nothing it began was committed. */
export class MigrationRunError extends Error {
  constructor(
    message: string,
    /** The migration that failed, when one did; not when the run failed around them. */
    readonly tag: string | undefined,
    options?: { cause?: unknown }
  ) {
    super(message, options);
    this.name = 'MigrationRunError';
  }
}

/**
 * What went wrong, in one line. drizzle wraps a driver error in one that
 * names the failed query, which for a migration is the whole statement, and
 * a refused connection to every address of a host is an `AggregateError`
 * with no message; the innermost error says why: its message and its code.
 */
export function describeDatabaseError(error: unknown): string {
  let current: unknown = error;
  while (current instanceof Error && current.cause instanceof Error) current = current.cause;
  if (current instanceof AggregateError && current.errors[0] instanceof Error) {
    current = current.errors[0];
  }
  if (!(current instanceof Error)) return String(current);
  const code = (current as { code?: unknown }).code;
  const message = current.message !== '' ? current.message : current.name;
  return typeof code === 'string' && !message.includes(code) ? `${message} (${code})` : message;
}

async function connect(target: MigrationTarget): Promise<Client> {
  const client = new Client({
    connectionString: target.connectionString,
    connectionTimeoutMillis: target.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
    application_name: APPLICATION_NAME,
  });
  try {
    await client.connect();
  } catch (error) {
    await client.end().catch(() => undefined);
    throw error;
  }
  return client;
}

/**
 * Measure a database against a migrations folder, changing nothing: no lock,
 * no migrations table created. What `--check` runs.
 */
export async function checkMigrations(
  target: MigrationTarget
): Promise<MigrationStatus & { readonly known: number }> {
  const entries = readMigrationJournal(target.migrationsFolder ?? QAUTH_MIGRATIONS_FOLDER);
  const client = await connect(target);
  try {
    return { known: entries.length, ...(await readMigrationStatus(client, entries)) };
  } finally {
    await client.end().catch(() => undefined);
  }
}

/**
 * Apply the pending migrations of a folder under the migration lock.
 *
 * A second run started beside it waits for the lock, then finds every
 * migration applied and returns an empty report.
 *
 * @throws MigrationRunError when a migration or the run's commit fails. The
 *   transaction rolled back, so the database is as it was. An error from
 *   reading the folder or from connecting is thrown as it is.
 */
export async function runMigrations(options: RunMigrationsOptions): Promise<MigrationRunReport> {
  const log = options.log ?? (() => undefined);
  const now = options.now ?? (() => performance.now());
  const migrationsFolder = options.migrationsFolder ?? QAUTH_MIGRATIONS_FOLDER;
  const entries = readMigrationJournal(migrationsFolder);

  const client = await connect(options);
  try {
    let waitedForLock = false;
    await acquireMigrationLock(client, () => {
      waitedForLock = true;
      log('Another migration runner holds the migration lock. Waiting for it to finish.');
    });
    try {
      const status = await readMigrationStatus(client, entries);
      const report = {
        known: entries.length,
        unknownApplied: status.unknownApplied,
        waitedForLock,
      };
      if (status.pending.length === 0) return { ...report, applied: [] };

      const count = status.pending.length;
      log(
        `Applying ${count} migration${count === 1 ? '' : 's'} in one transaction: ` +
          `${describePending(status.pending)}.`
      );
      const applied = await applyPending(client, migrationsFolder, status.pending, log, now);
      return { ...report, applied };
    } finally {
      // A failed migration leaves the session usable (the transaction rolled
      // back); a broken connection releases the lock as it closes.
      await releaseMigrationLock(client).catch(() => undefined);
    }
  } finally {
    await client.end().catch(() => undefined);
  }
}

/**
 * Run drizzle's `migrate()` and time each migration through its query log:
 * `migrate()` opens its transaction with `begin`, runs a migration's
 * statements, then records it with an insert whose parameters are the
 * migration's hash and generation time. The time from one record to the
 * next is the migration's.
 */
async function applyPending(
  client: Client,
  migrationsFolder: string,
  pending: readonly MigrationEntry[],
  log: (line: string) => void,
  now: () => number
): Promise<AppliedMigration[]> {
  const byWhen = new Map(pending.map((entry) => [entry.when, entry]));
  const applied: AppliedMigration[] = [];
  let began = false;
  let mark = 0;
  const logger = {
    logQuery(query: string, params: unknown[]): void {
      if (query.trim().toLowerCase() === 'begin') {
        began = true;
        mark = now();
        return;
      }
      if (!began || params.length !== 2 || !query.includes(MIGRATIONS_TABLE)) return;
      const entry = byWhen.get(Number(params[1]));
      if (entry === undefined) return;
      const at = now();
      const durationMs = at - mark;
      mark = at;
      applied.push({ tag: entry.tag, durationMs });
      log(`  ${entry.tag} ran in ${Math.round(durationMs)} ms`);
    },
  };

  try {
    await migrate(drizzle(client, { logger }), { migrationsFolder });
  } catch (error) {
    const failed = began ? pending[applied.length] : undefined;
    const reason = describeDatabaseError(error);
    const message =
      failed !== undefined
        ? `Migration ${failed.tag} failed: ${reason}`
        : began
          ? `The migration transaction failed to commit: ${reason}`
          : `The migrations could not start: ${reason}`;
    throw new MigrationRunError(message, failed?.tag, { cause: error });
  }
  return applied;
}
