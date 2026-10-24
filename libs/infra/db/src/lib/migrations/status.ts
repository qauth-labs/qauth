import type { MigrationEntry } from './journal';

/**
 * How far a database is from a migration list (issue #474), by the rule
 * drizzle's migrator applies: a migration is pending when it is newer than
 * the newest `created_at` in `drizzle.__drizzle_migrations`. So `--check`,
 * the auth server's boot check and the runner agree on what is pending.
 */

/** The schema and table drizzle records applied migrations in. */
export const MIGRATIONS_SCHEMA = 'drizzle';
export const MIGRATIONS_TABLE = '__drizzle_migrations';

/** Anything that runs a query: a `pg` client or pool. */
export interface MigrationQueryable {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

/** A database measured against a migration list. */
export interface MigrationStatus {
  /** The migrations the list holds that the database lacks, oldest first. */
  readonly pending: readonly MigrationEntry[];
  /**
   * Applied migrations newer than the list's newest: the database is ahead,
   * as it is for old code during a rolling upgrade.
   */
  readonly unknownApplied: number;
}

/**
 * Measure a database against a migration list. It only reads: a database
 * the runner never touched has no migrations table, and all are pending.
 */
export async function readMigrationStatus(
  db: MigrationQueryable,
  entries: readonly MigrationEntry[]
): Promise<MigrationStatus> {
  const { rows: presence } = await db.query(
    `SELECT to_regclass('"${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}"') IS NOT NULL AS present`
  );
  if (presence[0]?.['present'] !== true) return { pending: [...entries], unknownApplied: 0 };

  const newest = entries.reduce((max, entry) => Math.max(max, entry.when), -1);
  // The newest row the way drizzle's migrator reads it, `ORDER BY created_at
  // DESC LIMIT 1`: a NULL sorts first there, and drizzle then counts it as 0.
  const { rows } = await db.query(
    `SELECT
       (SELECT created_at FROM "${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}"
         ORDER BY created_at DESC LIMIT 1) AS last_applied,
       (SELECT count(*) FROM "${MIGRATIONS_SCHEMA}"."${MIGRATIONS_TABLE}"
         WHERE created_at > $1)::int AS unknown_applied`,
    [newest]
  );
  const lastApplied = Number(rows[0]?.['last_applied'] ?? 0);
  return {
    pending: entries.filter((entry) => lastApplied < entry.when),
    unknownApplied: Number(rows[0]?.['unknown_applied'] ?? 0),
  };
}

/** How many pending migrations a message names before it counts the rest. */
const NAMED_PENDING = 10;

/** The pending migrations, by name, for a log line or an error. */
export function describePending(pending: readonly MigrationEntry[]): string {
  const named = pending
    .slice(0, NAMED_PENDING)
    .map((entry) => entry.tag)
    .join(', ');
  const rest = pending.length - NAMED_PENDING;
  return rest > 0 ? `${named} and ${rest} more` : named;
}

/** The database still lacks migrations this code needs once the wait is over. */
export class MigrationsPendingError extends Error {
  constructor(
    readonly pending: readonly MigrationEntry[],
    waitMs: number
  ) {
    super(
      `The database lacks ${pending.length} migration${pending.length === 1 ? '' : 's'} ` +
        `this release needs: ${describePending(pending)}. Waited ${Number((waitMs / 1000).toFixed(1))} s ` +
        'for the migration runner. Run it against this database, then start the server again.'
    );
    this.name = 'MigrationsPendingError';
  }
}

/** Options for {@link waitForMigrations}. */
export interface WaitForMigrationsOptions {
  /** How long to wait for the pending migrations, in milliseconds. `0` checks once. */
  readonly waitMs: number;
  /** How often to look again, in milliseconds. One second unless set. */
  readonly pollMs?: number;
  /** Called once, the first time the database is found behind. */
  readonly onBehind?: (status: MigrationStatus) => void;
  /** The clock, for a test. */
  readonly now?: () => number;
  /** The wait between two looks, for a test. */
  readonly sleep?: (ms: number) => Promise<void>;
}

/**
 * Wait until a database has every migration of a list, for at most
 * `waitMs`, as a server does at boot while a migration runner may still be
 * running. A database ahead of the list is current: during a rolling upgrade
 * the old code runs on the new schema for a while.
 *
 * @throws MigrationsPendingError when migrations are still pending at the end
 *   of the wait. A failing query rejects at once: an unreachable database is
 *   not one that is behind.
 */
export async function waitForMigrations(
  db: MigrationQueryable,
  entries: readonly MigrationEntry[],
  options: WaitForMigrationsOptions
): Promise<MigrationStatus> {
  const now = options.now ?? Date.now;
  const sleep =
    options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const pollMs = options.pollMs ?? 1000;
  const deadline = now() + options.waitMs;
  let reported = false;
  for (;;) {
    const status = await readMigrationStatus(db, entries);
    if (status.pending.length === 0) return status;
    if (!reported) {
      options.onBehind?.(status);
      reported = true;
    }
    const left = deadline - now();
    if (left <= 0) throw new MigrationsPendingError(status.pending, options.waitMs);
    await sleep(Math.min(pollMs, left));
  }
}
