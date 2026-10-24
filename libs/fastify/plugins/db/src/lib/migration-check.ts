import {
  createDatabase,
  describePending,
  QAUTH_MIGRATIONS_FOLDER,
  readMigrationJournal,
  waitForMigrations,
} from '@qauth-labs/infra-db';
import type { FastifyBaseLogger } from 'fastify';

/** Options for {@link awaitDatabaseMigrations}. */
export interface DatabaseMigrationCheckOptions {
  /** The database the server is about to use. */
  readonly connectionString: string;
  /** How long to wait for missing migrations, in milliseconds. `0` checks once. */
  readonly waitMs: number;
  /** How long to wait for a connection, in milliseconds. */
  readonly connectTimeoutMs?: number;
  /** The server's logger. */
  readonly log: FastifyBaseLogger;
  /** The migrations this release needs; the database library's own unless set. */
  readonly migrationsFolder?: string;
  /** How often to look again while waiting, in milliseconds. One second unless set. */
  readonly pollMs?: number;
}

/**
 * The auth server's boot check (issue #474, ADR-018 §5): wait until the
 * database has every migration of this release, then return.
 *
 * Behind, the server waits up to `waitMs` for the migration runner, which a
 * deployment may start beside it, and then throws an error naming the
 * missing migrations, so `main.ts` exits non-zero. Ahead, it logs a warning
 * and returns: during a rolling upgrade the old release runs on the new
 * schema for a while.
 *
 * Not an `onReady` hook: Fastify fails a hook that runs longer than its
 * plugin timeout, 10 seconds by default, and the wait is longer. It uses a
 * pool of its own with one connection and closes it before it returns.
 *
 * @throws MigrationsPendingError when migrations are still missing after
 *   the wait. Any other error is the database's, at once.
 */
export async function awaitDatabaseMigrations(
  options: DatabaseMigrationCheckOptions
): Promise<void> {
  const entries = readMigrationJournal(options.migrationsFolder ?? QAUTH_MIGRATIONS_FOLDER);
  // One connection, re-opened on the next look if the database drops it
  // while the check waits.
  const database = createDatabase({
    connectionString: options.connectionString,
    pool: {
      max: 1,
      min: 0,
      ...(options.connectTimeoutMs === undefined
        ? {}
        : { connectionTimeoutMillis: options.connectTimeoutMs }),
    },
    logger: options.log,
  });

  let waited = false;
  try {
    const status = await waitForMigrations(database.pool, entries, {
      waitMs: options.waitMs,
      ...(options.pollMs === undefined ? {} : { pollMs: options.pollMs }),
      onBehind: ({ pending }) => {
        waited = true;
        options.log.warn(
          { pendingMigrations: pending.map((entry) => entry.tag), waitMs: options.waitMs },
          `The database lacks ${pending.length} migration${pending.length === 1 ? '' : 's'} ` +
            `this release needs: ${describePending(pending)}. Waiting up to ` +
            `${options.waitMs} ms for the migration runner.`
        );
      },
    });
    if (waited) options.log.info('The database now has every migration this release needs.');
    if (status.unknownApplied > 0) {
      options.log.warn(
        { newerMigrations: status.unknownApplied },
        `The database has ${status.unknownApplied} migration` +
          `${status.unknownApplied === 1 ? '' : 's'} newer than this release, ` +
          'from a newer one. Starting anyway, as during a rolling upgrade.'
      );
    }
  } finally {
    await database.close();
  }
}
