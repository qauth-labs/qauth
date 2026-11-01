import {
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';

import { createDatabase, type DatabaseInstance } from '../db';

/**
 * A fully migrated, container-backed database ready for repository tests.
 */
export interface IntegrationDb {
  /** The QAuth database instance ({@link createDatabase}). */
  database: DatabaseInstance;
  /** Connection string of the suite's database. */
  connectionString: string;
  /**
   * Truncate every domain table (FK-safe via CASCADE) so each test starts from
   * a clean slate without paying the database-setup cost per test.
   */
  reset(): Promise<void>;
  /** Close the pool and drop the database (or stop the private container). */
  teardown(): Promise<void>;
}

/** What {@link setupIntegrationDb} gives a suite. */
export interface IntegrationDbOptions {
  /**
   * A Postgres container of the suite's own instead of a database on a
   * shared server, for a suite that reaches past its database: it creates
   * roles, which are cluster-wide and outlive the database, so on a shared
   * server two suites would meet over the same role name. See
   * `StartPostgresOptions`.
   */
  readonly privateContainer?: boolean;
}

/**
 * A Postgres 18 database with all Drizzle migrations applied, and a connected
 * {@link DatabaseInstance} on it. Intended for a `beforeAll`; pair with
 * `reset()` in `beforeEach` and `teardown()` in `afterAll`.
 *
 * The database is the suite's own on a server the integration global setup
 * started, a copy of the template it migrated there, unless
 * `privateContainer` asks for a container of the suite's own.
 *
 * The migration step and the truncate list live in `@qauth-labs/shared-testing`
 * (#240) rather than here: `apps/auth-server`'s wallet E2E needs the same
 * migrated schema and, being `scope:app`, may not import this library. One
 * implementation is the point — a second copy would let the two suites drift
 * onto different DDL, which is the one thing container-backed tests exist to
 * rule out.
 *
 * Requires Docker. Suites should guard with `requireDockerOrSkip()` from
 * `@qauth-labs/shared-testing`, which skips locally but fails on CI so a
 * daemon-less runner cannot turn the suite into a green no-op.
 */
export async function setupIntegrationDb(
  options: IntegrationDbOptions = {}
): Promise<IntegrationDb> {
  // The real generated migrations, applied — this is the whole point: we
  // exercise the actual DDL (constraints, partial unique indexes, uuidv7
  // defaults), not a hand-rolled schema.
  const container: StartedPostgres = await startPostgresContainer({
    schema: 'migrated',
    privateContainer: options.privateContainer,
  });

  const database = createDatabase({ connectionString: container.connectionString });

  return {
    database,
    connectionString: container.connectionString,

    async reset(): Promise<void> {
      await database.pool.query(truncateDomainTablesStatement());
    },

    async teardown(): Promise<void> {
      await database.close();
      await container.stop();
    },
  };
}
