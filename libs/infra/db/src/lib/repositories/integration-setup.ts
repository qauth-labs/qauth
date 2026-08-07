import {
  applyQauthMigrations,
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
  /** Connection string of the throwaway container. */
  connectionString: string;
  /**
   * Truncate every domain table (FK-safe via CASCADE) so each test starts from
   * a clean slate without paying the container-startup cost per test.
   */
  reset(): Promise<void>;
  /** Close the pool and stop+remove the container. */
  teardown(): Promise<void>;
}

/**
 * Spin up a Postgres 18 container, apply all Drizzle migrations, and return a
 * connected {@link DatabaseInstance}. Intended for a `beforeAll`; pair with
 * `reset()` in `beforeEach` and `teardown()` in `afterAll`.
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
export async function setupIntegrationDb(): Promise<IntegrationDb> {
  const container: StartedPostgres = await startPostgresContainer();

  // Apply the real generated migrations — this is the whole point: we exercise
  // the actual DDL (constraints, partial unique indexes, uuidv7 defaults), not
  // a hand-rolled schema.
  await applyQauthMigrations(container.connectionString);

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
