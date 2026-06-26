import path from 'node:path';

import { type StartedPostgres, startPostgresContainer } from '@qauth-labs/shared-testing';
import { migrate } from 'drizzle-orm/node-postgres/migrator';

import { createDatabase, type DatabaseInstance } from '../db';

/**
 * Absolute path to the generated Drizzle migrations folder
 * (`libs/infra/db/drizzle`).
 *
 * The integration target / `test:integration` script run vitest from the
 * workspace root (`cwd: {workspaceRoot}`), so this resolves correctly under
 * both the CommonJS typecheck and the ESM vitest runtime — without needing
 * `import.meta.url` (unavailable under the lib's `module: commonjs` tsconfig).
 */
const MIGRATIONS_FOLDER = path.resolve(process.cwd(), 'libs/infra/db/drizzle');

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

/** Tables truncated by {@link IntegrationDb.reset}; child-first is irrelevant with CASCADE. */
const DOMAIN_TABLES = [
  'api_keys',
  'audit_logs',
  'oauth_consents',
  'refresh_tokens',
  'authorization_codes',
  'email_verification_tokens',
  'oauth_clients',
  'users',
  'realms',
];

/**
 * Spin up a Postgres 18 container, apply all Drizzle migrations, and return a
 * connected {@link DatabaseInstance}. Intended for a `beforeAll`; pair with
 * `reset()` in `beforeEach` and `teardown()` in `afterAll`.
 *
 * Requires Docker. Suites should guard with `isDockerAvailable()` from
 * `@qauth-labs/shared-testing` and `describe.skip` when it is unavailable.
 */
export async function setupIntegrationDb(): Promise<IntegrationDb> {
  const container: StartedPostgres = await startPostgresContainer();
  const database = createDatabase({ connectionString: container.connectionString });

  // Apply the real generated migrations — this is the whole point: we exercise
  // the actual DDL (constraints, partial unique indexes, uuidv7 defaults), not
  // a hand-rolled schema.
  await migrate(database.db, { migrationsFolder: MIGRATIONS_FOLDER });

  return {
    database,
    connectionString: container.connectionString,

    async reset(): Promise<void> {
      await database.pool.query(
        `TRUNCATE TABLE ${DOMAIN_TABLES.map((t) => `"${t}"`).join(', ')} RESTART IDENTITY CASCADE`
      );
    },

    async teardown(): Promise<void> {
      await database.close();
      await container.stop();
    },
  };
}
