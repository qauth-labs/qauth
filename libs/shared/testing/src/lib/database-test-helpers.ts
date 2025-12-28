import { PostgreSqlContainer, StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';

let container: StartedPostgreSqlContainer | null = null;
let pool: Pool | null = null;

/**
 * Start a PostgreSQL test container
 * @returns Started container and connection pool
 */
export async function startTestDatabase(): Promise<{
  container: StartedPostgreSqlContainer;
  pool: Pool;
  connectionString: string;
}> {
  if (container && pool) {
    return { container, pool, connectionString: container.getConnectionUri() };
  }

  container = await new PostgreSqlContainer('postgres:17-alpine').start();
  const connectionString = container.getConnectionUri();

  pool = new Pool({
    connectionString,
  });

  return { container, pool, connectionString };
}

/**
 * Stop the PostgreSQL test container
 */
export async function stopTestDatabase(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
  if (container) {
    await container.stop();
    container = null;
  }
}

/**
 * Get the current test database pool
 * @returns Pool instance or null if not started
 */
export function getTestDatabasePool(): Pool | null {
  return pool;
}

/**
 * Create a Drizzle instance for testing
 * @param testPool Optional pool instance (uses default if not provided)
 * @returns Drizzle instance
 */
export function createTestDrizzle(testPool?: Pool) {
  const dbPool = testPool || pool;
  if (!dbPool) {
    throw new Error('Test database not started. Call startTestDatabase() first.');
  }
  return drizzle(dbPool);
}
