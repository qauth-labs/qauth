import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';

import type {
  DatabaseConfig,
  DatabaseInstance,
  DatabasePool,
  DatabasePoolConfig,
  DbClient,
} from '../types';

export type { DatabaseConfig, DatabaseInstance, DatabasePool, DatabasePoolConfig, DbClient };

/**
 * Default pool configuration values
 */
export const DEFAULT_POOL_CONFIG: Required<DatabasePoolConfig> = {
  max: 20,
  min: 2,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 2000,
};

/**
 * Create a database instance with the given configuration
 *
 * @param config - Database configuration with connection string and optional pool settings
 * @returns Database instance with db, pool, close, and testConnection methods
 *
 * @example
 * ```typescript
 * const database = createDatabase({
 *   connectionString: 'postgresql://user:pass@localhost:5432/db',
 *   pool: {
 *     max: 20,
 *     min: 2,
 *   },
 * });
 *
 * // Use the database
 * const users = await database.db.select().from(usersTable);
 *
 * // Close when done
 * await database.close();
 * ```
 */
export function createDatabase(config: DatabaseConfig): DatabaseInstance {
  // Merge pool config with defaults
  const poolConfig = {
    ...DEFAULT_POOL_CONFIG,
    ...config.pool,
  };

  // Create PostgreSQL connection pool
  const pool = new Pool({
    connectionString: config.connectionString,
    max: poolConfig.max,
    min: poolConfig.min,
    idleTimeoutMillis: poolConfig.idleTimeoutMillis,
    connectionTimeoutMillis: poolConfig.connectionTimeoutMillis,
  });

  // Create Drizzle database instance
  const db = drizzle(pool);

  return {
    db,
    pool,

    async close(): Promise<void> {
      await pool.end();
    },

    async testConnection(): Promise<boolean> {
      try {
        const client = await pool.connect();
        await client.query('SELECT 1');
        client.release();
        return true;
      } catch (error) {
        console.error('Database connection test failed:', error);
        return false;
      }
    },
  };
}
