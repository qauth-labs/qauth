import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';

/**
 * Database pool type - abstracted from implementation
 * Currently uses pg Pool, but provides abstraction for potential future changes
 */
export type DatabasePool = Pool;

/**
 * Pool configuration options
 */
export interface DatabasePoolConfig {
  /**
   * Maximum number of connections in the pool
   * @default 20
   */
  max?: number;

  /**
   * Minimum number of connections in the pool
   * @default 2
   */
  min?: number;

  /**
   * Idle connection timeout in milliseconds
   * @default 10000
   */
  idleTimeoutMillis?: number;

  /**
   * Connection timeout in milliseconds
   * @default 2000
   */
  connectionTimeoutMillis?: number;
}

/**
 * Database configuration interface
 */
export interface DatabaseConfig {
  /**
   * PostgreSQL connection URL (required)
   */
  connectionString: string;

  /**
   * Pool configuration options (optional)
   */
  pool?: DatabasePoolConfig;
}

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
 * Database instance returned by the factory
 */
export interface DatabaseInstance {
  /**
   * Drizzle database client for queries
   */
  db: DbClient;

  /**
   * PostgreSQL connection pool for direct access
   */
  pool: DatabasePool;

  /**
   * Close the database connection pool
   */
  close(): Promise<void>;

  /**
   * Test the database connection
   * @returns true if connection is successful, false otherwise
   */
  testConnection(): Promise<boolean>;
}

/**
 * DbClient type that can be either the main db instance or a transaction
 * This allows repository methods to work with both regular queries and transactions
 */
export type DbClient = ReturnType<typeof drizzle<Record<string, never>>>;

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
