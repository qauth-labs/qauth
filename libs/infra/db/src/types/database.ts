import type { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';

/**
 * Database pool type - abstracted from implementation
 * Currently uses pg Pool, but provides abstraction for potential future changes
 */
export type DatabasePool = Pool;

/**
 * Pool configuration options
 */
export interface DatabasePoolConfig {
  /** Maximum number of connections in the pool @default 20 */
  max?: number;
  /** Minimum number of connections in the pool @default 2 */
  min?: number;
  /** Idle connection timeout in milliseconds @default 10000 */
  idleTimeoutMillis?: number;
  /** Connection timeout in milliseconds @default 2000 */
  connectionTimeoutMillis?: number;
}

/**
 * Database configuration interface
 */
export interface DatabaseConfig {
  /** PostgreSQL connection URL (required) */
  connectionString: string;
  /** Pool configuration options (optional) */
  pool?: DatabasePoolConfig;
}

/**
 * DbClient type that can be either the main db instance or a transaction
 * This allows repository methods to work with both regular queries and transactions
 */
export type DbClient = ReturnType<typeof drizzle<Record<string, never>>>;

/**
 * Database instance returned by the factory
 */
export interface DatabaseInstance {
  /** Drizzle database client for queries */
  db: DbClient;
  /** PostgreSQL connection pool for direct access */
  pool: DatabasePool;
  /** Close the database connection pool */
  close(): Promise<void>;
  /** Test the database connection @returns true if connection is successful, false otherwise */
  testConnection(): Promise<boolean>;
}
