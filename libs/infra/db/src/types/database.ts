import type { ExtractTablesWithRelations } from 'drizzle-orm';
import type { drizzle, NodePgQueryResultHKT } from 'drizzle-orm/node-postgres';
import type { PgTransaction } from 'drizzle-orm/pg-core';
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
 * The top-level drizzle database instance. Has `$client` + `.transaction(...)`.
 * Use this when you specifically need the root connection (e.g. to open a
 * transaction from a Fastify decorator).
 */
export type Database = ReturnType<typeof drizzle<Record<string, never>>>;

/**
 * Drizzle transaction handle as yielded to `db.transaction(async (tx) => ...)`.
 */
export type DbTransaction = PgTransaction<
  NodePgQueryResultHKT,
  Record<string, never>,
  ExtractTablesWithRelations<Record<string, never>>
>;

/**
 * DbClient accepts either the top-level database or an in-flight
 * transaction. Repository methods take this so the same call can
 * participate in an outer transaction or stand alone.
 */
export type DbClient = Database | DbTransaction;

/**
 * Database instance returned by the factory
 */
export interface DatabaseInstance {
  /** Drizzle database client for queries */
  db: Database;
  /** PostgreSQL connection pool for direct access */
  pool: DatabasePool;
  /** Close the database connection pool */
  close(): Promise<void>;
  /** Test the database connection @returns true if connection is successful, false otherwise */
  testConnection(): Promise<boolean>;
}
