import { sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';

/**
 * Clean database by truncating all tables
 * SECURITY: This function only works in test environment
 * @param fastify - Fastify instance with db decorator
 * @throws Error if not in test environment
 */
export async function cleanDatabase(fastify: FastifyInstance): Promise<void> {
  // SECURITY: Only allow in test environment
  if (env.NODE_ENV !== 'test') {
    throw new Error(
      'cleanDatabase() can only be called in test environment. Current NODE_ENV: ' + env.NODE_ENV
    );
  }

  // Get all table names from the database
  const tables = await fastify.db.execute(sql`
    SELECT tablename 
    FROM pg_tables 
    WHERE schemaname = 'public'
  `);

  // Disable foreign key checks temporarily
  await fastify.db.execute(sql`SET session_replication_role = replica;`);

  try {
    // Truncate all tables
    for (const row of tables.rows) {
      const tableName = (row as { tablename: string }).tablename;
      await fastify.db.execute(sql.raw(`TRUNCATE TABLE "${tableName}" CASCADE;`));
    }
  } finally {
    // Always re-enable foreign key checks, even if truncation fails
    await fastify.db.execute(sql`SET session_replication_role = DEFAULT;`);
  }
}
