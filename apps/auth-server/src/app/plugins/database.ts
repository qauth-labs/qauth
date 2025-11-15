import { closeDatabase, db, pool, testConnection } from '@qauth/db';
import { drizzle } from 'drizzle-orm/node-postgres';
import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    db: ReturnType<typeof drizzle>;
  }
}

/**
 * Database plugin for PostgreSQL connection
 *
 * Provides database access via Drizzle ORM
 */
export default fp(async function (fastify: FastifyInstance) {
  // Test database connection on startup
  const isConnected = await testConnection();

  if (!isConnected) {
    fastify.log.error('Failed to connect to database');
    throw new Error('Database connection failed');
  }

  fastify.log.info('Database connected successfully');

  // Decorate Fastify instance with database client
  fastify.decorate('db', db);

  // Graceful shutdown
  fastify.addHook('onClose', async () => {
    fastify.log.info('Closing database connection...');
    await closeDatabase();
    fastify.log.info('Database connection closed');
  });
});
