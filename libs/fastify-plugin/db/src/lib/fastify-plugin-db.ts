import { db, pool, testConnection } from '@qauth/db';
import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { Pool } from 'pg';

declare module 'fastify' {
  interface FastifyInstance {
    db: typeof db;
    dbPool: Pool;
  }
}

export interface DatabasePluginOptions {
  connectionString?: string;
}

/**
 * Fastify plugin for database connection
 * Decorates fastify instance with db and dbPool
 */
export const databasePlugin = fp<DatabasePluginOptions>(
  async (fastify: FastifyInstance) => {
    fastify.decorate('db', db);
    fastify.decorate('dbPool', pool);

    fastify.addHook('onReady', async () => {
      const isConnected = await testConnection();
      if (!isConnected) {
        fastify.log.warn('Database connection test failed on ready');
      } else {
        fastify.log.info('Database connection verified');
      }
    });

    fastify.addHook('onClose', async () => {
      fastify.log.info('Closing database connection...');
      await pool.end();
      fastify.log.info('Database connection closed');
    });
  },
  {
    name: '@qauth/fastify-plugin-db',
  }
);
