import {
  closeDatabase,
  createRealmsRepository,
  createUsersRepository,
  type DatabasePool,
  db,
  type DbClient,
  pool,
  type RealmsRepository,
  testConnection,
  type UsersRepository,
} from '@qauth/db';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    db: DbClient;
    dbPool: DatabasePool;
    repositories: {
      users: UsersRepository;
      realms: RealmsRepository;
    };
  }
}

/**
 * Fastify plugin for database connection
 * Decorates fastify instance with db, dbPool, and repositories
 */
export const databasePlugin = fp<FastifyPluginOptions>(
  async (fastify: FastifyInstance) => {
    fastify.decorate('db', db);
    fastify.decorate('dbPool', pool);
    fastify.decorate('repositories', {
      users: createUsersRepository(db),
      realms: createRealmsRepository(db),
    });

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
      await closeDatabase();
      fastify.log.info('Database connection closed');
    });
  },
  {
    name: '@qauth/fastify-plugin-db',
  }
);
