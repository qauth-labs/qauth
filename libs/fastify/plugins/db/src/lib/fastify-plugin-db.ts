import {
  type AuthorizationCodesRepository,
  createAuditLogsRepository,
  createAuthorizationCodesRepository,
  createDatabase,
  createEmailVerificationTokensRepository,
  createOAuthClientsRepository,
  createOAuthConsentsRepository,
  createRealmsRepository,
  createRefreshTokensRepository,
  createUsersRepository,
  type DatabasePool,
  type DbClient,
  type EmailVerificationTokensRepository,
  OAuthClientsRepository,
  type OAuthConsentsRepository,
  type RealmsRepository,
  type RefreshTokensRepository,
  type UsersRepository,
} from '@qauth-labs/infra-db';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type { DatabasePluginOptions } from '../types';

declare module 'fastify' {
  interface FastifyInstance {
    db: DbClient;
    dbPool: DatabasePool;
    repositories: {
      users: UsersRepository;
      realms: RealmsRepository;
      emailVerificationTokens: EmailVerificationTokensRepository;
      oauthClients: OAuthClientsRepository;
      oauthConsents: OAuthConsentsRepository;
      refreshTokens: RefreshTokensRepository;
      authorizationCodes: AuthorizationCodesRepository;
      auditLogs: ReturnType<typeof createAuditLogsRepository>;
    };
  }
}

/**
 * Fastify plugin for database connection
 * Decorates fastify instance with db, dbPool, and repositories
 *
 * @example
 * ```typescript
 * await fastify.register(databasePlugin, {
 *   config: {
 *     connectionString: env.DATABASE_URL,
 *     pool: {
 *       max: env.DB_POOL_MAX,
 *       min: env.DB_POOL_MIN,
 *       idleTimeoutMillis: env.DB_POOL_IDLE_TIMEOUT,
 *       connectionTimeoutMillis: env.DB_POOL_CONNECTION_TIMEOUT,
 *     },
 *   },
 * });
 * ```
 */
export const databasePlugin = fp<DatabasePluginOptions>(
  async (fastify: FastifyInstance, options: DatabasePluginOptions) => {
    // Create database instance using factory
    const database = createDatabase(options.config);

    fastify.decorate('db', database.db);
    fastify.decorate('dbPool', database.pool);
    fastify.decorate('repositories', {
      users: createUsersRepository(database.db),
      realms: createRealmsRepository(database.db),
      emailVerificationTokens: createEmailVerificationTokensRepository(database.db),
      oauthClients: createOAuthClientsRepository(database.db),
      oauthConsents: createOAuthConsentsRepository(database.db),
      refreshTokens: createRefreshTokensRepository(database.db),
      authorizationCodes: createAuthorizationCodesRepository(database.db),
      auditLogs: createAuditLogsRepository(database.db),
    });

    fastify.addHook('onReady', async () => {
      const isConnected = await database.testConnection();
      if (!isConnected) {
        fastify.log.warn('Database connection test failed on ready');
      } else {
        fastify.log.info('Database connection verified');
      }
    });

    fastify.addHook('onClose', async () => {
      fastify.log.info('Closing database connection...');
      await database.close();
      fastify.log.info('Database connection closed');
    });
  },
  {
    name: packageJson.name,
  }
);
