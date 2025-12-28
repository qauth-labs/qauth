import AutoLoad from '@fastify/autoload';
import cors from '@fastify/cors';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { databasePlugin } from '@qauth/fastify-plugin-db';
import { passwordPlugin } from '@qauth/fastify-plugin-password';
import { FastifyInstance } from 'fastify';
import * as path from 'path';

import { env } from '../config/env';
import errorHandler from './plugins/error-handler';
import { rateLimitPlugin } from './plugins/rate-limit';

export async function app(fastify: FastifyInstance, opts: object) {
  await fastify.register(databasePlugin, {
    config: {
      connectionString: env.DATABASE_URL,
      pool: {
        max: env.DB_POOL_MAX,
        min: env.DB_POOL_MIN,
        idleTimeoutMillis: env.DB_POOL_IDLE_TIMEOUT,
        connectionTimeoutMillis: env.DB_POOL_CONNECTION_TIMEOUT,
      },
    },
  });

  await fastify.register(cachePlugin, {
    config: {
      url: env.REDIS_URL,
      host: env.REDIS_HOST,
      port: env.REDIS_PORT,
      password: env.REDIS_PASSWORD,
      db: env.REDIS_DB,
      maxRetriesPerRequest: env.REDIS_MAX_RETRIES,
      connectTimeout: env.REDIS_CONNECTION_TIMEOUT,
      commandTimeout: env.REDIS_COMMAND_TIMEOUT,
      lazyConnect: true,
    },
  });

  await fastify.register(passwordPlugin, {
    hashConfig: {
      memoryCost: env.PASSWORD_MEMORY_COST,
      timeCost: env.PASSWORD_TIME_COST,
      parallelism: env.PASSWORD_PARALLELISM,
    },
    validationConfig: {
      minScore: env.PASSWORD_MIN_SCORE,
    },
  });

  await fastify.register(rateLimitPlugin);

  await fastify.register(cors, {
    origin: env.CORS_ORIGIN || '*',
  });

  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'plugins'),
    options: { ...opts },
    ignorePattern: /error-handler\.ts$/,
  });

  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'routes'),
    options: { ...opts },
  });

  // Register error handler last to catch all unhandled errors
  await fastify.register(errorHandler);
}
