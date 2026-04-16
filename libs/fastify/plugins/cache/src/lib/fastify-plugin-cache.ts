import {
  type CacheClient,
  createRedisConnection,
  createSessionUtils,
  type SessionUtilsInstance,
  testRedisConnection,
} from '@qauth-labs/infra-cache';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type { CachePluginOptions } from '../types';
declare module 'fastify' {
  interface FastifyInstance {
    redis: CacheClient;
    sessionUtils: SessionUtilsInstance;
  }
}

export const CACHE_PLUGIN_NAME = packageJson.name;

/**
 * Fastify plugin for Redis connection
 * Decorates fastify instance with redis
 *
 * @example
 * ```typescript
 * await fastify.register(cachePlugin, {
 *   config: {
 *     url: env.REDIS_URL,
 *     host: env.REDIS_HOST,
 *     port: env.REDIS_PORT,
 *     password: env.REDIS_PASSWORD,
 *     db: env.REDIS_DB,
 *     maxRetriesPerRequest: env.REDIS_MAX_RETRIES,
 *     connectTimeout: env.REDIS_CONNECTION_TIMEOUT,
 *     commandTimeout: env.REDIS_COMMAND_TIMEOUT,
 *     lazyConnect: true,
 *   },
 * });
 * ```
 */
export const cachePlugin = fp<CachePluginOptions>(
  async (fastify: FastifyInstance, options: CachePluginOptions) => {
    // Create Redis instance using factory
    const redis = createRedisConnection(options.config);

    // Create session utilities
    const sessionUtils = createSessionUtils(redis);

    fastify.decorate('redis', redis);
    fastify.decorate('sessionUtils', sessionUtils);

    fastify.addHook('onReady', async () => {
      const isConnected = await testRedisConnection(redis);
      if (!isConnected) {
        fastify.log.warn('Redis connection test failed on ready');
      } else {
        fastify.log.info('Redis connection verified');
      }
    });

    fastify.addHook('onClose', async () => {
      fastify.log.info('Closing Redis connection...');
      await redis.quit();
      fastify.log.info('Redis connection closed');
    });
  },
  {
    name: CACHE_PLUGIN_NAME,
  }
);
