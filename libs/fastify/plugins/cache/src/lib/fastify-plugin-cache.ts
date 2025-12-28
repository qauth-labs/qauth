import {
  type CacheClient,
  createRedisConnection,
  type RedisConfig,
  testRedisConnection,
} from '@qauth/cache';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    redis: CacheClient;
  }
}

/**
 * Options for the cache plugin
 */
export interface CachePluginOptions extends FastifyPluginOptions {
  /**
   * Redis configuration with connection settings
   */
  config: RedisConfig;
}

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
 *     retryDelayOnFailover: env.REDIS_RETRY_DELAY,
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

    fastify.decorate('redis', redis);

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
    name: '@qauth/fastify-plugin-cache',
  }
);
