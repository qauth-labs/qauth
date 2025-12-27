import { type CacheClient, getRedis, testConnection } from '@qauth/cache';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    redis: CacheClient;
  }
}

/**
 * Fastify plugin for Redis connection
 * Decorates fastify instance with redis
 *
 * TODO: Currently uses ioredis-specific methods (e.g., `redis.quit()`).
 * After refactoring @qauth/cache to proper abstraction, this should use
 * abstracted methods (e.g., `redis.close()` or similar) instead of
 * implementation-specific methods.
 */
export const cachePlugin = fp<FastifyPluginOptions>(
  async (fastify: FastifyInstance, options: FastifyPluginOptions) => {
    const redis = getRedis();

    fastify.decorate('redis', redis);

    fastify.addHook('onReady', async () => {
      const isConnected = await testConnection();
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
