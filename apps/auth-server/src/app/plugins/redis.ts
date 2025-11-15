import { closeRedis, getRedis, isRedisConnected, testConnection } from '@qauth/cache';
import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { Redis } from 'ioredis';

declare module 'fastify' {
  interface FastifyInstance {
    redis: Redis;
  }
}

/**
 * Redis plugin for caching and session management
 *
 * Provides Redis client access
 */
export default fp(async function (fastify: FastifyInstance) {
  // Get Redis instance
  const redis = getRedis();

  // Test Redis connection on startup
  const isConnected = await testConnection();

  if (!isConnected) {
    fastify.log.error('Failed to connect to Redis');
    throw new Error('Redis connection failed');
  }

  fastify.log.info('Redis connected successfully');

  // Decorate Fastify instance with Redis client
  fastify.decorate('redis', redis);

  // Graceful shutdown
  fastify.addHook('onClose', async () => {
    fastify.log.info('Closing Redis connection...');
    await closeRedis();
    fastify.log.info('Redis connection closed');
  });
});
