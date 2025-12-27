import type { FastifyInstance } from 'fastify';

/**
 * Clean Redis by flushing the current database
 * Note: This should be used carefully and only in test environments
 * @param fastify - Fastify instance with redis decorator
 */
export async function cleanRedis(fastify: FastifyInstance): Promise<void> {
  await fastify.redis.flushdb();
}
