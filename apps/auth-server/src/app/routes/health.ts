// Health check endpoint for monitoring and load balancer health checks
// Provides dependency status and service health information

import type { HealthCheckResponse } from '@qauth/types';
import { FastifyInstance, FastifyPluginOptions } from 'fastify';

export default async function healthRoutes(fastify: FastifyInstance, opts: FastifyPluginOptions) {
  // Health check endpoint
  fastify.get('/', async (request, reply) => {
    const startTime = Date.now();

    try {
      // Check database connectivity
      const dbStatus = (await fastify.db.ping()) ? 'connected' : 'disconnected';

      // Check Redis connectivity
      const redisStatus = (await fastify.redis.ping()) ? 'connected' : 'disconnected';

      // Calculate response time
      const responseTime = Date.now() - startTime;

      // Determine overall status
      const status = dbStatus === 'connected' && redisStatus === 'connected' ? 'ok' : 'error';

      // Build health response
      const healthResponse: HealthCheckResponse = {
        status,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        dependencies: {
          database: dbStatus,
          redis: redisStatus,
        },
        responseTime,
      };

      // Return appropriate status code
      const statusCode = status === 'ok' ? 200 : 503;

      reply.status(statusCode).send(healthResponse);
    } catch (error) {
      fastify.log.error({ error }, 'Health check failed');

      const healthResponse: HealthCheckResponse = {
        status: 'error',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        dependencies: {
          database: 'disconnected',
          redis: 'disconnected',
        },
        responseTime: Date.now() - startTime,
      };

      reply.status(503).send(healthResponse);
    }
  });

  // Detailed health endpoint with more information
  fastify.get('/detailed', async (request, reply) => {
    const startTime = Date.now();

    try {
      // Database health check
      const dbPing = await fastify.db.ping();
      const dbStats = fastify.db.getPoolStats();

      // Redis health check
      const redisPing = await fastify.redis.ping();
      const redisInfo = await fastify.redis.getInfo('memory');

      // Session statistics
      const sessionStats = await fastify.redis.getSessionStats();

      const responseTime = Date.now() - startTime;

      const detailedHealth = {
        status: dbPing && redisPing ? 'ok' : 'error',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        responseTime,
        dependencies: {
          database: {
            status: dbPing ? 'connected' : 'disconnected',
            pool: dbStats,
          },
          redis: {
            status: redisPing ? 'connected' : 'disconnected',
            memory:
              redisInfo
                .split('\n')
                .find((line: string) => line.startsWith('used_memory_human:'))
                ?.split(':')[1]
                ?.trim() || 'unknown',
            sessions: sessionStats,
          },
        },
        system: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch,
          memory: {
            used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
            total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
          },
        },
      };

      const statusCode = detailedHealth.status === 'ok' ? 200 : 503;
      reply.status(statusCode).send(detailedHealth);
    } catch (error) {
      fastify.log.error({ error }, 'Detailed health check failed');

      const errorHealth = {
        status: 'error',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        responseTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown error',
      };

      reply.status(503).send(errorHealth);
    }
  });
}
