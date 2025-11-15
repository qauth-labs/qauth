import { testConnection as testRedisConnection } from '@qauth/cache';
import { testConnection as testDbConnection } from '@qauth/db';
import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

interface HealthCheckResponse {
  status: 'healthy' | 'unhealthy' | 'degraded';
  timestamp: string;
  uptime: number;
  services: {
    database: {
      status: 'up' | 'down';
      responseTime?: number;
    };
    redis: {
      status: 'up' | 'down';
      responseTime?: number;
    };
  };
}

/**
 * Health check routes
 *
 * Provides detailed health status for monitoring and load balancers
 */
export default async function (fastify: FastifyInstance) {
  /**
   * Basic health check endpoint
   * Returns 200 if the server is running
   */
  fastify.get('/health', async (request: FastifyRequest, reply: FastifyReply) => {
    return reply.code(200).send({ status: 'ok' });
  });

  /**
   * Detailed health check endpoint
   * Checks database and Redis connections
   */
  fastify.get<{ Reply: HealthCheckResponse }>(
    '/health/detailed',
    async (request: FastifyRequest, reply: FastifyReply) => {
      const startTime = Date.now();

      // Test database connection
      const dbStart = Date.now();
      const dbHealthy = await testDbConnection();
      const dbResponseTime = Date.now() - dbStart;

      // Test Redis connection
      const redisStart = Date.now();
      const redisHealthy = await testRedisConnection();
      const redisResponseTime = Date.now() - redisStart;

      // Determine overall status
      let status: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';

      if (!dbHealthy || !redisHealthy) {
        status = !dbHealthy && !redisHealthy ? 'unhealthy' : 'degraded';
      }

      const response: HealthCheckResponse = {
        status,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        services: {
          database: {
            status: dbHealthy ? 'up' : 'down',
            responseTime: dbResponseTime,
          },
          redis: {
            status: redisHealthy ? 'up' : 'down',
            responseTime: redisResponseTime,
          },
        },
      };

      const statusCode = status === 'healthy' ? 200 : status === 'degraded' ? 200 : 503;

      return reply.code(statusCode).send(response);
    }
  );

  /**
   * RFC 5785 well-known health endpoint
   * For standard health check discovery
   */
  fastify.get('/.well-known/health', async (request: FastifyRequest, reply: FastifyReply) => {
    const dbHealthy = await testDbConnection();
    const redisHealthy = await testRedisConnection();

    const status = dbHealthy && redisHealthy ? 'pass' : 'fail';
    const statusCode = status === 'pass' ? 200 : 503;

    return reply.code(statusCode).send({
      status,
      version: '1',
      releaseId: process.env['RELEASE_ID'] || 'dev',
      serviceId: 'qauth-auth-server',
    });
  });
}
