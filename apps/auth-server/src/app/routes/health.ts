import { FastifyInstance } from 'fastify';

interface HealthResponse {
  status: 'ok' | 'unhealthy';
  timestamp: string;
  services: {
    database: 'connected' | 'disconnected';
    redis: 'connected' | 'disconnected';
  };
}

export default async function (fastify: FastifyInstance) {
  fastify.get<{ Reply: HealthResponse }>('/health', async function (request, reply) {
    try {
      const dbHealthy = await fastify.dbPool
        .query('SELECT 1')
        .then(() => true)
        .catch(() => false);

      const redisHealthy = await fastify.redis
        .ping()
        .then(() => true)
        .catch(() => false);

      const status = dbHealthy && redisHealthy ? 'ok' : 'unhealthy';
      const statusCode = status === 'ok' ? 200 : 503;

      const response: HealthResponse = {
        status,
        timestamp: new Date().toISOString(),
        services: {
          database: dbHealthy ? 'connected' : 'disconnected',
          redis: redisHealthy ? 'connected' : 'disconnected',
        },
      };

      return reply.status(statusCode).send(response);
    } catch (error) {
      fastify.log.error(error, 'Health check failed');
      return reply.status(503).send({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        services: {
          database: 'disconnected',
          redis: 'disconnected',
        },
      } satisfies HealthResponse);
    }
  });
}
