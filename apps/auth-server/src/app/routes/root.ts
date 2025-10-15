// Root endpoint and basic API information
// Provides service metadata and API discovery information

import { FastifyInstance, FastifyPluginOptions } from 'fastify';

import { getEnv } from '../../config/env';

export default async function rootRoutes(fastify: FastifyInstance, opts: FastifyPluginOptions) {
  // Root endpoint with service information
  fastify.get('/', async (request, reply) => {
    const env = getEnv();

    const serviceInfo = {
      name: 'QAuth OAuth 2.1/OIDC Server',
      version: '0.1.0',
      description: 'Post-quantum ready, headless-first identity platform',
      environment: env.NODE_ENV,
      timestamp: new Date().toISOString(),
      endpoints: {
        health: '/health',
        healthDetailed: '/health/detailed',
        docs: '/docs', // Will be added in future phases
        openidConfiguration: '/.well-known/openid_configuration', // Phase 1
        jwks: '/.well-known/jwks.json', // Phase 1
      },
      features: {
        oauth2_1: true,
        pkce: true,
        oidc: 'Phase 1',
        postQuantum: 'Phase 4+',
      },
      links: {
        repository: 'https://github.com/qauth-labs/qauth',
        documentation: 'https://docs.qauth.dev',
        support: 'https://github.com/qauth-labs/qauth/issues',
      },
    };

    reply.send(serviceInfo);
  });

  // API version endpoint
  fastify.get('/version', async (request, reply) => {
    const versionInfo = {
      version: '0.1.0',
      apiVersion: 'v1',
      buildTime: new Date().toISOString(),
      nodeVersion: process.version,
      environment: getEnv().NODE_ENV,
    };

    reply.send(versionInfo);
  });

  // Service status (lightweight health check)
  fastify.get('/status', async (request, reply) => {
    try {
      // Quick connectivity checks
      const [dbStatus, redisStatus] = await Promise.all([
        fastify.db.ping().catch(() => false),
        fastify.redis.ping().catch(() => false),
      ]);

      const status = {
        status: dbStatus && redisStatus ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        services: {
          database: dbStatus ? 'up' : 'down',
          redis: redisStatus ? 'up' : 'down',
        },
      };

      const statusCode = status.status === 'healthy' ? 200 : 503;
      reply.status(statusCode).send(status);
    } catch (error) {
      reply.status(503).send({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Service unavailable',
      });
    }
  });
}
