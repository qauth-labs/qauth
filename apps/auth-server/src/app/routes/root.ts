import { FastifyInstance } from 'fastify';

/**
 * Root route - API information endpoint
 */
export default async function (fastify: FastifyInstance) {
  fastify.get('/', async function () {
    return {
      name: 'QAuth Auth Server',
      description: 'Post-quantum ready, headless-first identity platform',
      version: '0.0.0',
      status: 'development',
      endpoints: {
        health: '/health',
        detailedHealth: '/health/detailed',
        wellKnown: '/.well-known/health',
      },
      documentation: 'https://docs.qauth.dev',
    };
  });
}
