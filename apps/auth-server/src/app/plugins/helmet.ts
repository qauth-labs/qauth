import helmet from '@fastify/helmet';
import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

/**
 * Helmet plugin for security headers
 *
 * @see https://github.com/fastify/fastify-helmet
 */
export default fp(async function (fastify: FastifyInstance) {
  fastify.register(helmet, {
    // Enable CSP, HSTS, and other security headers
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
  });
});
