import rateLimit from '@fastify/rate-limit';
import { CACHE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-cache';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

import { env } from '../../config/env';

/**
 * Rate limiting plugin configuration
 * Uses Redis store for distributed rate limiting
 * Applied globally, but can be overridden per-route via config.rateLimit
 * Can be disabled via RATE_LIMIT_ENABLED=false environment variable
 */
export const rateLimitPlugin = fp<FastifyPluginOptions>(
  async (fastify: FastifyInstance) => {
    if (!env.RATE_LIMIT_ENABLED) {
      fastify.log.warn('Rate limiting is DISABLED via RATE_LIMIT_ENABLED=false');
      return;
    }

    const defaultMax = env.RATE_LIMIT_MAX;
    const defaultTimeWindow = env.RATE_LIMIT_WINDOW;

    await fastify.register(rateLimit, {
      max: defaultMax,
      timeWindow: defaultTimeWindow * 1000,
      redis: fastify.redis,
      keyGenerator: (request) => {
        // TODO: Consider using a more secure key generator
        return request.ip || request.socket.remoteAddress || 'unknown';
      },
    });

    fastify.log.info('Rate limiting plugin registered');
  },
  {
    name: '@qauth-labs/rate-limit',
    dependencies: [CACHE_PLUGIN_NAME],
  }
);
