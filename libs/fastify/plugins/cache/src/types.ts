import type { RedisConfig } from '@qauth-labs/infra-cache';
import type { FastifyPluginOptions } from 'fastify';

/**
 * Options for the cache plugin
 */
export interface CachePluginOptions extends FastifyPluginOptions {
  /** Redis configuration with connection settings */
  config: RedisConfig;
}
