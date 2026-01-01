import type { DatabaseConfig } from '@qauth/infra-db';
import type { FastifyPluginOptions } from 'fastify';

/**
 * Options for the database plugin
 */
export interface DatabasePluginOptions extends FastifyPluginOptions {
  /** Database configuration with connection string and pool settings */
  config: DatabaseConfig;
}
