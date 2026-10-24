import type { DatabaseConfig, EventTelemetrySink } from '@qauth-labs/infra-db';
import type { FastifyPluginOptions } from 'fastify';

export type { EventTelemetrySink };

/**
 * Options for the database plugin
 */
export interface DatabasePluginOptions extends FastifyPluginOptions {
  /** Database configuration with connection string and pool settings */
  config: DatabaseConfig;
  /**
   * Where the event store hands each event once it has committed (#541): the
   * auth server's OpenTelemetry log export, when it is on. Absent, events
   * leave the store only through its reads.
   */
  eventTelemetry?: EventTelemetrySink;
}
