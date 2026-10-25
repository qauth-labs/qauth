import type { DatabaseConfig, EventTelemetrySink, RealmPolicySeeds } from '@qauth-labs/infra-db';
import type { FastifyPluginOptions } from 'fastify';

export type { EventTelemetrySink, RealmPolicySeeds };

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
  /**
   * The realm policies the environment seeds into every new realm (ADR-019
   * Decision 10): today the event retention of #536. Absent, a new realm
   * takes the column defaults.
   */
  realmPolicySeeds?: RealmPolicySeeds;
}
