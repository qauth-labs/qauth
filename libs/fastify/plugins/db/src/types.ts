import type {
  AdminRoleCatalog,
  DatabaseConfig,
  EventTelemetrySink,
  RealmPolicySeeds,
} from '@qauth-labs/infra-db';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';

export type { AdminRoleCatalog, EventTelemetrySink, RealmPolicySeeds };

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
  /**
   * The auth server's admin permission catalog and built-in roles (#510),
   * which the admin role and grant repositories check every write against.
   * Absent, they refuse to create or change a custom role and to grant a
   * built-in role; they still read.
   */
  adminRoleCatalog?: AdminRoleCatalog;
  /**
   * The repositories to build (#495): those the process's service roles use.
   * Every one when absent. Reading any other from `fastify.repositories`
   * throws, naming it, so a role cannot use a repository its list leaves out.
   */
  repositories?: readonly RepositoryName[];
}

/** The name of one repository on `fastify.repositories`. */
export type RepositoryName = keyof FastifyInstance['repositories'];
