import {
  type AdminGrantsRepository,
  type AdminRolesRepository,
  type ApiKeysRepository,
  type AuthorizationCodesRepository,
  createAdminGrantsRepository,
  createAdminRolesRepository,
  createApiKeysRepository,
  createAuditLogsRepository,
  createAuthorizationCodesRepository,
  createDatabase,
  createEmailVerificationTokensRepository,
  createEventDeliveriesRepository,
  createEventRetentionRepository,
  createEventsRepository,
  createOAuthClientsRepository,
  createOAuthConsentsRepository,
  createOid4vpRequestStatesRepository,
  createRealmsRepository,
  createRefreshTokensRepository,
  createSessionsRepository,
  createSsfStreamsRepository,
  createUserAttributesRepository,
  createUserCredentialsRepository,
  createUsersRepository,
  type Database,
  type DatabasePool,
  type EmailVerificationTokensRepository,
  type EventDeliveriesRepository,
  type EventRetentionRepository,
  type EventsRepository,
  OAuthClientsRepository,
  type OAuthConsentsRepository,
  type Oid4vpRequestStatesRepository,
  type RealmsRepository,
  type RefreshTokensRepository,
  type SessionsRepository,
  type SsfStreamsRepository,
  type UserAttributesRepository,
  type UserCredentialsRepository,
  type UsersRepository,
} from '@qauth-labs/infra-db';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type { DatabasePluginOptions } from '../types';

declare module 'fastify' {
  interface FastifyInstance {
    db: Database;
    dbPool: DatabasePool;
    repositories: {
      users: UsersRepository;
      realms: RealmsRepository;
      emailVerificationTokens: EmailVerificationTokensRepository;
      oauthClients: OAuthClientsRepository;
      oauthConsents: OAuthConsentsRepository;
      refreshTokens: RefreshTokensRepository;
      authorizationCodes: AuthorizationCodesRepository;
      auditLogs: ReturnType<typeof createAuditLogsRepository>;
      apiKeys: ApiKeysRepository;
      userCredentials: UserCredentialsRepository;
      userAttributes: UserAttributesRepository;
      /**
       * OID4VP presentation-request states (ADR-004, #233). Decorated
       * unconditionally like every other repository — the WALLET FLOW is gated
       * (by `WALLET_FEDERATION_ENABLED` plus a resolved `VerifierProfile`), not
       * the storage layer, so a disabled deployment simply never writes a row.
       */
      oid4vpRequestStates: Oid4vpRequestStatesRepository;
      /**
       * The event store (ADR-019 Decision 8, #457): `emit(tx, event)` in the
       * transaction of the change, `emitInOwnTransaction(event)` without one,
       * and `readAfter(realmId, position, limit)` for a realm's stream.
       */
      events: EventsRepository;
      /**
       * The delivery role's queue (ADR-019 Decision 8, #460), for the readers
       * of its state: `minOffered(realmId)` for the retention job (#536) and
       * `listForEvent(eventId)` for the delivery history. The role itself
       * builds its own on the database it connects to.
       */
      eventDeliveries: EventDeliveriesRepository;
      /**
       * The retention job's access to the event store (#536): the realms
       * with events and their retention, the offered bound, the batch
       * delete that keeps the admin chain's anchor, and the oldest event of
       * each category for `/metrics`. Deleting needs the retention role's
       * grants (`eventRetentionGrantStatements`).
       */
      eventRetention: EventRetentionRepository;
      /**
       * Browser sessions (ADR-019 Decision 3, #468). Routes reach them through
       * `fastify.sessionService` (#469), which adds the cache, the realm's
       * lifetimes and the last-seen throttle.
       */
      sessions: SessionsRepository;
      /**
       * The streams of the Shared Signals Framework transmitter (#410): the
       * stream management routes, the status endpoint and the SSF delivery
       * route read and write them.
       */
      ssfStreams: SsfStreamsRepository;
      /**
       * Custom admin roles (ADR-019 Decision 7, #510). Built-in roles are
       * defined in the auth server's code, not stored.
       */
      adminRoles: AdminRolesRepository;
      /**
       * Admin grants (ADR-019 Decision 7, #510): which account administers
       * which realm through which role. The admin API reads them on every
       * request (`resolveAdminAuthority`), never from a token.
       */
      adminGrants: AdminGrantsRepository;
    };
  }
}

export const DATABASE_PLUGIN_NAME = packageJson.name;

/**
 * Fastify plugin for database connection
 * Decorates fastify instance with db, dbPool, and repositories
 *
 * @example
 * ```typescript
 * await fastify.register(databasePlugin, {
 *   config: {
 *     connectionString: env.DATABASE_URL,
 *     pool: {
 *       max: env.DB_POOL_MAX,
 *       min: env.DB_POOL_MIN,
 *       idleTimeoutMillis: env.DB_POOL_IDLE_TIMEOUT,
 *       connectionTimeoutMillis: env.DB_POOL_CONNECTION_TIMEOUT,
 *     },
 *   },
 * });
 * ```
 */
export const databasePlugin = fp<DatabasePluginOptions>(
  async (fastify: FastifyInstance, options: DatabasePluginOptions) => {
    // Create database instance using factory. Inject the Fastify logger so DB
    // diagnostics flow through pino (levels + request-id correlation) instead
    // of bare `console`.
    const database = createDatabase({ ...options.config, logger: fastify.log });

    fastify.decorate('db', database.db);
    fastify.decorate('dbPool', database.pool);
    fastify.decorate('repositories', {
      users: createUsersRepository(database.db),
      realms: createRealmsRepository(database.db, { seeds: options.realmPolicySeeds }),
      emailVerificationTokens: createEmailVerificationTokensRepository(database.db),
      oauthClients: createOAuthClientsRepository(database.db),
      oauthConsents: createOAuthConsentsRepository(database.db),
      refreshTokens: createRefreshTokensRepository(database.db),
      authorizationCodes: createAuthorizationCodesRepository(database.db),
      auditLogs: createAuditLogsRepository(database.db),
      apiKeys: createApiKeysRepository(database.db),
      userCredentials: createUserCredentialsRepository(database.db),
      userAttributes: createUserAttributesRepository(database.db),
      oid4vpRequestStates: createOid4vpRequestStatesRepository(database.db),
      events: createEventsRepository(database.db, { telemetry: options.eventTelemetry }),
      eventDeliveries: createEventDeliveriesRepository(database.db),
      eventRetention: createEventRetentionRepository(database.db),
      sessions: createSessionsRepository(database.db),
      ssfStreams: createSsfStreamsRepository(database.db),
      adminRoles: createAdminRolesRepository(database.db, { catalog: options.adminRoleCatalog }),
      adminGrants: createAdminGrantsRepository(database.db, { catalog: options.adminRoleCatalog }),
    });

    fastify.addHook('onReady', async () => {
      const isConnected = await database.testConnection();
      if (!isConnected) {
        fastify.log.warn('Database connection test failed on ready');
      } else {
        fastify.log.info('Database connection verified');
      }
    });

    fastify.addHook('onClose', async () => {
      fastify.log.info('Closing database connection...');
      await database.close();
      fastify.log.info('Database connection closed');
    });
  },
  {
    name: DATABASE_PLUGIN_NAME,
  }
);
