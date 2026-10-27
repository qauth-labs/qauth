import {
  type ApiKeysRepository,
  type AuthorizationCodesRepository,
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
import type { DatabasePluginOptions, RepositoryName } from '../types';

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
    };
  }
}

export const DATABASE_PLUGIN_NAME = packageJson.name;

type Repositories = FastifyInstance['repositories'];

/**
 * Every repository name, as a record so the compiler refuses a name the
 * repositories type gains and this list misses.
 */
const ALL_REPOSITORIES: Readonly<Record<RepositoryName, true>> = {
  users: true,
  realms: true,
  emailVerificationTokens: true,
  oauthClients: true,
  oauthConsents: true,
  refreshTokens: true,
  authorizationCodes: true,
  auditLogs: true,
  apiKeys: true,
  userCredentials: true,
  userAttributes: true,
  oid4vpRequestStates: true,
  events: true,
  eventDeliveries: true,
  eventRetention: true,
  sessions: true,
  ssfStreams: true,
};

/** Every repository the plugin can build, in the order of the type above. */
export const REPOSITORY_NAMES: readonly RepositoryName[] = Object.freeze(
  Object.keys(ALL_REPOSITORIES) as RepositoryName[]
);

/**
 * Whether `fastify.repositories` holds the repository `name`: always, unless
 * the plugin was given a list that leaves it out (#495).
 */
export function hasRepository(repositories: Repositories, name: RepositoryName): boolean {
  return name in repositories;
}

/**
 * The repositories object of {@link databasePlugin}: the `loaded` ones, and for
 * every other name a refusal that names it. A process whose service roles do
 * not use a repository never builds it, and a read of it is a wiring mistake
 * that fails where it happens instead of as `undefined` later.
 */
function repositoriesView(loaded: Partial<Repositories>): Repositories {
  return new Proxy(loaded, {
    get(target, property, receiver) {
      if (
        typeof property === 'string' &&
        (REPOSITORY_NAMES as readonly string[]).includes(property) &&
        !(property in target)
      ) {
        throw new Error(
          `The ${property} repository is not loaded in this process: its service roles (SERVICE_ROLES) do not use it`
        );
      }
      return Reflect.get(target, property, receiver);
    },
  }) as Repositories;
}

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
    // Built lazily per name, so a process builds only the repositories its
    // service roles use (#495). Every one when no list is given.
    const builders: { [Name in RepositoryName]: () => Repositories[Name] } = {
      users: () => createUsersRepository(database.db),
      realms: () => createRealmsRepository(database.db, { seeds: options.realmPolicySeeds }),
      emailVerificationTokens: () => createEmailVerificationTokensRepository(database.db),
      oauthClients: () => createOAuthClientsRepository(database.db),
      oauthConsents: () => createOAuthConsentsRepository(database.db),
      refreshTokens: () => createRefreshTokensRepository(database.db),
      authorizationCodes: () => createAuthorizationCodesRepository(database.db),
      auditLogs: () => createAuditLogsRepository(database.db),
      apiKeys: () => createApiKeysRepository(database.db),
      userCredentials: () => createUserCredentialsRepository(database.db),
      userAttributes: () => createUserAttributesRepository(database.db),
      oid4vpRequestStates: () => createOid4vpRequestStatesRepository(database.db),
      events: () => createEventsRepository(database.db, { telemetry: options.eventTelemetry }),
      eventDeliveries: () => createEventDeliveriesRepository(database.db),
      eventRetention: () => createEventRetentionRepository(database.db),
      sessions: () => createSessionsRepository(database.db),
      ssfStreams: () => createSsfStreamsRepository(database.db),
    };
    const loaded: Partial<Record<RepositoryName, unknown>> = {};
    for (const name of options.repositories ?? REPOSITORY_NAMES) {
      loaded[name] = builders[name]();
    }
    fastify.decorate('repositories', repositoriesView(loaded as Partial<Repositories>));

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
