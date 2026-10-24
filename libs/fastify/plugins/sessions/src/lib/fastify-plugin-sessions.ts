import { CACHE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-cache';
import { DATABASE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-db';
import {
  createRedisSessionCache,
  createSessionService,
  type RealmSessionLifetimes,
  type SessionMetrics,
  type SessionService,
  type SessionServiceSettings,
  type SessionStore,
} from '@qauth-labs/server-sessions';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The browser session service (ADR-019 Decision 3, #469): Postgres as the
     * source of truth, Redis as a cache, last-seen writes throttled.
     */
    sessionService: SessionService;
  }
}

/** Options for {@link sessionServicePlugin}. */
export interface SessionServicePluginOptions extends FastifyPluginOptions {
  /**
   * `SESSION_COOKIE_TTL` and `SESSION_LAST_SEEN_INTERVAL`, and, for tests, a
   * shorter cache time.
   */
  settings: SessionServiceSettings;
  /** Where the service counts cache reads, Postgres reads and last-seen writes. */
  metrics?: SessionMetrics;
  /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
  now?: () => number;
}

export const SESSION_SERVICE_PLUGIN_NAME = packageJson.name;

type Repositories = FastifyInstance['repositories'];
type RealmRow = NonNullable<Awaited<ReturnType<Repositories['realms']['findById']>>>;

function lifetimesOf(realm: RealmRow): RealmSessionLifetimes {
  return {
    maxLifespanSeconds: realm.ssoMaxLifespan,
    idleTimeoutSeconds: realm.ssoIdleTimeout,
  };
}

/**
 * The session service's Postgres port over the database plugin's
 * repositories. A miss reads the session and its realm's row together; every
 * statement filters on the realm.
 */
export function repositorySessionStore(
  repositories: Pick<Repositories, 'realms' | 'sessions'>
): SessionStore {
  return {
    async findRealmLifetimes(realmId) {
      const realm = await repositories.realms.findById(realmId);
      return realm === undefined ? undefined : lifetimesOf(realm);
    },
    insert: (session) => repositories.sessions.create(session),
    async find(realmId, sid) {
      const [session, realm] = await Promise.all([
        repositories.sessions.findById(realmId, sid),
        repositories.realms.findById(realmId),
      ]);
      if (session === undefined || realm === undefined) return undefined;
      return { session, lifetimes: lifetimesOf(realm) };
    },
    touchLastSeen: (realmId, sid, minIntervalMs) =>
      repositories.sessions.updateLastSeen(realmId, sid, { minIntervalMs }),
    revoke: (realmId, sid, reason) => repositories.sessions.revoke(realmId, sid, reason),
  };
}

/**
 * The browser session service (ADR-019 Decision 3, issue #469), over the
 * database plugin's repositories and the cache plugin's Redis client, which
 * must be registered first. Decorates `fastify.sessionService`.
 *
 * It only builds the service: nothing touches Postgres or Redis until a
 * session is created or read, so a boot with no reachable database still
 * boots.
 */
export const sessionServicePlugin = fp<SessionServicePluginOptions>(
  async (fastify: FastifyInstance, options: SessionServicePluginOptions) => {
    fastify.decorate(
      'sessionService',
      createSessionService({
        store: repositorySessionStore(fastify.repositories),
        cache: createRedisSessionCache(fastify.redis),
        settings: options.settings,
        logger: fastify.log,
        ...(options.metrics ? { metrics: options.metrics } : {}),
        ...(options.now ? { now: options.now } : {}),
      })
    );
  },
  {
    name: SESSION_SERVICE_PLUGIN_NAME,
    // `fastify.repositories` and `fastify.redis`.
    dependencies: [DATABASE_PLUGIN_NAME, CACHE_PLUGIN_NAME],
  }
);

export default sessionServicePlugin;
