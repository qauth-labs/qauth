import type { Redis } from 'ioredis';
import { GenericContainer, type StartedTestContainer, Wait } from 'testcontainers';

/**
 * A running throwaway Redis instance for integration tests (issue #240).
 *
 * The sibling of `pg-testcontainer.ts`, and it exists for the same reason: the
 * wallet-login flow keeps its browser-side flow record, its wallet-side signal
 * and the parked presentation in Redis, so an end-to-end run of that flow cannot
 * be done against a mocked cache without mocking away the very handoff between
 * the unauthenticated `direct_post` endpoint and the cookie-bound browser poll —
 * which is the part worth testing.
 */
export interface StartedRedis {
  /** ioredis-compatible connection URL of the suite's logical database. */
  connectionUrl: string;
  /**
   * A second logical database on the same server, as empty and as much the
   * suite's own as the first: for a node that must share no key with the
   * others (a node with a cache of its own).
   */
  spareConnectionUrl: string;
  /** Host port the server listens on. */
  port: number;
  /**
   * Release what the suite was given. On the shared server it empties the
   * suite's two logical databases; a private container is stopped and removed.
   */
  stop(): Promise<void>;
}

/** What {@link startRedisContainer} hands a suite. */
export interface StartRedisOptions {
  /**
   * A Redis container of the suite's own instead of two logical databases on
   * the shared server. For a suite that stops, kills, pauses or restarts the
   * server, changes its configuration, or relies on what spans its logical
   * databases (pub/sub, keyspace notifications, `FLUSHALL`).
   */
  readonly privateContainer?: boolean;
}

/** Redis image — pinned to match docker-compose (`redis:7-alpine`). */
export const REDIS_IMAGE = 'redis:7-alpine';

/**
 * The environment variable that names the run's shared Redis server
 * (`redis://host:port`, no database). The integration global setup sets it;
 * unset, every suite gets a private container.
 */
export const SHARED_REDIS_URL_ENV = 'QAUTH_TEST_SHARED_REDIS_URL';

/**
 * Logical databases of the shared server. Each suite takes the next unused
 * pair, so 1024 is room for 511 suites a run, against some 60 today.
 * Database 0 keeps the pair counter, and no suite is given database 1.
 */
const SHARED_REDIS_DATABASES = 1024;

/** The key in database 0 of the shared server that counts the pairs handed out. */
const PAIR_COUNTER_KEY = 'qauth-test:database-pairs';

/**
 * Start the run's shared Redis server, for the integration global setup.
 *
 * @returns the environment that points suites at the server, and its stop.
 */
export async function startSharedRedis(): Promise<{
  env: Record<string, string>;
  stop(): Promise<void>;
}> {
  const container = await startServer(['--databases', String(SHARED_REDIS_DATABASES)]);
  return {
    env: {
      [SHARED_REDIS_URL_ENV]: `redis://${container.getHost()}:${container.getMappedPort(6379)}`,
    },
    async stop(): Promise<void> {
      await container.stop();
    },
  };
}

async function startServer(args: readonly string[] = []): Promise<StartedTestContainer> {
  let builder = new GenericContainer(REDIS_IMAGE)
    .withExposedPorts(6379)
    .withWaitStrategy(Wait.forLogMessage(/Ready to accept connections/))
    .withStartupTimeout(120_000);
  if (args.length > 0) builder = builder.withCommand(['redis-server', ...args]);
  return builder.start();
}

/** Run `work` on a short-lived client of database 0 of the server at `serverUrl`. */
async function withClient<T>(serverUrl: string, work: (client: Redis) => Promise<T>): Promise<T> {
  // Loaded here, not at module load: most importers of this library never
  // reach Redis.
  const { default: RedisClient } = await import('ioredis');
  const client = new RedisClient(`${serverUrl}/0`, { lazyConnect: true });
  try {
    await client.connect();
    return await work(client);
  } finally {
    client.disconnect();
  }
}

async function sharedDatabases(serverUrl: string): Promise<StartedRedis> {
  const pair = await withClient(serverUrl, (client) => client.incr(PAIR_COUNTER_KEY));
  const first = 2 * pair;
  const spare = first + 1;
  if (spare >= SHARED_REDIS_DATABASES) {
    throw new Error(
      `the shared Redis has no logical database left for pair ${pair}: raise SHARED_REDIS_DATABASES`
    );
  }
  return {
    connectionUrl: `${serverUrl}/${first}`,
    spareConnectionUrl: `${serverUrl}/${spare}`,
    port: Number(new URL(serverUrl).port),
    async stop(): Promise<void> {
      await withClient(serverUrl, async (client) => {
        for (const database of [first, spare]) {
          await client.select(database);
          await client.flushdb();
        }
      });
    },
  };
}

async function startPrivateRedis(): Promise<StartedRedis> {
  const container = await startServer();
  const host = container.getHost();
  const port = container.getMappedPort(6379);
  return {
    connectionUrl: `redis://${host}:${port}/0`,
    spareConnectionUrl: `redis://${host}:${port}/1`,
    port,
    async stop(): Promise<void> {
      await container.stop();
    },
  };
}

/**
 * A Redis 7 keyspace for one integration suite.
 *
 * Under the integration config it is a pair of logical databases on the
 * run's shared server (see {@link SHARED_REDIS_URL_ENV}) that no other suite
 * of the run is given. Keys, their expiry and the scripts that work on them
 * stay inside the suite's databases; what spans databases (pub/sub, keyspace
 * notifications, `FLUSHALL`, the server's configuration) does not, which is
 * why `privateContainer` exists. With it, or when no shared server was started,
 * it is a container of the suite's own.
 *
 * Pinned to the same image docker-compose runs so key expiry, eviction and
 * command behaviour match a real deployment.
 *
 * Requires a running Docker daemon. Call `requireDockerOrSkip()` first — it
 * skips the suite where Docker is absent but FAILS on CI, so a daemon-less
 * runner cannot turn a container suite into a green no-op.
 *
 * @example
 * ```ts
 * const redis = await startRedisContainer();
 * process.env['REDIS_URL'] = redis.connectionUrl;
 * // ... boot the app, run tests ...
 * await redis.stop();
 * ```
 */
export async function startRedisContainer(options: StartRedisOptions = {}): Promise<StartedRedis> {
  const shared = process.env[SHARED_REDIS_URL_ENV];
  if (options.privateContainer === true || !shared) return startPrivateRedis();
  return sharedDatabases(shared);
}
