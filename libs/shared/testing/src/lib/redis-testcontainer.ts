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
  /** ioredis-compatible connection URL. */
  connectionUrl: string;
  /** Mapped host port for the container's 6379. */
  port: number;
  /** Stop and remove the container. */
  stop(): Promise<void>;
}

/** Redis image — pinned to match docker-compose (`redis:7-alpine`). */
export const REDIS_IMAGE = 'redis:7-alpine';

/**
 * Start a disposable Redis 7 container for integration tests.
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
export async function startRedisContainer(): Promise<StartedRedis> {
  const container: StartedTestContainer = await new GenericContainer(REDIS_IMAGE)
    .withExposedPorts(6379)
    .withWaitStrategy(Wait.forLogMessage(/Ready to accept connections/))
    .withStartupTimeout(120_000)
    .start();

  const host = container.getHost();
  const port = container.getMappedPort(6379);

  return {
    connectionUrl: `redis://${host}:${port}/0`,
    port,
    async stop(): Promise<void> {
      await container.stop();
    },
  };
}
