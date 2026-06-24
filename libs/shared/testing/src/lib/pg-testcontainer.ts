import { GenericContainer, type StartedTestContainer, Wait } from 'testcontainers';

/**
 * A running throwaway Postgres instance for integration tests.
 */
export interface StartedPostgres {
  /** node-postgres / drizzle compatible connection string. */
  connectionString: string;
  /** Mapped host port for the container's 5432. */
  port: number;
  /** Stop and remove the container. */
  stop(): Promise<void>;
}

/** Postgres image — pinned to match docker-compose (`postgres:18-alpine`). */
export const POSTGRES_IMAGE = 'postgres:18-alpine';

const POSTGRES_USER = 'qauth_test';
const POSTGRES_PASSWORD = 'qauth_test';
const POSTGRES_DB = 'qauth_test';

/**
 * Start a disposable PostgreSQL 18 container for repository integration tests.
 *
 * PG18 is required for native `uuidv7()` (see the 0000 migration); the image is
 * pinned to the same `postgres:18-alpine` used by docker-compose so behaviour
 * matches local/CI Postgres exactly.
 *
 * Requires a running Docker daemon. Call {@link isDockerAvailable} first to skip
 * the suite gracefully where Docker is absent.
 *
 * @example
 * ```ts
 * const pg = await startPostgresContainer();
 * // ... apply migrations against pg.connectionString, run tests ...
 * await pg.stop();
 * ```
 */
export async function startPostgresContainer(): Promise<StartedPostgres> {
  const container: StartedTestContainer = await new GenericContainer(POSTGRES_IMAGE)
    .withEnvironment({
      POSTGRES_USER,
      POSTGRES_PASSWORD,
      POSTGRES_DB,
    })
    .withExposedPorts(5432)
    // Postgres logs "ready to accept connections" twice (init + final boot);
    // wait for the second so we connect only once it is genuinely ready.
    .withWaitStrategy(Wait.forLogMessage(/database system is ready to accept connections/, 2))
    .withStartupTimeout(120_000)
    .start();

  const host = container.getHost();
  const port = container.getMappedPort(5432);
  const connectionString = `postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${host}:${port}/${POSTGRES_DB}`;

  return {
    connectionString,
    port,
    async stop(): Promise<void> {
      await container.stop();
    },
  };
}

/**
 * Best-effort check for a reachable Docker daemon. Integration suites use this
 * to `describe.skip` when Docker is unavailable (e.g. some CI lanes, sandboxes)
 * instead of failing the whole run.
 */
export async function isDockerAvailable(): Promise<boolean> {
  try {
    // Lazy import keeps testcontainers' Docker probing out of the module load
    // path for consumers that only want the types.
    const { getContainerRuntimeClient } = await import('testcontainers');
    await getContainerRuntimeClient();
    return true;
  } catch {
    return false;
  }
}
