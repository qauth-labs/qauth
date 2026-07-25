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
 * Requires a running Docker daemon. Call {@link requireDockerOrSkip} first: it
 * skips the suite gracefully where Docker is absent, but fails on CI.
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
 * Best-effort check for a reachable Docker daemon.
 *
 * Prefer {@link requireDockerOrSkip} in test suites: this raw probe cannot tell
 * a contributor's Docker-less laptop (skip is fine) from a misconfigured CI
 * runner (skip is a silent loss of coverage).
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

/**
 * True when running on a CI lane. GitHub Actions sets `CI=true`; the explicit
 * falsey forms let a developer reproduce a local run inside a CI-ish shell.
 */
function isCiLane(): boolean {
  const ci = process.env['CI'];
  if (ci === undefined || ci === '') return false;
  return ci !== '0' && ci.toLowerCase() !== 'false';
}

/**
 * Docker gate for container-backed integration suites — the probe every suite
 * should call in its `beforeAll`.
 *
 * Returns `true` when a daemon is reachable. When one is NOT reachable the
 * behaviour deliberately differs by lane:
 *
 * - **Locally** it returns `false` so the suite can `skip()`, keeping the run
 *   green for contributors without Docker.
 * - **On CI** it THROWS. These suites are the only place some behaviour is
 *   observable at all — notably the real generated DDL, since the auth-server
 *   tests mock the repositories — so a daemon-less CI lane that skipped would
 *   report green while asserting nothing, which is exactly how a regression
 *   like qauth-labs/qauth#316 ships twice. A missing daemon on CI is a
 *   misconfigured runner, not a supported environment.
 *
 * @returns `true` when Docker is reachable, `false` when the caller should skip.
 * @throws When Docker is unreachable and `CI` is set.
 */
export async function requireDockerOrSkip(): Promise<boolean> {
  if (await isDockerAvailable()) return true;

  if (isCiLane()) {
    throw new Error(
      'Docker is not reachable but CI is set. Container-backed integration suites must never ' +
        'skip on CI: they are the only coverage for the real migrated schema, so skipping ' +
        'turns the run into a green no-op. Provision a Docker daemon on this runner ' +
        '(GitHub-hosted runners have one) or stop running the `test-integration` target here.'
    );
  }

  return false;
}
