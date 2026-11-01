import { isDockerAvailable, startSharedPostgres } from './lib/pg-testcontainer';
import { startSharedRedis } from './lib/redis-testcontainer';

/** The part of Vitest's `TestProject` this setup reads. */
interface GlobalSetupProject {
  readonly config: { readonly maxWorkers: number };
}

/**
 * Vitest global setup of `vitest.integration.config.mts`: the Postgres and
 * Redis servers the run's suites share.
 *
 * Starting a container, and migrating its database, took most of the time of
 * a suite, and every suite did it for itself. Now this setup starts the
 * servers once, migrates a template database once per Postgres server, and
 * points the suites at them through the environment
 * (`SHARED_POSTGRES_URLS_ENV`, `SHARED_POSTGRES_TEMPLATE_ENV`,
 * `SHARED_REDIS_URL_ENV`), which Vitest's workers inherit:
 *
 * - one Postgres server per worker slot (`maxWorkers` of them), on which
 *   `startPostgresContainer` gives each suite a database of its own. A slot
 *   runs one file at a time, so no two files on a server overlap, which the
 *   event store's transaction horizon needs (see `SHARED_POSTGRES_URLS_ENV`);
 * - one Redis server, on which `startRedisContainer` gives each suite a pair
 *   of logical databases no other suite is given.
 *
 * Without a reachable Docker daemon it starts nothing and fails nothing: the
 * suites find no shared server and call `requireDockerOrSkip()` as before,
 * which skips them locally and fails them on CI.
 *
 * It runs in Vitest's main process, once per `vitest` run: Nx runs each
 * project's `test-integration` target as a run of its own, with servers of
 * its own.
 */
export default async function setup(
  project: GlobalSetupProject
): Promise<(() => Promise<void>) | undefined> {
  if (!(await isDockerAvailable())) return undefined;

  const started = await Promise.allSettled([
    startSharedPostgres(project.config.maxWorkers),
    startSharedRedis(),
  ]);
  const servers = started.flatMap((result) =>
    result.status === 'fulfilled' ? [result.value] : []
  );
  const failure = started.find((result) => result.status === 'rejected');
  if (failure !== undefined) {
    await Promise.allSettled(servers.map((server) => server.stop()));
    throw failure.reason;
  }

  const env: Record<string, string> = Object.assign({}, ...servers.map((server) => server.env));
  Object.assign(process.env, env);

  return async () => {
    for (const key of Object.keys(env)) delete process.env[key];
    await Promise.all(servers.map((server) => server.stop()));
  };
}
