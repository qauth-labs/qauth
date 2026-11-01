import { availableParallelism } from 'node:os';

import { configDefaults, defineConfig } from 'vitest/config';

/**
 * True on a CI lane, read as `requireDockerOrSkip` reads it: `CI` set, and
 * not to `0` or `false`.
 */
function onCi(): boolean {
  const ci = process.env['CI'];
  return ci !== undefined && ci !== '' && ci !== '0' && ci.toLowerCase() !== 'false';
}

/**
 * How many integration files run at once in one `vitest` run.
 *
 * It is also the number of Postgres servers the global setup starts, one per
 * worker slot. `QAUTH_INTEGRATION_WORKERS` sets it. Otherwise, on CI, 3: the
 * `integration` job runs on a 4-vCPU, 16 GB runner, and Nx runs up to three
 * `test-integration` targets at once, each its own `vitest` run with its own
 * servers. Three runs of three workers keep the auth server's suites, which
 * boot the whole app and hash passwords, at about two workers per core while
 * the library suites, which mostly wait on Postgres, run beside them; each
 * worker stays well under 1 GB. Locally, half the cores and at most 4, so a
 * run leaves the machine usable.
 */
function integrationWorkers(): number {
  const configured = Number(process.env['QAUTH_INTEGRATION_WORKERS']);
  if (Number.isInteger(configured) && configured > 0) return configured;
  if (onCi()) return 3;
  return Math.max(1, Math.min(4, Math.floor(availableParallelism() / 2)));
}

/**
 * Integration test config (#167).
 *
 * Runs ONLY the Docker-backed `*.integration.test.ts` suites (testcontainers
 * Postgres and Redis) that the fast unit config (vitest.config.mts)
 * deliberately excludes. Kept separate so the unit suite + coverage gate stay
 * free of Postgres/Redis, and so the slow container suite is opt-in
 * (`test-integration` target / `pnpm test:integration`).
 *
 * Starting a container used to dominate: every file started its own Postgres
 * and Redis, migrated the database, and ran alone. Now the global setup
 * starts the servers once for the run: a Postgres server per worker slot,
 * each with a migrated template database, and one Redis server. Each file
 * gets a database of its own on its slot's Postgres server (a copy of the
 * template, or an empty one) and a pair of logical databases on the Redis
 * server, so files run side by side and share no state. A Postgres server
 * per slot, not one for the run, because a server's transaction horizon
 * spans its databases and the event store reads it (see
 * `SHARED_POSTGRES_URLS_ENV` in `@qauth-labs/shared-testing`). A suite that
 * stops a server, creates a cluster-wide object (a role) or relies on what
 * spans Redis databases asks for a private container instead
 * (`privateContainer`). Without Docker the setup starts nothing, and the
 * suites skip (locally) or fail (on CI) through `requireDockerOrSkip` as
 * before.
 *
 * A generous hookTimeout covers an image pull on a cold cache and the setup
 * of a suite that boots several nodes while other files run.
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    watch: false,
    // Vitest 5 clears every mock before each test by default. Kept off so a
    // call recorded in beforeAll or at module scope still counts, as in v4.
    clearMocks: false,
    include: ['**/*.integration.test.ts'],
    // Not the gitignored scratch directory, where the upgrade test (#475)
    // unpacks the baseline release's tree, its integration suites included
    // (see vitest.config.mts).
    exclude: [...configDefaults.exclude, 'tmp/**'],
    globalSetup: ['libs/shared/testing/src/integration-global-setup.ts'],
    fileParallelism: true,
    maxWorkers: integrationWorkers(),
    testTimeout: 60_000,
    hookTimeout: 180_000,
  },
});
