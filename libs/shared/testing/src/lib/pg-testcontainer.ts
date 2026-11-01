import { randomBytes } from 'node:crypto';

import { Client } from 'pg';
import { GenericContainer, type StartedTestContainer, Wait } from 'testcontainers';

import { applyQauthMigrations } from './drizzle-migrations';

/**
 * A database of one integration suite's own, on a throwaway Postgres server.
 *
 * Under `vitest.integration.config.mts` the server is one the integration
 * global setup started for the run (`integration-global-setup.ts`), shared
 * by the files that run one after another in this worker slot, and the
 * database is new: no other suite sees it. A suite that asked for
 * `privateContainer` has a server of its own.
 */
export interface StartedPostgres {
  /** node-postgres / drizzle compatible connection string of this suite's database. */
  connectionString: string;
  /** Host port the server listens on. */
  port: number;
  /**
   * Create a further empty database on the same server and return its URL,
   * for a suite that needs one database per case (issue #474). Each has a
   * name of its own, and {@link StartedPostgres.stop} drops it.
   */
  createDatabase(): Promise<string>;
  /**
   * Release what the suite was given. On a shared server it drops the
   * suite's databases; a private container is stopped and removed.
   */
  stop(): Promise<void>;
}

/** What {@link startPostgresContainer} hands a suite. */
export interface StartPostgresOptions {
  /**
   * `'empty'` (the default): a database with nothing in it, for a suite that
   * applies migrations itself, all or some of them. `'migrated'`: every
   * generated migration applied, a copy of the server's migrated template.
   */
  readonly schema?: 'empty' | 'migrated';
  /**
   * A Postgres container of the suite's own instead of a database on a
   * shared server. For a suite that stops, kills, pauses or restarts the
   * server, changes a server-wide setting, terminates backends it does not
   * own, or creates a cluster-wide object (a role, a tablespace): on a
   * shared server that would reach the suites that run on it after this one.
   */
  readonly privateContainer?: boolean;
}

/** Postgres image — pinned to match docker-compose (`postgres:18-alpine`). */
export const POSTGRES_IMAGE = 'postgres:18-alpine';

const POSTGRES_USER = 'qauth_test';
const POSTGRES_PASSWORD = 'qauth_test';
const POSTGRES_DB = 'qauth_test';

/**
 * The environment variable that names the run's shared Postgres servers: one
 * URL per Vitest worker slot (`VITEST_POOL_ID`), comma-separated, each the
 * URL of a server's maintenance database (`postgres`) as the superuser. The
 * integration global setup sets it; unset, every suite gets a private
 * container, as before the servers were shared.
 *
 * One server per slot, not one for the run: a server's transaction horizon
 * (`pg_snapshot_xmin(pg_current_snapshot())`) spans its databases, and the
 * event store reads it to decide which events are final (event delivery
 * fan-out, event retention). A write transaction open in one suite's
 * database would hold back another's events. A slot runs one file at a
 * time, so the files on a server follow one another and never overlap.
 */
export const SHARED_POSTGRES_URLS_ENV = 'QAUTH_TEST_SHARED_POSTGRES_URLS';

/** The environment variable that names the migrated template database on those servers. */
export const SHARED_POSTGRES_TEMPLATE_ENV = 'QAUTH_TEST_SHARED_POSTGRES_TEMPLATE';

/** The migrated template's name on a shared server. */
const TEMPLATE_DATABASE = 'qauth_template';

/**
 * Settings of a shared server. Durability is off: the server lives for one
 * run, and a crash loses the run either way.
 */
const SHARED_SERVER_SETTINGS: readonly string[] = [
  'fsync=off',
  'synchronous_commit=off',
  'full_page_writes=off',
];

async function startServer(
  database: string,
  settings: readonly string[] = []
): Promise<{ container: StartedTestContainer; url: (database: string) => string }> {
  let builder = new GenericContainer(POSTGRES_IMAGE)
    .withEnvironment({ POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB: database })
    .withExposedPorts(5432)
    // Postgres logs "ready to accept connections" twice (init + final boot);
    // wait for the second so we connect only once it is genuinely ready.
    .withWaitStrategy(Wait.forLogMessage(/database system is ready to accept connections/, 2))
    .withStartupTimeout(120_000);
  if (settings.length > 0) {
    builder = builder.withCommand(['postgres', ...settings.flatMap((setting) => ['-c', setting])]);
  }
  const container = await builder.start();
  const host = container.getHost();
  const port = container.getMappedPort(5432);
  return {
    container,
    url: (name) => `postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${host}:${port}/${name}`,
  };
}

/** The same server's URL, for another database. */
function databaseUrl(connectionString: string, name: string): string {
  const url = new URL(connectionString);
  url.pathname = `/${name}`;
  return url.toString();
}

/** A database name no other suite of the run holds. */
function uniqueDatabaseName(): string {
  return `qauth_${randomBytes(8).toString('hex')}`;
}

async function runStatements(connectionString: string, statements: readonly string[]) {
  const client = new Client({ connectionString });
  await client.connect();
  try {
    for (const statement of statements) await client.query(statement);
  } finally {
    await client.end();
  }
}

/** One shared server: a container with a migrated template database. */
async function startSharedServer(): Promise<{ admin: string; stop(): Promise<void> }> {
  const { container, url } = await startServer('postgres', SHARED_SERVER_SETTINGS);
  try {
    const admin = url('postgres');
    await runStatements(admin, [`CREATE DATABASE ${TEMPLATE_DATABASE}`]);
    await applyQauthMigrations(url(TEMPLATE_DATABASE));
    await runStatements(admin, [
      `ALTER DATABASE ${TEMPLATE_DATABASE} WITH IS_TEMPLATE true ALLOW_CONNECTIONS false`,
    ]);
    return {
      admin,
      async stop(): Promise<void> {
        await container.stop();
      },
    };
  } catch (error) {
    await container.stop();
    throw error;
  }
}

/**
 * Start the run's shared Postgres servers, for the integration global setup:
 * `count` containers (one per worker slot, see {@link SHARED_POSTGRES_URLS_ENV})
 * with {@link SHARED_SERVER_SETTINGS}, each with a template database that has
 * every generated migration applied.
 *
 * A template is closed to connections once migrated (`ALLOW_CONNECTIONS
 * false`), so a `CREATE DATABASE … TEMPLATE` never meets a session on it, the
 * one thing that makes such a copy fail.
 *
 * @returns the environment that points suites at the servers, and their stop.
 */
export async function startSharedPostgres(count: number): Promise<{
  env: Record<string, string>;
  stop(): Promise<void>;
}> {
  const started = await Promise.allSettled(
    Array.from({ length: Math.max(1, count) }, () => startSharedServer())
  );
  const servers = started.flatMap((result) =>
    result.status === 'fulfilled' ? [result.value] : []
  );
  const stop = async () => {
    await Promise.all(servers.map((server) => server.stop()));
  };
  const failure = started.find((result) => result.status === 'rejected');
  if (failure !== undefined) {
    await stop();
    throw failure.reason;
  }
  return {
    env: {
      [SHARED_POSTGRES_URLS_ENV]: servers.map((server) => server.admin).join(','),
      [SHARED_POSTGRES_TEMPLATE_ENV]: TEMPLATE_DATABASE,
    },
    stop,
  };
}

/**
 * The maintenance database URL of the shared server of this worker's slot,
 * or `undefined` when no shared server was started.
 */
function sharedServerOfThisWorker(): string | undefined {
  const urls = (process.env[SHARED_POSTGRES_URLS_ENV] ?? '').split(',').filter(Boolean);
  if (urls.length === 0) return undefined;
  const slot = Number(process.env['VITEST_POOL_ID'] ?? '1');
  return urls[((Number.isInteger(slot) && slot > 0 ? slot : 1) - 1) % urls.length];
}

/** A suite's databases on a shared server, `admin` being its maintenance database URL. */
async function createSharedDatabase(
  admin: string,
  template: string | undefined
): Promise<StartedPostgres> {
  const name = uniqueDatabaseName();
  // template0 for an empty database: like the migrated template it takes no
  // connections, so no session on it can make the copy fail.
  await runStatements(admin, [`CREATE DATABASE ${name} TEMPLATE ${template ?? 'template0'}`]);
  const owned = [name];
  return {
    connectionString: databaseUrl(admin, name),
    port: Number(new URL(admin).port),
    async createDatabase(): Promise<string> {
      const further = uniqueDatabaseName();
      await runStatements(admin, [`CREATE DATABASE ${further} TEMPLATE template0`]);
      owned.push(further);
      return databaseUrl(admin, further);
    },
    async stop(): Promise<void> {
      // FORCE ends whatever session the suite left open on them.
      await runStatements(
        admin,
        owned.splice(0).map((database) => `DROP DATABASE IF EXISTS ${database} WITH (FORCE)`)
      );
    },
  };
}

async function startPrivatePostgres(schema: 'empty' | 'migrated'): Promise<StartedPostgres> {
  const { container, url } = await startServer(POSTGRES_DB);
  const connectionString = url(POSTGRES_DB);
  try {
    if (schema === 'migrated') await applyQauthMigrations(connectionString);
  } catch (error) {
    await container.stop();
    throw error;
  }
  return {
    connectionString,
    port: container.getMappedPort(5432),
    createDatabase: () => createPostgresDatabase(connectionString, uniqueDatabaseName()),
    async stop(): Promise<void> {
      await container.stop();
    },
  };
}

/**
 * A Postgres 18 database for one integration suite.
 *
 * Under the integration config it is a new database on the shared server
 * of this worker slot (see {@link SHARED_POSTGRES_URLS_ENV}): empty, or a
 * copy of the migrated template with `schema: 'migrated'`, which saves
 * applying every migration again. With `privateContainer`, or when no shared
 * server was started, it is a container of the suite's own, as every suite
 * had one before the servers were shared.
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
 * const pg = await startPostgresContainer({ schema: 'migrated' });
 * // ... run tests against pg.connectionString ...
 * await pg.stop();
 * ```
 */
export async function startPostgresContainer(
  options: StartPostgresOptions = {}
): Promise<StartedPostgres> {
  const schema = options.schema ?? 'empty';
  const admin = sharedServerOfThisWorker();
  const template = process.env[SHARED_POSTGRES_TEMPLATE_ENV];
  if (options.privateContainer === true || admin === undefined || !template) {
    return startPrivatePostgres(schema);
  }
  return createSharedDatabase(admin, schema === 'migrated' ? template : undefined);
}

/**
 * Create an empty database on the server `connectionString` points at and
 * return its URL, for a suite that needs one database per case (issue #474).
 * Prefer {@link StartedPostgres.createDatabase}, which picks a name no other
 * suite holds and drops the database again.
 *
 * @param name - a plain lower-case identifier; it is not quoted.
 */
export async function createPostgresDatabase(
  connectionString: string,
  name: string
): Promise<string> {
  if (!/^[a-z_][a-z0-9_]*$/.test(name)) throw new Error(`not a plain database name: ${name}`);
  await runStatements(connectionString, [`CREATE DATABASE ${name}`]);
  return databaseUrl(connectionString, name);
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
