/**
 * THE AUTH SERVER'S MIGRATION CHECK AT BOOT (issue #474, ADR-018 §5).
 *
 * Each case starts the real entry point, `src/main.ts` under tsx as the image
 * runs it, as a child process against a database of its own: one missing the
 * last migration exits non-zero after the wait, naming it; one that catches
 * up during the wait starts; a current one and one with a migration newer
 * than this release start. A process, not `app()`, because the check runs in
 * `main.ts` before the app is registered, and the property is the exit.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */
import { type ChildProcess, spawn } from 'node:child_process';
import { rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import path from 'node:path';

import {
  appendQauthMigration,
  applyQauthMigrations,
  createPostgresDatabase,
  qauthMigrationsFolderWithFirst,
  qauthMigrationTags,
  requireDockerOrSkip,
  type StartedPostgres,
  type StartedRedis,
  startPostgresContainer,
  startRedisContainer,
} from '@qauth-labs/shared-testing';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { generateJwtPem, type PemKeyPair, REQUIRED_TEST_ENVIRONMENT } from './testing/e2e-harness';

const APP_ROOT = path.resolve(process.cwd(), 'apps/auth-server');
const TSX_CLI = createRequire(path.join(APP_ROOT, 'package.json')).resolve('tsx/cli');
const TAGS = qauthMigrationTags();
const LAST = TAGS[TAGS.length - 1] as string;

/** One pino line of the server's log. */
interface LogLine {
  readonly level: number;
  readonly msg: string;
  readonly time: number;
  readonly err?: { readonly type?: string; readonly message?: string };
  readonly [field: string]: unknown;
}

interface StartedServer {
  /** The log lines so far. */
  lines(): LogLine[];
  /** Resolves with the exit code once the process has exited. */
  readonly exited: Promise<number | null>;
  readonly child: ChildProcess;
}

const WARN = 40;
const ERROR = 50;

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() =>
        typeof address === 'object' && address !== null
          ? resolve(address.port)
          : reject(new Error('no port'))
      );
    });
  });
}

async function until(
  condition: () => boolean,
  what: string,
  server: StartedServer,
  timeoutMs = 45_000
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline || server.child.exitCode !== null) {
      throw new Error(
        `timed out waiting for ${what}; log so far:\n` +
          server
            .lines()
            .map((line) => JSON.stringify(line))
            .join('\n')
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

describe('migration check at boot (src/main.ts, testcontainers Postgres)', () => {
  let postgres: StartedPostgres | undefined;
  let redis: StartedRedis | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  let databases = 0;
  const folders: string[] = [];
  const servers: StartedServer[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    postgres = await startPostgresContainer();
    redis = await startRedisContainer();
    jwt = await generateJwtPem();
  }, 180_000);

  afterEach(async () => {
    for (const server of servers.splice(0)) {
      if (server.child.exitCode === null && server.child.signalCode === null) {
        server.child.kill('SIGKILL');
        await server.exited;
      }
    }
    for (const folder of folders.splice(0)) rmSync(folder, { recursive: true, force: true });
  });

  afterAll(async () => {
    await redis?.stop();
    await postgres?.stop();
  });

  /** A new, empty database on the container, by URL. */
  async function freshDatabase(ctx: { skip: () => void }): Promise<string> {
    if (!dockerUp || !postgres) {
      ctx.skip();
      throw new Error('unreachable');
    }
    return createPostgresDatabase(postgres.connectionString, `boot_check_${++databases}`);
  }

  /** A database with every migration but the last, as an older release left it. */
  async function databaseBehind(ctx: { skip: () => void }): Promise<string> {
    const url = await freshDatabase(ctx);
    const folder = qauthMigrationsFolderWithFirst(TAGS.length - 1);
    folders.push(folder);
    await applyQauthMigrations(url, folder);
    return url;
  }

  async function startServer(databaseUrl: string, waitMs: number): Promise<StartedServer> {
    if (!redis || !jwt) throw new Error('no infrastructure');
    const child = spawn(process.execPath, [TSX_CLI, 'src/main.ts'], {
      cwd: APP_ROOT,
      env: {
        PATH: process.env['PATH'] ?? '',
        ...REQUIRED_TEST_ENVIRONMENT,
        LOG_LEVEL: 'info',
        HOST: '127.0.0.1',
        PORT: String(await freePort()),
        // The admin listener (#511) binds a port of its own too.
        ADMIN_API_PORT: String(await freePort()),
        DATABASE_URL: databaseUrl,
        REDIS_URL: redis.connectionUrl,
        JWT_PRIVATE_KEY: jwt.privateKey,
        JWT_PUBLIC_KEY: jwt.publicKey,
        DB_MIGRATION_WAIT_MS: String(waitMs),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const lines: LogLine[] = [];
    let partial = '';
    child.stdout?.on('data', (chunk: Buffer) => {
      partial += chunk.toString('utf8');
      const complete = partial.split('\n');
      partial = complete.pop() ?? '';
      for (const line of complete) {
        try {
          lines.push(JSON.parse(line) as LogLine);
        } catch {
          // Not a log line.
        }
      }
    });
    child.stderr?.resume();
    const exited = new Promise<number | null>((resolve) =>
      child.on('exit', (code) => resolve(code))
    );
    const server = { lines: () => lines, exited, child };
    servers.push(server);
    return server;
  }

  const listening = (server: StartedServer) => () =>
    server.lines().some((line) => line.msg.startsWith('Server listening on '));
  const behindWarning = (server: StartedServer) =>
    server.lines().find((line) => line.level === WARN && line.msg.startsWith('The database lacks'));

  it('exits non-zero after the wait on a database missing a migration, naming it', async (ctx) => {
    const url = await databaseBehind(ctx);
    const waitMs = 1500;

    const server = await startServer(url, waitMs);
    const code = await server.exited;
    const exitedAt = Date.now();

    expect(code).toBe(1);
    const warning = behindWarning(server);
    expect(warning?.msg).toBe(
      `The database lacks 1 migration this release needs: ${LAST}. ` +
        `Waiting up to ${waitMs} ms for the migration runner.`
    );
    expect(warning?.['pendingMigrations']).toEqual([LAST]);
    const failure = server.lines().find((line) => line.level === ERROR);
    expect(failure?.msg).toBe('Failed to start server');
    expect(failure?.err?.type).toBe('MigrationsPendingError');
    expect(failure?.err?.message).toBe(
      `The database lacks 1 migration this release needs: ${LAST}. Waited 1.5 s for the ` +
        'migration runner. Run it against this database, then start the server again.'
    );
    // It waited the limit, and not much longer.
    const waited = exitedAt - (warning?.time ?? exitedAt);
    expect(waited).toBeGreaterThanOrEqual(waitMs - 100);
    expect(waited).toBeLessThan(waitMs + 10_000);
    expect(listening(server)()).toBe(false);
  });

  it('starts once the migration runner catches the database up during the wait', async (ctx) => {
    const url = await databaseBehind(ctx);

    const server = await startServer(url, 60_000);
    await until(() => behindWarning(server) !== undefined, 'the server to wait', server);
    await applyQauthMigrations(url);
    await until(listening(server), 'the server to listen', server);

    expect(
      server
        .lines()
        .some((line) => line.msg === 'The database now has every migration this release needs.')
    ).toBe(true);
    server.child.kill('SIGTERM');
    expect(await server.exited).toBe(0);
  });

  it('starts on a current database without waiting', async (ctx) => {
    const url = await freshDatabase(ctx);
    await applyQauthMigrations(url);

    const server = await startServer(url, 60_000);
    await until(listening(server), 'the server to listen', server);

    expect(behindWarning(server)).toBeUndefined();
    server.child.kill('SIGTERM');
    expect(await server.exited).toBe(0);
  });

  it('starts on a database ahead of this release, saying so', async (ctx) => {
    const url = await freshDatabase(ctx);
    const newer = qauthMigrationsFolderWithFirst(TAGS.length);
    folders.push(newer);
    appendQauthMigration(newer, '9999_from_a_newer_release', 'SELECT 1;');
    await applyQauthMigrations(url, newer);

    const server = await startServer(url, 0);
    await until(listening(server), 'the server to listen', server);

    const ahead = server.lines().find((line) => line.msg.includes('newer than this release'));
    expect(ahead?.level).toBe(WARN);
    expect(ahead?.msg).toBe(
      'The database has 1 migration newer than this release, from a newer one. ' +
        'Starting anyway, as during a rolling upgrade.'
    );
    expect(ahead?.['newerMigrations']).toBe(1);
    expect(behindWarning(server)).toBeUndefined();
    server.child.kill('SIGTERM');
    expect(await server.exited).toBe(0);
  });
});
