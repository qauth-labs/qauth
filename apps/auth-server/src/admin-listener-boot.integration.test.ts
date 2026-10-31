/**
 * THE ADMIN LISTENER OF THE REAL ENTRY POINT (issue #511, ADR-019 Decisions 7
 * and 8).
 *
 * Each case starts `src/main.ts` under tsx, as the image runs it, as a child
 * process: a process, not `app()`, because `main.ts` builds the second
 * instance, binds it and stops it on a signal, and those are the properties.
 *
 * - With ADMIN_API_ENABLED=true, the process listens on the admin port, on
 *   loopback, then on the public port. The admin listener serves the admin OpenAPI
 *   document; the public listener answers 404 for every admin path; SIGTERM
 *   stops both and the process exits 0.
 * - With the admin port taken, the process exits 1 and never listens on the
 *   public port.
 * - With ADMIN_API_ENABLED unset (off by default until #517 and #520) or
 *   false, or without the admin role, nothing listens on the admin port.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */
import { type ChildProcess, spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { connect, createServer } from 'node:net';
import path from 'node:path';

import {
  applyQauthMigrations,
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
const REALM_PATH = '/admin/v1-rc.0/realms/018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';

/** One pino line of the server's log. */
interface LogLine {
  readonly level: number;
  readonly msg: string;
  readonly [field: string]: unknown;
}

interface StartedServer {
  lines(): LogLine[];
  readonly exited: Promise<number | null>;
  readonly child: ChildProcess;
  readonly port: number;
  readonly adminPort: number;
}

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

/**
 * A free port other than `taken`: each probe releases its port before it
 * resolves, so two probes in a row may be handed the same one.
 */
async function freePortOtherThan(taken: number): Promise<number> {
  for (;;) {
    const port = await freePort();
    if (port !== taken) return port;
  }
}

/** Whether something accepts a TCP connection on loopback `port`. */
function accepts(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => resolve(false));
  });
}

async function until(
  condition: () => boolean,
  what: string,
  server: StartedServer,
  timeoutMs = 60_000
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

describe('the admin listener of src/main.ts (#511, testcontainers)', () => {
  let postgres: StartedPostgres | undefined;
  let redis: StartedRedis | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const servers: StartedServer[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    postgres = await startPostgresContainer();
    redis = await startRedisContainer();
    await applyQauthMigrations(postgres.connectionString);
    jwt = await generateJwtPem();
  }, 180_000);

  afterEach(async () => {
    for (const server of servers.splice(0)) {
      if (server.child.exitCode === null && server.child.signalCode === null) {
        server.child.kill('SIGKILL');
        await server.exited;
      }
    }
  });

  afterAll(async () => {
    await redis?.stop();
    await postgres?.stop();
  });

  async function startServer(
    ctx: { skip: () => void },
    environment: Record<string, string> = {},
    ports: { adminPort?: number } = {}
  ): Promise<StartedServer> {
    if (!dockerUp || !postgres || !redis || !jwt) {
      ctx.skip();
      throw new Error('unreachable');
    }
    const port = await freePort();
    const adminPort = ports.adminPort ?? (await freePortOtherThan(port));
    const child = spawn(process.execPath, [TSX_CLI, 'src/main.ts'], {
      cwd: APP_ROOT,
      env: {
        PATH: process.env['PATH'] ?? '',
        ...REQUIRED_TEST_ENVIRONMENT,
        LOG_LEVEL: 'info',
        HOST: '127.0.0.1',
        PORT: String(port),
        // Off by default until #517 and #520: every case but the last turns
        // the listener on.
        ADMIN_API_ENABLED: 'true',
        ADMIN_API_PORT: String(adminPort),
        DATABASE_URL: postgres.connectionString,
        REDIS_URL: redis.connectionUrl,
        JWT_PRIVATE_KEY: jwt.privateKey,
        JWT_PUBLIC_KEY: jwt.publicKey,
        ...environment,
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
    const server = { lines: () => lines, exited, child, port, adminPort };
    servers.push(server);
    return server;
  }

  const logged = (server: StartedServer, prefix: string) => () =>
    server.lines().some((line) => line.msg.startsWith(prefix));

  it('serves the admin listener on its own loopback port, and stops it on SIGTERM', async (ctx) => {
    const server = await startServer(ctx);
    await until(logged(server, 'Server listening on '), 'the server to listen', server);

    // The admin listener bound first: a process that cannot serve its admin
    // API never takes public traffic.
    const messages = server.lines().map((line) => line.msg);
    const adminAt = messages.indexOf(`Admin API listening on http://127.0.0.1:${server.adminPort}`);
    expect(adminAt).toBeGreaterThanOrEqual(0);
    expect(adminAt).toBeLessThan(
      messages.indexOf(`Server listening on http://127.0.0.1:${server.port}`)
    );

    // The admin listener answers its own OpenAPI document. No admin operation
    // ships yet (#517), so the realm path is one no route serves; the
    // pipeline's refusals are `app/admin-listener.integration.test.ts`'s.
    const document = await fetch(`http://127.0.0.1:${server.adminPort}/admin/v1-rc.0/openapi.json`);
    expect(document.status).toBe(200);
    expect(await document.json()).toMatchObject({ info: { title: 'QAuth Admin API' } });
    const realm = await fetch(`http://127.0.0.1:${server.adminPort}${REALM_PATH}`);
    expect(realm.status).toBe(404);
    // No route serves them there, so the answer comes before any realm.
    for (const pathname of [REALM_PATH, '/admin/v1-rc.0/openapi.json']) {
      const onPublic = await fetch(`http://127.0.0.1:${server.port}${pathname}`);
      expect(onPublic.status).toBe(404);
      expect(await onPublic.json()).toMatchObject({ code: 'not_found' });
    }

    server.child.kill('SIGTERM');
    expect(await server.exited).toBe(0);
    expect(await accepts(server.adminPort)).toBe(false);
    expect(await accepts(server.port)).toBe(false);
  });

  it('never opens the public port when the admin port is taken, and exits non-zero', async (ctx) => {
    const squatter = createServer();
    const adminPort = await new Promise<number>((resolve, reject) => {
      squatter.once('error', reject);
      squatter.listen(0, '127.0.0.1', () => {
        const address = squatter.address();
        if (typeof address === 'object' && address !== null) resolve(address.port);
        else reject(new Error('no port'));
      });
    });
    try {
      const server = await startServer(ctx, {}, { adminPort });
      expect(await server.exited).toBe(1);

      const failure = server.lines().find((line) => line.msg === 'Failed to start server');
      expect(JSON.stringify(failure)).toContain('EADDRINUSE');
      expect(logged(server, 'Server listening on ')()).toBe(false);
    } finally {
      await new Promise((resolve) => squatter.close(resolve));
    }
  });

  it('opens no admin port by default, with ADMIN_API_ENABLED=false, or without the admin role', async (ctx) => {
    const environments: Record<string, string>[] = [
      // Blank is unset: the default.
      { ADMIN_API_ENABLED: '' },
      { ADMIN_API_ENABLED: 'false' },
      // A process with the signer, so it needs no signer service.
      { SERVICE_ROLES: 'web,api,signer,delivery' },
    ];
    for (const environment of environments) {
      const server = await startServer(ctx, environment);
      await until(logged(server, 'Server listening on '), 'the server to listen', server);

      expect(logged(server, 'Admin API listening')()).toBe(false);
      expect(await accepts(server.adminPort)).toBe(false);
      server.child.kill('SIGTERM');
      expect(await server.exited).toBe(0);
    }
  });
});
