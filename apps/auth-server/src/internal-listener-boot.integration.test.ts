/**
 * THE INTERNAL LISTENER OF THE REAL ENTRY POINT (issue #496, ADR-019
 * Decision 8).
 *
 * Each case starts `src/main.ts` under tsx, as the image runs it, as a child
 * process, as `admin-listener-boot.integration.test.ts` does for the admin
 * listener: `main.ts` decides whether the internal listener runs, reads its
 * TLS files, binds it, reloads its files and stops it on a signal.
 *
 * - A split process holding the signer, with the internal TLS files, listens
 *   on the internal port with mutual TLS before the public port; a peer with
 *   a known certificate reaches it, one with no certificate fails the
 *   handshake, an unknown one gets 403; replacing the files changes the
 *   certificate it serves with no restart; SIGTERM stops it.
 * - Without the TLS files, the same process exits 1 naming each missing
 *   setting, never listens on the public port, and opens no internal port.
 * - A single process opens no internal port.
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

import { createInternalClient, type InternalClient } from './app/internal/client';
import { generateJwtPem, type PemKeyPair, REQUIRED_TEST_ENVIRONMENT } from './testing/e2e-harness';
import {
  createInternalPki,
  eventually,
  fingerprintOf,
  type InternalPki,
  servedFingerprint,
  tlsExchange,
  type TlsFileDirectory,
  writeTlsFiles,
} from './testing/internal-pki';

const APP_ROOT = path.resolve(process.cwd(), 'apps/auth-server');
const TSX_CLI = createRequire(path.join(APP_ROOT, 'package.json')).resolve('tsx/cli');
const SIGNER_SAN = 'spiffe://qauth.test/signer';
/** A path under the signer service's prefix; no route serves it until #497. */
const SIGNER_PATH = '/internal/signer/v1-rc.0/sign';

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
  readonly internalPort: number;
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

/** A free port none of `taken` is: each probe releases its port before it resolves. */
async function freePortOtherThan(...taken: number[]): Promise<number> {
  for (;;) {
    const port = await freePort();
    if (!taken.includes(port)) return port;
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

describe('the internal listener of src/main.ts (#496, testcontainers)', () => {
  let postgres: StartedPostgres | undefined;
  let redis: StartedRedis | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  let pki: InternalPki;
  let tls: TlsFileDirectory;
  const servers: StartedServer[] = [];
  const clients: InternalClient[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    postgres = await startPostgresContainer();
    redis = await startRedisContainer();
    await applyQauthMigrations(postgres.connectionString);
    jwt = await generateJwtPem();
    pki = createInternalPki();
    tls = writeTlsFiles(pki.issue({ uris: [SIGNER_SAN] }), pki.caPem);
  }, 180_000);

  afterEach(async () => {
    for (const client of clients.splice(0)) client.close();
    for (const server of servers.splice(0)) {
      if (server.child.exitCode === null && server.child.signalCode === null) {
        server.child.kill('SIGKILL');
        await server.exited;
      }
    }
  });

  afterAll(async () => {
    tls?.remove();
    await redis?.stop();
    await postgres?.stop();
  });

  /** The internal TLS settings of the signer's process. */
  function tlsSettings(): Record<string, string> {
    return {
      INTERNAL_TLS_CERT_PATH: tls.files.certPath,
      INTERNAL_TLS_KEY_PATH: tls.files.keyPath,
      INTERNAL_TLS_CA_PATH: tls.files.caPath,
      INTERNAL_PEER_ROLES: JSON.stringify({ 'spiffe://qauth.test/web': 'web' }),
    };
  }

  async function startServer(
    ctx: { skip: () => void },
    environment: Record<string, string> = {}
  ): Promise<StartedServer> {
    if (!dockerUp || !postgres || !redis || !jwt) {
      ctx.skip();
      throw new Error('unreachable');
    }
    const port = await freePort();
    const internalPort = await freePortOtherThan(port);
    const child = spawn(process.execPath, [TSX_CLI, 'src/main.ts'], {
      cwd: APP_ROOT,
      env: {
        PATH: process.env['PATH'] ?? '',
        ...REQUIRED_TEST_ENVIRONMENT,
        LOG_LEVEL: 'info',
        HOST: '127.0.0.1',
        PORT: String(port),
        INTERNAL_PORT: String(internalPort),
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
    const server = { lines: () => lines, exited, child, port, internalPort };
    servers.push(server);
    return server;
  }

  const logged = (server: StartedServer, prefix: string) => () =>
    server.lines().some((line) => line.msg.startsWith(prefix));

  /** A client of the server's internal listener, presenting `credentials`. */
  function clientOf(server: StartedServer, credentials: { cert: string; key: string }) {
    const client = createInternalClient({
      url: `https://127.0.0.1:${server.internalPort}`,
      ...credentials,
      ca: pki.caPem,
      expectedServerSan: SIGNER_SAN,
    });
    clients.push(client);
    return client;
  }

  it('serves mutual TLS on its own port on a split process holding the signer, reloads its files, and stops on SIGTERM', async (ctx) => {
    const server = await startServer(ctx, { SERVICE_ROLES: 'api,signer', ...tlsSettings() });
    await until(logged(server, 'Server listening on '), 'the server to listen', server);

    // The internal listener bound first: a process that cannot serve it never
    // takes public traffic.
    const messages = server.lines().map((line) => line.msg);
    const internalAt = messages.indexOf(
      `Internal listener listening on https://127.0.0.1:${server.internalPort} (mutual TLS)`
    );
    expect(internalAt).toBeGreaterThanOrEqual(0);
    expect(internalAt).toBeLessThan(
      messages.indexOf(`Server listening on http://127.0.0.1:${server.port}`)
    );

    // A known peer reaches the listener; no signer route ships yet (#497).
    const web = pki.issue({ uris: ['spiffe://qauth.test/web'] });
    const known = await clientOf(server, web).request({ method: 'POST', path: SIGNER_PATH });
    expect(known.status).toBe(404);
    expect(JSON.parse(known.body.toString())).toMatchObject({ code: 'not_found' });

    // A certificate from the CA whose SAN INTERNAL_PEER_ROLES does not map.
    const stranger = pki.issue({ uris: ['spiffe://qauth.test/stranger'] });
    const refused = await clientOf(server, stranger).request({ method: 'POST', path: SIGNER_PATH });
    expect(refused.status).toBe(403);
    expect(JSON.parse(refused.body.toString())).toMatchObject({ code: 'forbidden' });

    // No certificate: no HTTP answer at all.
    const target = { host: '127.0.0.1', port: server.internalPort };
    expect((await tlsExchange(target, { ca: pki.caPem }, SIGNER_PATH)).received).toBe('');

    // The public listener serves no internal path.
    const onPublic = await fetch(`http://127.0.0.1:${server.port}${SIGNER_PATH}`, {
      method: 'POST',
    });
    expect(onPublic.status).toBe(404);

    // A rotation on disk: the listener serves the new certificate, with no
    // restart, within its reload interval.
    const rotated = pki.issue({ uris: [SIGNER_SAN] });
    tls.replace(rotated, pki.caPem);
    await eventually(
      async () =>
        (await servedFingerprint(target, web, [pki.caPem])) === fingerprintOf(rotated.cert),
      20_000,
      250
    );
    await until(logged(server, 'Reloaded the internal TLS files'), 'the reload log line', server);
    expect(server.child.exitCode).toBeNull();

    server.child.kill('SIGTERM');
    expect(await server.exited).toBe(0);
    expect(await accepts(server.internalPort)).toBe(false);
    expect(await accepts(server.port)).toBe(false);
  });

  it('refuses to start a split process holding the signer without mutual TLS, naming each setting', async (ctx) => {
    const server = await startServer(ctx, { SERVICE_ROLES: 'api,signer' });
    expect(await server.exited).toBe(1);

    const failure = JSON.stringify(
      server.lines().find((line) => line.msg === 'Failed to start server')
    );
    for (const variable of [
      'INTERNAL_TLS_CERT_PATH',
      'INTERNAL_TLS_KEY_PATH',
      'INTERNAL_TLS_CA_PATH',
      'INTERNAL_PEER_ROLES',
    ]) {
      expect(failure).toContain(`${variable} is required`);
    }
    expect(failure).toContain('so the signer routes are not registered without it');
    expect(logged(server, 'Server listening on ')()).toBe(false);
    expect(logged(server, 'Internal listener listening')()).toBe(false);
    expect(await accepts(server.internalPort)).toBe(false);
  });

  it('opens no internal port in a single process, whatever its TLS settings', async (ctx) => {
    const server = await startServer(ctx, tlsSettings());
    await until(logged(server, 'Server listening on '), 'the server to listen', server);

    expect(logged(server, 'Internal listener listening')()).toBe(false);
    expect(await accepts(server.internalPort)).toBe(false);
    server.child.kill('SIGTERM');
    expect(await server.exited).toBe(0);
  });
});
