import {
  closeSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import {
  type AddressInfo,
  createServer as createTcpServer,
  type Server,
  type Socket,
} from 'node:net';
import { platform, tmpdir } from 'node:os';
import { join } from 'node:path';
import tls, { getCACertificates, setDefaultCACertificates } from 'node:tls';

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { explicitCurveCertificate, serverFirstFlight } from '../testing/hostile-handshake';
import { createTestCertificate } from '../testing/test-certificate';
import {
  dialPinned,
  exchange,
  type ExchangeJob,
  type ExchangeOutcome,
  FETCH_PROCESS_TAG,
} from './exchange';
import {
  createProcessPool,
  egressPoolStats,
  opensslSetup,
  parseFetchProcessMessage,
  type ProcessPool,
  sharedProcessPool,
} from './process-pool';
import { NODE_TRANSPORT } from './transport';

/*
 * The pool of fetch processes, with real processes against local servers. The
 * egress client's address checks run before the pool and have their own
 * suite, so these jobs hand the pool 127.0.0.1 as a checked address.
 *
 * A fetch process trusts what this process trusts when it starts, so the
 * servers' test CA is added to this process's trust store first.
 */

const LINUX = platform() === 'linux';

let trustedBefore: string[];
let ca: ReturnType<typeof createTestCertificate>;
let leaf: ReturnType<typeof createTestCertificate>;
let okServer: HttpsServer;
let okPort: number;
let okRequests: { url: string; host: string | undefined; body: string }[];
let okHandler: (req: IncomingMessage, body: Buffer, res: ServerResponse) => void;

/**
 * A TLS server that stalls mid-handshake: it reads the ClientHello, sends the
 * first bytes of a ServerHello record and nothing more.
 */
let stallServer: Server;
let stallPort: number;
const stallSockets = new Set<Socket>();
let stallOpen = 0;
let stallMostOpen = 0;
let stallClosed = 0;

const respond: typeof okHandler = (_req, _body, res) => {
  res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'max-age=60' });
  res.end('ok');
};

beforeAll(async () => {
  ca = createTestCertificate({ subject: 'pool test CA' });
  leaf = createTestCertificate({
    subject: 'egress.test',
    issuer: ca,
    dnsNames: ['egress.test', '*.egress.test'],
  });
  trustedBefore = getCACertificates('default');
  setDefaultCACertificates([...trustedBefore, ca.pem]);

  okServer = createHttpsServer({ key: leaf.keyPem, cert: leaf.pem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      okRequests.push({ url: req.url ?? '', host: req.headers.host, body: body.toString() });
      okHandler(req, body, res);
    });
  });
  await new Promise<void>((resolve) => okServer.listen(0, '127.0.0.1', resolve));
  okPort = (okServer.address() as AddressInfo).port;

  stallServer = createTcpServer((socket) => {
    stallSockets.add(socket);
    stallOpen += 1;
    stallMostOpen = Math.max(stallMostOpen, stallOpen);
    socket.on('error', () => undefined);
    socket.once('data', () => {
      // A handshake record of 122 bytes announced, a ServerHello begun.
      socket.write(Buffer.from([0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00]));
    });
    socket.resume();
    socket.on('close', () => {
      stallSockets.delete(socket);
      stallOpen -= 1;
      stallClosed += 1;
    });
  });
  await new Promise<void>((resolve) => stallServer.listen(0, '127.0.0.1', resolve));
  stallPort = (stallServer.address() as AddressInfo).port;
});

afterAll(async () => {
  setDefaultCACertificates(trustedBefore);
  for (const socket of stallSockets) socket.destroy();
  okServer.closeAllConnections();
  await Promise.all([
    new Promise<void>((resolve) => okServer.close(() => resolve())),
    new Promise<void>((resolve) => stallServer.close(() => resolve())),
  ]);
});

let pools: ProcessPool[] = [];

/** A pool closed after the test. */
const pool = (...args: Parameters<typeof createProcessPool>): ProcessPool => {
  const created = createProcessPool(...args);
  pools.push(created);
  return created;
};

beforeEach(() => {
  okRequests = [];
  okHandler = respond;
  stallMostOpen = stallOpen;
  stallClosed = 0;
});

afterEach(async () => {
  await Promise.all(pools.map((p) => p.close()));
  pools = [];
  if (LINUX) expect(fetchProcessPids()).toEqual([]);
});

const job = (hostname: string, port: number, extra: Partial<ExchangeJob> = {}): ExchangeJob => ({
  hostname,
  port,
  literalFamily: 0,
  path: '/doc?x=1',
  addresses: [{ address: '127.0.0.1', family: 4 }],
  method: 'GET',
  headers: { 'user-agent': 'pool-test' },
  body: undefined,
  connectTimeoutMs: 5_000,
  maxResponseBytes: 64 * 1024,
  ...extra,
});

const okJob = (extra: Partial<ExchangeJob> = {}): ExchangeJob =>
  job('ok.egress.test', okPort, extra);
const stallJob = (hostname: string, extra: Partial<ExchangeJob> = {}): ExchangeJob =>
  job(hostname, stallPort, extra);

const within = (ms: number): AbortSignal => AbortSignal.timeout(ms);

/** Resolves once `check` holds, polling every 10 ms for up to 5 s. */
async function until(check: () => boolean): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (!check()) {
    if (Date.now() > deadline) throw new Error('condition not met in time');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

const text = (outcome: ExchangeOutcome): string =>
  outcome.kind === 'response' ? Buffer.from(outcome.body).toString() : outcome.message;

/** The fetch processes this process started (Linux: read from /proc). */
function fetchProcessPids(): number[] {
  const pids: number[] = [];
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const stat = readFileSync(`/proc/${entry}/stat`, 'utf8');
      // `pid (comm) state ppid …`; the command name may contain spaces.
      const ppid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
      if (ppid !== process.pid) continue;
      const argv = readFileSync(`/proc/${entry}/cmdline`, 'utf8').split('\0');
      if (argv.includes(FETCH_PROCESS_TAG)) pids.push(Number(entry));
    } catch {
      // Gone between the listing and the read.
    }
  }
  return pids;
}

/** Where each open descriptor of process `pid` points (Linux). */
function openFiles(pid: number | 'self'): Map<string, string> {
  const files = new Map<string, string>();
  for (const fd of readdirSync(`/proc/${pid}/fd`)) {
    try {
      files.set(fd, readlinkSync(`/proc/${pid}/fd/${fd}`));
    } catch {
      // Closed between the listing and the read.
    }
  }
  return files;
}

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

describe('fetch processes (integration: real processes, local TLS servers)', () => {
  it('runs an exchange in a fetch process that trusts what this process trusts', async () => {
    const fetches = pool();
    const outcome = await fetches.exchange(okJob(), within(5_000));
    expect(outcome).toMatchObject({
      kind: 'response',
      status: 200,
      location: undefined,
      headers: { 'content-type': 'text/plain', 'cache-control': 'max-age=60' },
    });
    expect(text(outcome)).toBe('ok');
    expect(okRequests).toEqual([{ url: '/doc?x=1', host: `ok.egress.test:${okPort}`, body: '' }]);
    expect(fetches.stats()).toEqual({
      processes: 1,
      busy: 0,
      waiting: 0,
      deadlineKills: 0,
      maxProcesses: 8,
    });
    if (LINUX) expect(fetchProcessPids()).toHaveLength(1);
  });

  it('sends the request body and reuses an idle process for the next call', async () => {
    okHandler = (_req, body, res) => res.end(`got ${body.length} bytes`);
    const fetches = pool();
    const pids: number[][] = [];
    for (const size of [3, 70_000]) {
      const outcome = await fetches.exchange(
        okJob({ method: 'POST', body: new Uint8Array(size).fill(0x61) }),
        within(5_000)
      );
      expect(text(outcome)).toBe(`got ${size} bytes`);
      if (LINUX) pids.push(fetchProcessPids());
    }
    expect(fetches.stats().processes).toBe(1);
    if (LINUX) expect(pids[1]).toEqual(pids[0]);
  });

  it('kills a process whose TLS handshake stalls, at the connect deadline, while another host is served', async () => {
    const fetches = pool();
    const started = performance.now();
    const stalled = fetches.exchange(
      stallJob('slow.stall.test', { connectTimeoutMs: 800 }),
      within(10_000)
    );
    await until(() => stallOpen === 1);
    const stalledPids = LINUX ? fetchProcessPids() : [];

    // Meanwhile another host is served, by another process.
    const other = await fetches.exchange(okJob(), within(5_000));
    expect(text(other)).toBe('ok');
    expect(performance.now() - started).toBeLessThan(800);
    expect(fetches.stats()).toMatchObject({ processes: 2, busy: 1 });

    const outcome = await stalled;
    const elapsed = performance.now() - started;
    expect(outcome).toEqual({
      kind: 'failed',
      reason: 'timeout',
      message: 'egress to slow.stall.test failed: the connection timed out',
    });
    // The pool's deadline ended it, not the process's own timer, which runs a
    // second longer and would have answered without a kill.
    expect(elapsed).toBeGreaterThanOrEqual(790);
    expect(elapsed).toBeLessThan(3_000);
    expect(fetches.stats().deadlineKills).toBe(1);
    // The connection closes with the process that held it.
    await until(() => stallClosed === 1);
    await until(() => fetches.stats().processes === 1);
    if (LINUX) {
      expect(stalledPids).toHaveLength(1);
      expect(alive(stalledPids[0])).toBe(false);
      expect(fetchProcessPids()).not.toContain(stalledPids[0]);
    }

    // The pool goes on with the process that is left, and starts fresh ones.
    const after = await Promise.all([
      fetches.exchange(okJob(), within(5_000)),
      fetches.exchange(okJob(), within(5_000)),
    ]);
    expect(after.map(text)).toEqual(['ok', 'ok']);
    expect(fetches.stats()).toMatchObject({ processes: 2, busy: 0, deadlineKills: 1 });
  });

  it('kills a process that a host keeps inside OpenSSL, at the deadline, while another host is served', async () => {
    // Twelve certificates OpenSSL decodes in one synchronous call of several
    // seconds (ANT-2026-3OJSXV7G): no timer of the process that runs it
    // fires meanwhile, and a worker thread there kept its slot until the end.
    const flight = serverFirstFlight(Array.from({ length: 12 }, () => explicitCurveCertificate()));
    let flightSent = false;
    const hostile = createTcpServer((socket) => {
      let received = Buffer.alloc(0);
      socket.on('error', () => undefined);
      socket.on('data', (bytes: Buffer) => {
        if (flightSent) return;
        received = Buffer.concat([received, bytes]);
        // The whole ClientHello record, then the flight, once.
        if (received.length < 5 || received.length < 5 + received.readUInt16BE(3)) return;
        socket.write(flight, () => {
          flightSent = true;
        });
      });
    });
    await new Promise<void>((resolve) => hostile.listen(0, '127.0.0.1', resolve));
    try {
      const fetches = pool();
      const started = performance.now();
      const stuck = fetches.exchange(
        job('slow.hostile.test', (hostile.address() as AddressInfo).port, {
          connectTimeoutMs: 1_000,
        }),
        within(10_000)
      );
      await until(() => flightSent);
      expect(text(await fetches.exchange(okJob(), within(5_000)))).toBe('ok');

      await expect(stuck).resolves.toEqual({
        kind: 'failed',
        reason: 'timeout',
        message: 'egress to slow.hostile.test failed: the connection timed out',
      });
      expect(fetches.stats().deadlineKills).toBe(1);
      // The process is gone at the deadline, seconds before OpenSSL would
      // have returned (about 0.4 s per certificate).
      await until(() => fetches.stats().processes === 1);
      expect(performance.now() - started).toBeLessThan(3_000);
    } finally {
      await new Promise<void>((resolve) => hostile.close(() => resolve()));
    }
  });

  it('kills a process whose call passes its total deadline', async () => {
    okHandler = (_req, _body, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      const drip = setInterval(() => res.write('.'), 50);
      res.on('close', () => clearInterval(drip));
    };
    const fetches = pool();
    const started = performance.now();
    const outcome = await fetches.exchange(okJob(), within(600));
    expect(outcome).toEqual({
      kind: 'failed',
      reason: 'timeout',
      message: 'egress to ok.egress.test failed: the call timed out',
    });
    expect(performance.now() - started).toBeLessThan(3_000);
    expect(fetches.stats().deadlineKills).toBe(1);
    await until(() => fetches.stats().processes === 0);
  });

  it('holds the calls to many host names of one stalling server to the per-family bound', async () => {
    const fetches = pool({ maxProcesses: 8, maxProcessesPerFamily: 2, maxWaitingPerFamily: 8 });
    const controller = new AbortController();
    const calls = Array.from({ length: 10 }, (_, i) =>
      fetches.exchange(
        stallJob(`h${i}.stall.test`, { connectTimeoutMs: 30_000 }),
        controller.signal
      )
    );
    await until(() => stallOpen === 2);
    expect(fetches.stats()).toMatchObject({ busy: 2, waiting: 8 });

    // The family's queue is full: one more name of it is refused at once.
    await expect(fetches.exchange(stallJob('h10.stall.test'), within(5_000))).resolves.toEqual({
      kind: 'failed',
      reason: 'busy',
      message: 'egress to h10.stall.test failed: too many calls in progress',
    });
    // Another host still has the other processes.
    expect(text(await fetches.exchange(okJob(), within(5_000)))).toBe('ok');
    expect(stallMostOpen).toBe(2);

    // At the deadline the two running calls' processes are killed and the
    // waiting calls leave the queue; none of them reaches the server.
    controller.abort();
    const outcomes = await Promise.all(calls);
    expect(outcomes.every((o) => o.kind === 'failed' && o.reason === 'timeout')).toBe(true);
    expect(fetches.stats()).toMatchObject({ waiting: 0, deadlineKills: 2 });
    await until(() => stallClosed === 2);
    expect(stallMostOpen).toBe(2);
  });

  it('refuses a call at once when the whole queue is full', async () => {
    const fetches = pool({ maxProcesses: 1, maxWaiting: 1 });
    const controller = new AbortController();
    const running = fetches.exchange(
      stallJob('a.stall.test', { connectTimeoutMs: 30_000 }),
      controller.signal
    );
    await until(() => stallOpen === 1);
    const queued = fetches.exchange(okJob(), controller.signal);
    expect(fetches.stats()).toMatchObject({ busy: 1, waiting: 1 });
    await expect(
      fetches.exchange(job('b.example.test', okPort), within(5_000))
    ).resolves.toMatchObject({
      kind: 'failed',
      reason: 'busy',
    });
    controller.abort();
    await expect(running).resolves.toMatchObject({ reason: 'timeout' });
    await expect(queued).resolves.toMatchObject({ reason: 'timeout' });
    expect(okRequests).toEqual([]);
  });

  it('starts a waiting call when a process is free', async () => {
    const fetches = pool({ maxProcesses: 1 });
    const first = fetches.exchange(
      stallJob('a.stall.test', { connectTimeoutMs: 300 }),
      within(5_000)
    );
    await until(() => stallOpen === 1);
    const second = fetches.exchange(okJob(), within(5_000));
    expect(fetches.stats().waiting).toBe(1);
    await expect(first).resolves.toMatchObject({ reason: 'timeout' });
    expect(text(await second)).toBe('ok');
  });

  it('lets an idle process exit after the idle timeout', async () => {
    const fetches = pool({ idleTimeoutMs: 150 });
    expect(text(await fetches.exchange(okJob(), within(5_000)))).toBe('ok');
    expect(fetches.stats().processes).toBe(1);
    await until(() => fetches.stats().processes === 0);
    expect(fetches.stats().deadlineKills).toBe(0);
  });

  it('runs an exchange with the TLS defaults of this process', async () => {
    // A server that speaks TLS 1.2 at most.
    const old = createHttpsServer(
      { key: leaf.keyPem, cert: leaf.pem, maxVersion: 'TLSv1.2' },
      (_req, res) => res.end('old')
    );
    await new Promise<void>((resolve) => old.listen(0, '127.0.0.1', resolve));
    const port = (old.address() as AddressInfo).port;
    const minVersion = tls.DEFAULT_MIN_VERSION;
    try {
      expect(text(await pool().exchange(job('old.egress.test', port), within(5_000)))).toBe('old');
      // As `--tls-min-v1.3` would set it. A process started now takes it.
      tls.DEFAULT_MIN_VERSION = 'TLSv1.3';
      const outcome = await pool().exchange(job('old.egress.test', port), within(5_000));
      expect(outcome).toMatchObject({ kind: 'failed', reason: 'network' });
    } finally {
      tls.DEFAULT_MIN_VERSION = minVersion;
      old.closeAllConnections();
      await new Promise<void>((resolve) => old.close(() => resolve()));
    }
  });

  it('uses OpenSSL’s trust store when this process is set to', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'egress-openssl-'));
    writeFileSync(join(dir, 'ca.pem'), ca.pem);
    const before = { options: process.env['NODE_OPTIONS'], file: process.env['SSL_CERT_FILE'] };
    const restore = (name: string, value: string | undefined): void => {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    };
    // This process no longer trusts the test CA, so neither does a process
    // that takes its trust store.
    setDefaultCACertificates(trustedBefore);
    try {
      await expect(pool().exchange(okJob(), within(5_000))).resolves.toMatchObject({
        kind: 'failed',
        reason: 'network',
      });
      // As a server started with NODE_OPTIONS=--use-openssl-ca and
      // SSL_CERT_FILE would see them.
      process.env['NODE_OPTIONS'] = `${before.options ?? ''} --use-openssl-ca`.trim();
      process.env['SSL_CERT_FILE'] = join(dir, 'ca.pem');
      expect(text(await pool().exchange(okJob(), within(5_000)))).toBe('ok');
    } finally {
      restore('NODE_OPTIONS', before.options);
      restore('SSL_CERT_FILE', before.file);
      setDefaultCACertificates([...trustedBefore, ca.pem]);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns a request Node refuses to send as a failure, with its reason', async () => {
    const refused = {
      kind: 'failed',
      reason: 'network',
      message: 'egress to ok.egress.test failed: Request path contains unescaped characters',
    };
    await expect(exchange(okJob({ path: '/a b' }), dialPinned, within(5_000))).resolves.toEqual(
      refused
    );
    await expect(pool().exchange(okJob({ path: '/a b' }), within(5_000))).resolves.toEqual(refused);
  });

  it('returns a TLS failure from the process with its host-only message', async () => {
    const fetches = pool();
    // The certificate does not cover this name.
    const outcome = await fetches.exchange(job('ok.elsewhere.test', okPort), within(5_000));
    expect(outcome).toMatchObject({ kind: 'failed', reason: 'network' });
    expect(text(outcome)).toMatch(/^egress to ok\.elsewhere\.test failed: /);
    expect(fetches.stats()).toMatchObject({ processes: 1, deadlineKills: 0 });
  });

  it('refuses calls once closed and leaves no process behind', async () => {
    const fetches = pool();
    expect(text(await fetches.exchange(okJob(), within(5_000)))).toBe('ok');
    await fetches.close();
    expect(fetches.stats().processes).toBe(0);
    await expect(fetches.exchange(okJob(), within(5_000))).resolves.toMatchObject({
      kind: 'failed',
      reason: 'network',
    });
    if (LINUX) expect(fetchProcessPids()).toEqual([]);
  });

  it('runs the egress client’s exchanges in the shared pool', async () => {
    expect(egressPoolStats().processes).toBe(0);
    const outcome = await NODE_TRANSPORT.exchange(okJob(), within(5_000));
    expect(text(outcome)).toBe('ok');
    expect(egressPoolStats()).toMatchObject({ processes: 1, busy: 0, maxProcesses: 8 });
    await sharedProcessPool().close();
    expect(egressPoolStats().processes).toBe(0);
  });
});

describe.skipIf(!LINUX)('what a fetch process inherits (integration, Linux /proc)', () => {
  it('ends the call of a process that dies, and starts a fresh one', async () => {
    const fetches = pool();
    const call = fetches.exchange(
      stallJob('a.stall.test', { connectTimeoutMs: 30_000 }),
      within(10_000)
    );
    await until(() => stallOpen === 1);
    const [pid] = fetchProcessPids();
    process.kill(pid, 'SIGKILL');
    await expect(call).resolves.toEqual({
      kind: 'failed',
      reason: 'network',
      message: 'egress to a.stall.test failed: the fetch process ended without a result',
    });
    expect(fetches.stats()).toMatchObject({ processes: 0, deadlineKills: 0 });
    expect(text(await fetches.exchange(okJob(), within(5_000)))).toBe('ok');
  });

  it('starts a fetch process with none of this process’s environment', async () => {
    process.env['QAUTH_POOL_TEST_SECRET'] = 'must-not-leak';
    try {
      const fetches = pool();
      expect(text(await fetches.exchange(okJob(), within(5_000)))).toBe('ok');
      const [pid] = fetchProcessPids();
      const environ = readFileSync(`/proc/${pid}/environ`, 'utf8').split('\0').filter(Boolean);
      // Only the two variables Node adds for the IPC channel, which the
      // process removes from process.env at start.
      expect(environ.map((entry) => entry.slice(0, entry.indexOf('='))).sort()).toEqual([
        'NODE_CHANNEL_FD',
        'NODE_CHANNEL_SERIALIZATION_MODE',
      ]);
      expect(environ.join('\n')).not.toContain('must-not-leak');
      expect(Object.keys(process.env).length).toBeGreaterThan(2);
      // Nor the flags this process runs with.
      const argv = readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0');
      for (const flag of process.execArgv) expect(argv).not.toContain(flag);
    } finally {
      delete process.env['QAUTH_POOL_TEST_SECRET'];
    }
  });

  it('makes a fetch process the first one Linux ends when memory runs out', async () => {
    const fetches = pool();
    expect(text(await fetches.exchange(okJob(), within(5_000)))).toBe('ok');
    const [pid] = fetchProcessPids();
    expect(readFileSync(`/proc/${pid}/oom_score_adj`, 'utf8').trim()).toBe('1000');
  });

  it('gives a fetch process no file descriptor of this process but its channel', async () => {
    // A file and listening sockets this process holds while the process starts.
    const held = openSync(__filename, 'r');
    try {
      const fetches = pool();
      expect(text(await fetches.exchange(okJob(), within(5_000)))).toBe('ok');
      const [pid] = fetchProcessPids();
      const mine = new Set(openFiles('self').values());
      const theirs = openFiles(pid);

      for (const fd of ['0', '1', '2']) expect(theirs.get(fd)).toBe('/dev/null');
      expect(mine.has(__filename)).toBe(true);
      expect([...theirs.values()]).not.toContain(__filename);
      // Sockets, pipes and files are named by inode or path: none of this
      // process's is open there. `/dev/null` and anonymous inodes (event
      // loop, timers) are the process's own.
      const shared = [...theirs.values()].filter(
        (target) => mine.has(target) && target !== '/dev/null' && !target.startsWith('anon_inode:')
      );
      expect(shared).toEqual([]);
      // One socket: the IPC channel (the exchange's own connection is closed).
      expect([...theirs.values()].filter((target) => target.startsWith('socket:'))).toHaveLength(1);
    } finally {
      closeSync(held);
    }
  });
});

describe('opensslSetup', () => {
  it('passes nothing on for a server with no OpenSSL settings', () => {
    expect(opensslSetup(['--max-old-space-size=512'], '--enable-source-maps', {})).toEqual({
      flags: [],
      opensslStore: false,
      certFile: undefined,
      certDir: undefined,
    });
  });

  it('passes on the OpenSSL flags of NODE_OPTIONS and of the command line', () => {
    expect(
      opensslSetup(['--use-openssl-ca', '--inspect'], '--require x --openssl-legacy-provider', {
        SSL_CERT_FILE: '/etc/ssl/ca.pem',
        SSL_CERT_DIR: '/etc/ssl/certs',
        DATABASE_URL: 'postgres://secret',
      })
    ).toEqual({
      flags: ['--openssl-legacy-provider', '--use-openssl-ca'],
      opensslStore: true,
      certFile: '/etc/ssl/ca.pem',
      certDir: '/etc/ssl/certs',
    });
  });

  it('turns OPENSSL_CONF into --openssl-config, unless a flag names the file', () => {
    expect(
      opensslSetup(['--enable-fips'], undefined, { OPENSSL_CONF: '/etc/fips.cnf' }).flags
    ).toEqual(['--enable-fips', '--openssl-config=/etc/fips.cnf']);
    expect(
      opensslSetup(['--openssl-config', '/etc/a.cnf'], undefined, { OPENSSL_CONF: '/etc/b.cnf' })
        .flags
    ).toEqual(['--openssl-config=/etc/a.cnf']);
  });
});

describe('parseFetchProcessMessage', () => {
  const sent = job('api.egress.test', 443, { maxResponseBytes: 10 });
  const response = (outcome: Record<string, unknown>) => ({
    type: 'outcome',
    id: 7,
    outcome: { kind: 'response', status: 200, headers: {}, body: new Uint8Array(2), ...outcome },
  });

  it('accepts the messages a process sends', () => {
    expect(parseFetchProcessMessage({ type: 'secured', id: 7 }, 7, sent)).toEqual({
      type: 'secured',
      id: 7,
    });
    expect(parseFetchProcessMessage(response({ headers: { a: 'b' } }), 7, sent)).toMatchObject({
      outcome: { kind: 'response', status: 200, headers: { a: 'b' }, location: undefined },
    });
    const failure = {
      kind: 'failed',
      reason: 'network',
      message: 'egress to api.egress.test failed: certificate has expired',
    };
    expect(parseFetchProcessMessage({ type: 'outcome', id: 7, outcome: failure }, 7, sent)).toEqual(
      {
        type: 'outcome',
        id: 7,
        outcome: failure,
      }
    );
  });

  it.each([
    ['not an object', 'secured'],
    ['another exchange', { type: 'secured', id: 6 }],
    ['an unknown type', { type: 'hello', id: 7 }],
    ['no outcome', { type: 'outcome', id: 7 }],
    ['a status that is not an integer', response({ status: 200.5 })],
    ['a status out of range', response({ status: 42 })],
    ['a body that is not bytes', response({ body: 'ok' })],
    ['a body above the cap', response({ body: new Uint8Array(11) })],
    ['a header value that is not a string', response({ headers: { a: ['b'] } })],
    ['a header name that is not a token', response({ headers: { 'a b': 'c' } })],
    ['a header name in upper case', response({ headers: { A: 'b' } })],
    ['a header value with a line break', response({ headers: { a: 'b\r\nx-forged: 1' } })],
    ['a location that is not a string', response({ location: 1 })],
    [
      'a reason only the pool gives',
      { type: 'outcome', id: 7, outcome: { kind: 'failed', reason: 'busy', message: 'x' } },
    ],
    ['an unknown outcome', { type: 'outcome', id: 7, outcome: { kind: 'other' } }],
  ])('refuses %s', (_case, raw) => {
    expect(parseFetchProcessMessage(raw, 7, sent)).toBeUndefined();
  });

  it('keeps a failure message on one line and within its length', () => {
    const message = (text: string): string | undefined => {
      const parsed = parseFetchProcessMessage(
        { type: 'outcome', id: 7, outcome: { kind: 'failed', reason: 'network', message: text } },
        7,
        sent
      );
      return parsed?.type === 'outcome' && parsed.outcome.kind === 'failed'
        ? parsed.outcome.message
        : undefined;
    };
    expect(message('egress to api.egress.test failed: x\r\nforged log line\n')).toBe(
      'egress to api.egress.test failed: x forged log line'
    );
    expect(message('egress to api.egress.test failed: a\u2028b\u202ec')).toBe(
      'egress to api.egress.test failed: a b c'
    );
    const long = message(`egress to api.egress.test failed: ${'x'.repeat(600)}`);
    expect(long).toMatch(/^egress to api\.egress\.test failed: x+$/);
    expect(long).toHaveLength(512);
    expect(message('egress to evil.test failed: x')).toBe(
      'egress to api.egress.test failed: the fetch process gave no reason'
    );
  });
});
