import { spawn } from 'node:child_process';
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
import { join, relative } from 'node:path';
import tls, { getCACertificates, setDefaultCACertificates } from 'node:tls';
import { stripVTControlCharacters } from 'node:util';

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { explicitCurveCertificate, serverFirstFlight } from '../testing/hostile-handshake';
import { createTestCertificate } from '../testing/test-certificate';
import {
  createFrameReader,
  dialPinned,
  encodeOutcome,
  encodeSecured,
  exchange,
  type ExchangeJob,
  type ExchangeOutcome,
  FETCH_PROCESS_TAG,
  FRAME,
  FRAME_HEADER_BYTES,
  MAX_FAILURE_PAYLOAD_BYTES,
  MAX_RESPONSE_FIELDS_BYTES,
} from './exchange';
import {
  createProcessPool,
  egressPoolStats,
  fetchProcessFrameLimit,
  opensslSetup,
  parseFetchProcessFrame,
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

/**
 * The time a call that should succeed gets. Generous: CI runs every project's
 * suite at once, and a process can take a second or more to start then.
 */
const CALL_MS = 15_000;

/** The time a test of real processes gets, for the same reason. */
const PROCESS_TEST = { timeout: 60_000 };

/** Resolves once `check` holds, polling every 10 ms for up to 15 s. */
async function until(check: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
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

describe('fetch processes (integration: real processes, local TLS servers)', PROCESS_TEST, () => {
  it('runs an exchange in a fetch process that trusts what this process trusts', async () => {
    const fetches = pool();
    const outcome = await fetches.exchange(okJob(), within(CALL_MS));
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

  it('returns a redirect from a fetch process with its location and no body', async () => {
    okHandler = (_req, _body, res) => {
      res.writeHead(302, { location: '/elsewhere?a=1' });
      res.end('moved');
    };
    const outcome = await pool().exchange(okJob(), within(CALL_MS));
    expect(outcome).toMatchObject({
      kind: 'response',
      status: 302,
      location: '/elsewhere?a=1',
      headers: { location: '/elsewhere?a=1' },
    });
    expect(text(outcome)).toBe('');
  });

  it('sends the request body and reuses an idle process for the next call', async () => {
    okHandler = (_req, body, res) => res.end(`got ${body.length} bytes`);
    const fetches = pool();
    const pids: number[][] = [];
    for (const size of [3, 70_000]) {
      const outcome = await fetches.exchange(
        okJob({ method: 'POST', body: new Uint8Array(size).fill(0x61) }),
        within(CALL_MS)
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
    let stalledAnswered = false;
    // Long enough that the other host's fresh process starts and answers
    // before it ends, on a machine as busy as a coverage run makes it.
    const stalled = fetches
      .exchange(stallJob('slow.stall.test', { connectTimeoutMs: 8_000 }), within(CALL_MS))
      .finally(() => {
        stalledAnswered = true;
      });
    await until(() => stallOpen === 1);
    const stalledPids = LINUX ? fetchProcessPids() : [];

    // Meanwhile another host is served, by another process: the stalled call
    // is still waiting, and its connection is still open.
    const other = await fetches.exchange(okJob(), within(CALL_MS));
    expect(text(other)).toBe('ok');
    expect(stalledAnswered).toBe(false);
    expect(stallOpen).toBe(1);
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
    expect(elapsed).toBeGreaterThanOrEqual(7_990);
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
      fetches.exchange(okJob(), within(CALL_MS)),
      fetches.exchange(okJob(), within(CALL_MS)),
    ]);
    expect(after.map(text)).toEqual(['ok', 'ok']);
    expect(fetches.stats()).toMatchObject({ processes: 2, busy: 0, deadlineKills: 1 });
  });

  it('kills a process that a host keeps inside OpenSSL, at the deadline, while another host is served', async () => {
    // Twenty certificates OpenSSL decodes in one synchronous call of about
    // 0.45 s each, longer on a busy machine (ANT-2026-3OJSXV7G): no timer of
    // the process that runs it fires meanwhile, and a worker thread there kept
    // its slot until the end.
    const flight = serverFirstFlight(Array.from({ length: 20 }, () => explicitCurveCertificate()));
    let flightSent = false;
    let flightSentAt = 0;
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
          flightSentAt = performance.now();
        });
      });
    });
    await new Promise<void>((resolve) => hostile.listen(0, '127.0.0.1', resolve));
    try {
      const fetches = pool();
      const stuck = fetches.exchange(
        job('slow.hostile.test', (hostile.address() as AddressInfo).port, {
          connectTimeoutMs: 1_000,
        }),
        within(CALL_MS)
      );
      await until(() => flightSent);
      expect(text(await fetches.exchange(okJob(), within(CALL_MS)))).toBe('ok');

      await expect(stuck).resolves.toEqual({
        kind: 'failed',
        reason: 'timeout',
        message: 'egress to slow.hostile.test failed: the connection timed out',
      });
      expect(fetches.stats().deadlineKills).toBe(1);
      // The process is gone at the deadline, which falls within a second of
      // the flight: seconds before OpenSSL would have returned.
      await until(() => fetches.stats().processes === 1);
      expect(performance.now() - flightSentAt).toBeLessThan(5_000);
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
    expect(performance.now() - started).toBeLessThan(5_000);
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
    await expect(fetches.exchange(stallJob('h10.stall.test'), within(CALL_MS))).resolves.toEqual({
      kind: 'failed',
      reason: 'busy',
      message: 'egress to h10.stall.test failed: too many calls in progress',
    });
    // Another host still has the other processes.
    expect(text(await fetches.exchange(okJob(), within(CALL_MS)))).toBe('ok');
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
      fetches.exchange(job('b.example.test', okPort), within(CALL_MS))
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
      within(CALL_MS)
    );
    await until(() => stallOpen === 1);
    const second = fetches.exchange(okJob(), within(CALL_MS));
    expect(fetches.stats().waiting).toBe(1);
    await expect(first).resolves.toMatchObject({ reason: 'timeout' });
    expect(text(await second)).toBe('ok');
  });

  it('lets an idle process exit after the idle timeout', async () => {
    const fetches = pool({ idleTimeoutMs: 150 });
    expect(text(await fetches.exchange(okJob(), within(CALL_MS)))).toBe('ok');
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
      expect(text(await pool().exchange(job('old.egress.test', port), within(CALL_MS)))).toBe(
        'old'
      );
      // As `--tls-min-v1.3` would set it. A process started now takes it.
      tls.DEFAULT_MIN_VERSION = 'TLSv1.3';
      const outcome = await pool().exchange(job('old.egress.test', port), within(CALL_MS));
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
      await expect(pool().exchange(okJob(), within(CALL_MS))).resolves.toMatchObject({
        kind: 'failed',
        reason: 'network',
      });
      // As a server started with NODE_OPTIONS=--use-openssl-ca and
      // SSL_CERT_FILE would see them.
      process.env['NODE_OPTIONS'] = `${before.options ?? ''} --use-openssl-ca`.trim();
      process.env['SSL_CERT_FILE'] = join(dir, 'ca.pem');
      expect(text(await pool().exchange(okJob(), within(CALL_MS)))).toBe('ok');
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
    await expect(exchange(okJob({ path: '/a b' }), dialPinned, within(CALL_MS))).resolves.toEqual(
      refused
    );
    await expect(pool().exchange(okJob({ path: '/a b' }), within(CALL_MS))).resolves.toEqual(
      refused
    );
  });

  it('returns a TLS failure from the process with its host-only message', async () => {
    const fetches = pool();
    // The certificate does not cover this name.
    const outcome = await fetches.exchange(job('ok.elsewhere.test', okPort), within(CALL_MS));
    expect(outcome).toMatchObject({ kind: 'failed', reason: 'network' });
    expect(text(outcome)).toMatch(/^egress to ok\.elsewhere\.test failed: /);
    expect(fetches.stats()).toMatchObject({ processes: 1, deadlineKills: 0 });
  });

  it('refuses calls once closed and leaves no process behind', async () => {
    const fetches = pool();
    expect(text(await fetches.exchange(okJob(), within(CALL_MS)))).toBe('ok');
    await fetches.close();
    expect(fetches.stats().processes).toBe(0);
    await expect(fetches.exchange(okJob(), within(CALL_MS))).resolves.toMatchObject({
      kind: 'failed',
      reason: 'network',
    });
    if (LINUX) expect(fetchProcessPids()).toEqual([]);
  });

  it('runs the egress client’s exchanges in the shared pool', async () => {
    expect(egressPoolStats().processes).toBe(0);
    const outcome = await NODE_TRANSPORT.exchange(okJob(), within(CALL_MS));
    expect(text(outcome)).toBe('ok');
    expect(egressPoolStats()).toMatchObject({ processes: 1, busy: 0, maxProcesses: 8 });
    await sharedProcessPool().close();
    expect(egressPoolStats().processes).toBe(0);
  });
});

describe.skipIf(!LINUX)(
  'what a fetch process inherits (integration, Linux /proc)',
  PROCESS_TEST,
  () => {
    it('ends the call of a process that dies, and starts a fresh one', async () => {
      const fetches = pool();
      const call = fetches.exchange(
        stallJob('a.stall.test', { connectTimeoutMs: 30_000 }),
        within(CALL_MS)
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
      expect(text(await fetches.exchange(okJob(), within(CALL_MS)))).toBe('ok');
    });

    it('starts a fetch process with none of this process’s environment', async () => {
      process.env['QAUTH_POOL_TEST_SECRET'] = 'must-not-leak';
      try {
        const fetches = pool();
        expect(text(await fetches.exchange(okJob(), within(CALL_MS)))).toBe('ok');
        const [pid] = fetchProcessPids();
        const environ = readFileSync(`/proc/${pid}/environ`, 'utf8').split('\0').filter(Boolean);
        // Nothing at all: the channel is a plain socket, not Node's IPC
        // channel, which added two variables of its own.
        expect(environ).toEqual([]);
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
      expect(text(await fetches.exchange(okJob(), within(CALL_MS)))).toBe('ok');
      const [pid] = fetchProcessPids();
      expect(readFileSync(`/proc/${pid}/oom_score_adj`, 'utf8').trim()).toBe('1000');
    });

    it('gives a fetch process no file descriptor of this process but its channel', async () => {
      // A file and listening sockets this process holds while the process starts.
      const held = openSync(__filename, 'r');
      try {
        const fetches = pool();
        expect(text(await fetches.exchange(okJob(), within(CALL_MS)))).toBe('ok');
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
          (target) =>
            mine.has(target) && target !== '/dev/null' && !target.startsWith('anon_inode:')
        );
        expect(shared).toEqual([]);
        // One socket: the channel (the exchange's own connection is closed).
        expect([...theirs.values()].filter((target) => target.startsWith('socket:'))).toHaveLength(
          1
        );
      } finally {
        closeSync(held);
      }
    });

    it('gives it none this process holds without close-on-exec either, as a CI runner hands some down', async () => {
      // The test above, run by a vitest that holds a socket at descriptor 200
      // without close-on-exec, the way a CI runner hands a job pipes. Node marks
      // only a low few inherited descriptors close-on-exec and libuv's spawn
      // closes none, so the socket reaches this process's fetch processes
      // unless they close it first.
      const root = join(__dirname, '../../../../..');
      const vitest = join(__dirname, '../../node_modules/vitest/vitest.mjs');
      const child = spawn(
        process.execPath,
        [
          vitest,
          'run',
          relative(root, __filename),
          '-t',
          'gives a fetch process no file descriptor of this process but its channel',
        ],
        {
          cwd: root,
          env: { PATH: process.env['PATH'], HOME: process.env['HOME'] },
          stdio: [
            'ignore',
            'pipe',
            'pipe',
            ...Array.from({ length: 197 }, () => 'ignore' as const),
            'pipe',
          ],
        }
      );
      let output = '';
      child.stdout?.on('data', (chunk: Buffer) => (output += chunk.toString()));
      child.stderr?.on('data', (chunk: Buffer) => (output += chunk.toString()));
      const code = await new Promise<number | null>((resolve) => child.once('exit', resolve));
      expect(stripVTControlCharacters(output)).toMatch(/Tests\s+1 passed/);
      expect(code).toBe(0);
    }, 120_000);
  }
);

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

describe('the channel from a fetch process', () => {
  describe('createFrameReader', () => {
    /** A frame of `type` announcing `length` bytes, with `payload` after its header. */
    const frame = (type: number, payload: Buffer, length = payload.length): Buffer => {
      const header = Buffer.alloc(FRAME_HEADER_BYTES);
      header.writeUInt8(type, 0);
      header.writeUInt32BE(length, 1);
      return Buffer.concat([header, payload]);
    };

    /** A reader that records what it is given, with `limit` as its caps. */
    const recorder = (limit: (type: number) => number | undefined) => {
      const frames: [number, string][] = [];
      const refused: [number, number, boolean][] = [];
      const push = createFrameReader({
        limit,
        frame: (type, payload) => {
          frames.push([type, payload.toString()]);
          return true;
        },
        refuse: (type, length, oversized) => refused.push([type, length, oversized]),
      });
      return { push, frames, refused };
    };

    it('reads frames split anywhere, empty ones included', () => {
      const { push, frames, refused } = recorder(() => 100);
      const bytes = Buffer.concat([
        frame(1, Buffer.from('hello')),
        frame(2, Buffer.alloc(0)),
        frame(3, Buffer.from('x'.repeat(100))),
      ]);
      for (const byte of bytes) expect(push(Buffer.from([byte]))).toBe(true);
      expect(frames).toEqual([
        [1, 'hello'],
        [2, ''],
        [3, 'x'.repeat(100)],
      ]);
      expect(refused).toEqual([]);
    });

    it('refuses a frame above its cap from the header, before any payload arrives', () => {
      const { push, frames, refused } = recorder((type) => (type === 5 ? 10 : undefined));
      // The header alone: the payload has not been sent, and is not waited for.
      expect(push(frame(5, Buffer.alloc(0), 11))).toBe(false);
      expect(refused).toEqual([[5, 11, true]]);
      // Nothing after it is taken.
      expect(push(Buffer.alloc(11))).toBe(false);
      expect(push(frame(5, Buffer.from('ok')))).toBe(false);
      expect(frames).toEqual([]);
      expect(refused).toHaveLength(1);
    });

    it('refuses a frame of a type that may not come now, with its payload in the same chunk', () => {
      const { push, frames, refused } = recorder((type) => (type === 5 ? 10 : undefined));
      expect(push(Buffer.concat([frame(5, Buffer.from('a')), frame(6, Buffer.from('b'))]))).toBe(
        false
      );
      expect(frames).toEqual([[5, 'a']]);
      expect(refused).toEqual([[6, 1, false]]);
    });

    it('asks for the cap once the frame before has been handled', () => {
      let secured = false;
      const frames: number[] = [];
      const push = createFrameReader({
        limit: (type) => (type === 5 && !secured ? undefined : 4),
        frame: (type) => {
          frames.push(type);
          if (type === 4) secured = true;
          return true;
        },
        refuse: () => undefined,
      });
      expect(push(Buffer.concat([frame(4, Buffer.alloc(4)), frame(5, Buffer.alloc(4))]))).toBe(
        true
      );
      expect(frames).toEqual([4, 5]);
    });

    it('stops when a frame is not taken', () => {
      const frames: number[] = [];
      const push = createFrameReader({
        limit: () => 4,
        frame: (type) => {
          frames.push(type);
          return false;
        },
        refuse: () => undefined,
      });
      expect(push(Buffer.concat([frame(1, Buffer.alloc(1)), frame(2, Buffer.alloc(1))]))).toBe(
        false
      );
      expect(frames).toEqual([1]);
    });
  });

  describe('fetchProcessFrameLimit', () => {
    const running = job('api.egress.test', 443, { maxResponseBytes: 1000 });
    const types = [FRAME.ready, FRAME.secured, FRAME.response, FRAME.failure, FRAME.init, 0, 255];
    const limits = (state: Parameters<typeof fetchProcessFrameLimit>[1]) =>
      types.map((type) => fetchProcessFrameLimit(type, state));

    it('takes an empty ready frame only from a process that has not said it is ready', () => {
      expect(limits({ ready: false, job: undefined, secured: false })).toEqual([
        0,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
      ]);
      expect(limits({ ready: false, job: running, secured: false })[0]).toBe(0);
    });

    it('takes nothing from an idle process', () => {
      expect(limits({ ready: true, job: undefined, secured: false })).toEqual(
        types.map(() => undefined)
      );
    });

    it('caps each frame of an exchange by its type, a response by the job’s body cap', () => {
      // Before the TLS handshake: the id, or a failure; no response yet.
      expect(limits({ ready: true, job: running, secured: false })).toEqual([
        undefined,
        4,
        undefined,
        MAX_FAILURE_PAYLOAD_BYTES,
        undefined,
        undefined,
        undefined,
      ]);
      // After it: no second `secured`, and a response of the body cap at most.
      expect(limits({ ready: true, job: running, secured: true })).toEqual([
        undefined,
        undefined,
        MAX_RESPONSE_FIELDS_BYTES + 1000,
        MAX_FAILURE_PAYLOAD_BYTES,
        undefined,
        undefined,
        undefined,
      ]);
      expect(MAX_FAILURE_PAYLOAD_BYTES).toBe(4 + 1 + 2 + 2048);
      expect(MAX_RESPONSE_FIELDS_BYTES).toBe(4 + 2 + 2 + 100 * 4 + 16 * 1024 + 1 + 2 + 8 * 1024);
    });
  });

  describe('parseFetchProcessFrame', () => {
    const sent = job('api.egress.test', 443, { maxResponseBytes: 10 });

    interface Frame {
      readonly type: number;
      readonly payload: Buffer;
    }

    /** A frame as a fetch process encodes it, without its header. */
    const encoded = (parts: readonly Uint8Array[]): Frame => {
      const bytes = Buffer.concat(parts);
      return { type: bytes.readUInt8(0), payload: bytes.subarray(FRAME_HEADER_BYTES) };
    };
    const parse = ({ type, payload }: Frame) => parseFetchProcessFrame(type, payload, 7, sent);

    const u16 = (value: number): Buffer => {
      const bytes = Buffer.alloc(2);
      bytes.writeUInt16BE(value);
      return bytes;
    };
    const u32 = (value: number): Buffer => {
      const bytes = Buffer.alloc(4);
      bytes.writeUInt32BE(value);
      return bytes;
    };

    /** A response frame laid out by hand, so that it can break any rule. */
    const response = ({
      id = 7,
      status = 200,
      headers = [],
      count = headers.length,
      locationFlag,
      location,
      body = Buffer.alloc(2),
    }: {
      id?: number;
      status?: number;
      headers?: readonly (readonly [string, string])[];
      count?: number;
      locationFlag?: number;
      location?: string;
      body?: Buffer;
    } = {}): Frame => {
      const parts = [u32(id), u16(status), u16(count)];
      for (const [name, value] of headers) {
        parts.push(u16(name.length), Buffer.from(name, 'latin1'));
        parts.push(u16(value.length), Buffer.from(value, 'latin1'));
      }
      parts.push(Buffer.from([locationFlag ?? (location === undefined ? 0 : 1)]));
      if (location !== undefined) parts.push(u16(location.length), Buffer.from(location, 'latin1'));
      parts.push(body);
      return { type: FRAME.response, payload: Buffer.concat(parts) };
    };

    /** A failure frame laid out by hand. */
    const failure = ({
      code = 1,
      message = Buffer.from('egress to api.egress.test failed: x'),
      length = message.length,
    }: {
      code?: number;
      message?: Buffer;
      length?: number;
    } = {}): Frame => ({
      type: FRAME.failure,
      payload: Buffer.concat([u32(7), Buffer.from([code]), u16(length), message]),
    });

    /** `count` headers of `size` bytes each, names and values together. */
    const headersOf = (count: number, size = 2): [string, string][] =>
      Array.from({ length: count }, (_, i) => {
        const name = `h${i}`;
        return [name, 'v'.repeat(Math.max(1, size - name.length))];
      });

    it('accepts the frames a process sends', () => {
      expect(parse(encoded(encodeSecured(7)))).toEqual({ type: 'secured', id: 7 });
      const answered: ExchangeOutcome = {
        kind: 'response',
        status: 200,
        headers: { a: 'b', 'content-type': 'text/plain; charset=é' },
        body: Buffer.from('ok'),
        location: undefined,
      };
      expect(parse(encoded(encodeOutcome(7, answered)))).toEqual({
        type: 'outcome',
        id: 7,
        outcome: answered,
      });
      const redirected: ExchangeOutcome = {
        kind: 'response',
        status: 302,
        headers: { location: '/next' },
        body: Buffer.alloc(0),
        location: '/next',
      };
      expect(parse(encoded(encodeOutcome(7, redirected)))).toEqual({
        type: 'outcome',
        id: 7,
        outcome: redirected,
      });
      const failed: ExchangeOutcome = {
        kind: 'failed',
        reason: 'network',
        message: 'egress to api.egress.test failed: certificate has expired',
      };
      expect(parse(encoded(encodeOutcome(7, failed)))).toEqual({
        type: 'outcome',
        id: 7,
        outcome: failed,
      });
    });

    it.each([
      // Each bound at its cap.
      ['100 headers', response({ headers: headersOf(100) })],
      ['a header name of 256 bytes', response({ headers: [['n'.repeat(256), 'v']] })],
      ['a header value of 8 KiB', response({ headers: [['v', 'v'.repeat(8192)]] })],
      [
        'headers of 16 KiB together',
        response({
          headers: [
            ['a', 'v'.repeat(8191)],
            ['b', 'v'.repeat(8191)],
          ],
        }),
      ],
      ['a location of 8 KiB', response({ location: `/${'l'.repeat(8191)}` })],
      ['a body of the job’s cap', response({ body: Buffer.alloc(10) })],
      [
        'a failure message of 2 KiB',
        failure({ message: Buffer.from(`egress to api.egress.test failed: ${'x'.repeat(2014)}`) }),
      ],
    ])('accepts %s', (_case, frame) => {
      expect(parse(frame)).toMatchObject({ type: 'outcome', id: 7 });
    });

    it.each([
      ['a frame of an unknown type', { type: 99, payload: u32(7) }],
      ['a ready frame during an exchange', { type: FRAME.ready, payload: Buffer.alloc(0) }],
      ['another exchange', encoded(encodeSecured(6))],
      ['a secured frame with more than the id', { type: FRAME.secured, payload: u32(7 << 8) }],
      [
        'a secured frame with bytes after the id',
        { type: FRAME.secured, payload: Buffer.concat([u32(7), Buffer.from([0])]) },
      ],
      [
        'a response cut short',
        { type: FRAME.response, payload: Buffer.concat([u32(7), u16(200)]) },
      ],
      ['a status below the range', response({ status: 42 })],
      ['a status above the range', response({ status: 1000 })],
      ['more headers than it holds', response({ headers: headersOf(1), count: 2 })],
      ['a body above the cap', response({ body: Buffer.alloc(11) })],
      ['a header name that is not a token', response({ headers: [['a b', 'c']] })],
      ['an empty header name', response({ headers: [['', 'c']] })],
      ['a header name in upper case', response({ headers: [['A', 'b']] })],
      ['a header value with a line break', response({ headers: [['a', 'b\r\nx-forged: 1']] })],
      [
        'a header given twice',
        response({
          headers: [
            ['a', 'b'],
            ['a', 'c'],
          ],
        }),
      ],
      ['a location with a line break', response({ location: '/a\r\nx-forged: 1' })],
      ['a location flag that is neither 0 nor 1', response({ locationFlag: 2 })],
      // Every bound, each one past its cap.
      ['more than 100 headers', response({ headers: headersOf(101) })],
      ['a header name above 256 bytes', response({ headers: [['n'.repeat(257), 'v']] })],
      ['a header value above 8 KiB', response({ headers: [['v', 'v'.repeat(8193)]] })],
      [
        // Each value within its own cap.
        'headers above 16 KiB together',
        response({
          headers: [
            ['a', 'v'.repeat(8192)],
            ['b', 'v'.repeat(8191)],
          ],
        }),
      ],
      ['a location above 8 KiB', response({ location: `/${'l'.repeat(8192)}` })],
      [
        // Line breaks the cleaning would turn into one space: the length is
        // checked before the cleaning runs, on what the process sent.
        'a failure message above 2 KiB',
        failure({
          message: Buffer.from(`egress to api.egress.test failed: ${'\n'.repeat(2015)}`),
        }),
      ],
      ['a failure message longer than it says', failure({ length: 3 })],
      ['a failure message that is not UTF-8', failure({ message: Buffer.from([0xff, 0xfe]) })],
      ['a reason only the pool gives', failure({ code: 3 })],
      ['an unknown reason', failure({ code: 255 })],
    ])('refuses %s', (_case, frame) => {
      expect(parse(frame)).toBeUndefined();
    });

    it('keeps a failure message on one line and within its length', () => {
      const message = (text: string): string | undefined => {
        const parsed = parse(
          encoded(encodeOutcome(7, { kind: 'failed', reason: 'network', message: text }))
        );
        return parsed?.type === 'outcome' && parsed.outcome.kind === 'failed'
          ? parsed.outcome.message
          : undefined;
      };
      expect(message('egress to api.egress.test failed: x\r\nforged log line\n')).toBe(
        'egress to api.egress.test failed: x forged log line'
      );
      expect(message('egress to api.egress.test failed: a b‮c')).toBe(
        'egress to api.egress.test failed: a b c'
      );
      const long = message(`egress to api.egress.test failed: ${'x'.repeat(600)}`);
      expect(long).toMatch(/^egress to api\.egress\.test failed: x+$/);
      expect(long).toHaveLength(512);
      expect(message('egress to evil.test failed: x')).toBe(
        'egress to api.egress.test failed: the fetch process gave no reason'
      );
      // The process cuts a longer message to the cap, between characters.
      const euros = message(`egress to api.egress.test failed: ${'€'.repeat(1000)}`);
      expect(euros).toMatch(/^egress to api\.egress\.test failed: €+$/);
      expect(euros).toHaveLength(512);
    });
  });
});
