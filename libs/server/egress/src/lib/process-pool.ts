import { type ChildProcess, spawn } from 'node:child_process';
import { fstatSync, readdirSync, readFileSync } from 'node:fs';
import { validateHeaderName, validateHeaderValue } from 'node:http';
import { join } from 'node:path';
import tls from 'node:tls';

import {
  type ExchangeFailureReason,
  type ExchangeJob,
  type ExchangeOutcome,
  FETCH_PROCESS_CHANNEL_FD,
  FETCH_PROCESS_TAG,
  type FromFetchProcess,
  type ToFetchProcess,
} from './exchange';
import { hostFamily } from './host-family';

/**
 * The pool of fetch processes that run the egress client's exchanges
 * (`exchange.ts`): the TLS handshake and the HTTP exchange with a host the
 * caller names happen there, never in the server's process.
 *
 * A fetch process is a Node process of its own. It starts with an empty
 * environment, with `/dev/null` as its standard streams and with no file
 * descriptor of the server's but the IPC channel the pool talks to it on. It
 * runs one exchange at a time and holds nothing between them.
 *
 * The deadlines stay here, in the server's process, where their timers always
 * fire: the connect time, until the process reports the end of the TLS
 * handshake, and the call's total time. A process that passes either is
 * killed, whatever it is doing, and a fresh one is started in its place when
 * a call needs it. OpenSSL works through a handshake message in one
 * synchronous call that nothing interrupts, so a worker thread stuck there
 * keeps its slot until OpenSSL returns; a process does not.
 */

/** The bounds of a pool. */
export interface ProcessPoolLimits {
  /** Fetch processes alive at once, busy or idle. A killed one counts until it has exited. */
  maxProcesses: number;
  /** Fetch processes the calls to one host family may hold at once (see `host-family.ts`). */
  maxProcessesPerFamily: number;
  /** Calls that may wait for a process, across all families; any more are refused at once. */
  maxWaiting: number;
  /** Calls to one host family that may wait, so one family cannot fill the queue. */
  maxWaitingPerFamily: number;
  /** An idle process exits after this long without an exchange, in milliseconds. */
  idleTimeoutMs: number;
}

/** The bounds of the pool the egress client uses. */
export const DEFAULT_POOL_LIMITS: Readonly<ProcessPoolLimits> = Object.freeze({
  maxProcesses: 8,
  maxProcessesPerFamily: 2,
  maxWaiting: 64,
  maxWaitingPerFamily: 8,
  idleTimeoutMs: 60_000,
});

/** What the pool of fetch processes is doing, for metrics. */
export interface EgressPoolStats {
  /** Fetch processes alive, busy or idle; a killed one until it has exited. */
  readonly processes: number;
  /** Processes running an exchange. */
  readonly busy: number;
  /** Calls waiting for a process. */
  readonly waiting: number;
  /** Processes killed because their exchange passed a deadline, since the pool started. */
  readonly deadlineKills: number;
  /** The most processes the pool runs at once. */
  readonly maxProcesses: number;
}

/** A pool of fetch processes. */
export interface ProcessPool {
  /**
   * Run `job` in a fetch process. Never rejects. `signal` aborts the call when
   * its total time runs out: a waiting call leaves the queue, and a running
   * call's process is killed.
   */
  exchange(job: ExchangeJob, signal: AbortSignal): Promise<ExchangeOutcome>;
  stats(): EgressPoolStats;
  /** Refuse waiting and new calls, kill every process, and wait until they have exited. */
  close(): Promise<void>;
}

/**
 * Node flags of a fetch process. None of the server's are passed on: they may
 * load the server's toolchain or preload modules. The heap holds the state of
 * one exchange; bodies are Buffers, which live outside it.
 */
const FETCH_PROCESS_FLAGS = ['--max-old-space-size=64', '--no-addons'];

/** `O_CLOEXEC` in the octal `flags` of `/proc/self/fdinfo/<fd>`. */
const O_CLOEXEC = 0o2000000;

/**
 * The descriptors of this process that a child keeps across the exec: those
 * above the child's standard streams and channel without close-on-exec, as
 * `fd:dev:ino`. A fetch process closes them at its start
 * (`closeInheritedDescriptors` in `exchange.ts`).
 *
 * Node opens every descriptor close-on-exec and marks a low few it inherits,
 * but a supervisor (a CI runner, an init system, a shell) can hand the server
 * higher ones, and libuv's spawn passes them on. Linux only: the flags are
 * read from `/proc/self/fdinfo`. Elsewhere the list is empty.
 */
export function inheritedDescriptors(): string {
  let names: string[];
  try {
    names = readdirSync('/proc/self/fd');
  } catch {
    return '';
  }
  const found: string[] = [];
  for (const name of names) {
    const fd = Number(name);
    if (!Number.isInteger(fd) || fd <= FETCH_PROCESS_CHANNEL_FD) continue;
    try {
      const flags = /^flags:\s*([0-7]+)$/m.exec(
        readFileSync(`/proc/self/fdinfo/${fd}`, 'utf8')
      )?.[1];
      if (flags === undefined || (parseInt(flags, 8) & O_CLOEXEC) !== 0) continue;
      const { dev, ino } = fstatSync(fd, { bigint: true });
      found.push(`${fd}:${dev}:${ino}`);
    } catch {
      // Closed between the listing and the read (the listing's own, for one).
    }
  }
  return found.join(',');
}

/**
 * The program of a fetch process: `exchange.ts` next to this module. The
 * source is handed to Node with `--eval` rather than as a file: Node does not
 * strip the types of a file under `node_modules`, which is where a deployment
 * keeps this library. The library runs from its TypeScript sources, as the
 * server does; a fetch process could not load a compiled form, which needs
 * `tslib` from a module path it does not have.
 */
const PROGRAM_FILE = join(__dirname, 'exchange.ts');

let program: string | undefined;

function fetchProcessProgram(): string {
  program ??= readFileSync(PROGRAM_FILE, 'utf8');
  return program;
}

/** Node flags that set up OpenSSL and its trust store, which a fetch process takes from the server. */
const OPENSSL_FLAGS: readonly string[] = [
  '--use-openssl-ca',
  '--use-bundled-ca',
  '--use-system-ca',
  '--openssl-legacy-provider',
  '--openssl-shared-config',
  '--enable-fips',
  '--force-fips',
];

/** How a fetch process sets up OpenSSL: the server's way. */
export interface OpensslSetup {
  /** Node flags for the process. */
  readonly flags: string[];
  /** The server uses OpenSSL's trust store, which the process then uses too. */
  readonly opensslStore: boolean;
  readonly certFile: string | undefined;
  readonly certDir: string | undefined;
}

/**
 * The OpenSSL setup of a process started with `execArgv` and `nodeOptions`
 * (`NODE_OPTIONS`) in `env`. The empty environment of a fetch process would
 * otherwise drop it: `OPENSSL_CONF` becomes `--openssl-config`, the flags in
 * {@link OPENSSL_FLAGS} are passed on, and `SSL_CERT_FILE` and `SSL_CERT_DIR`
 * go over the channel. Nothing else of the environment is read.
 *
 * @internal exported for its tests
 */
export function opensslSetup(
  execArgv: readonly string[],
  nodeOptions: string | undefined,
  env: Readonly<Record<string, string | undefined>>
): OpensslSetup {
  const given = [...(nodeOptions ?? '').split(/\s+/).filter(Boolean), ...execArgv];
  const flags: string[] = [];
  let config: string | undefined;
  for (let i = 0; i < given.length; i += 1) {
    const flag = given[i];
    if (OPENSSL_FLAGS.includes(flag)) {
      if (!flags.includes(flag)) flags.push(flag);
    } else if (flag.startsWith('--openssl-config=')) {
      config = flag.slice('--openssl-config='.length);
    } else if (flag === '--openssl-config' && i + 1 < given.length) {
      config = given[i + 1];
      i += 1;
    }
  }
  config ??= env['OPENSSL_CONF'];
  if (config) flags.push(`--openssl-config=${config}`);
  return {
    flags,
    // Node refuses to start with both --use-openssl-ca and --use-bundled-ca.
    opensslStore: flags.includes('--use-openssl-ca'),
    certFile: env['SSL_CERT_FILE'] || undefined,
    certDir: env['SSL_CERT_DIR'] || undefined,
  };
}

/** The longest failure message taken from a fetch process. */
const MAX_MESSAGE_LENGTH = 512;

const CHILD_FAILURE_REASONS: readonly ExchangeFailureReason[] = ['timeout', 'network', 'size'];

const failed = (
  job: ExchangeJob,
  reason: ExchangeFailureReason,
  what: string
): ExchangeOutcome => ({
  kind: 'failed',
  reason,
  message: `egress to ${job.hostname} failed: ${what}`,
});

/** What a fetch process sends about the exchange it runs. */
export type ExchangeMessage = Exclude<FromFetchProcess, { readonly type: 'ready' }>;

/**
 * Check a message from the fetch process running `job` as exchange `id`,
 * trusting nothing about its shape. `undefined` for anything that is not a
 * message the process may send now.
 *
 * @internal exported for its tests
 */
export function parseFetchProcessMessage(
  raw: unknown,
  id: number,
  job: ExchangeJob
): ExchangeMessage | undefined {
  if (typeof raw !== 'object' || raw === null) return undefined;
  const message = raw as Record<string, unknown>;
  if (message['id'] !== id) return undefined;
  if (message['type'] === 'secured') return { type: 'secured', id };
  if (message['type'] !== 'outcome') return undefined;
  const outcome = message['outcome'];
  if (typeof outcome !== 'object' || outcome === null) return undefined;
  const o = outcome as Record<string, unknown>;

  if (o['kind'] === 'failed') {
    const reason = o['reason'] as ExchangeFailureReason;
    const text = o['message'];
    if (!CHILD_FAILURE_REASONS.includes(reason) || typeof text !== 'string') return undefined;
    // The message reaches errors and logs: it must be the exchange's own,
    // naming the host, on one line and without format characters. OpenSSL's
    // end with a line break.
    const prefix = `egress to ${job.hostname} failed: `;
    const line = text
      .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, ' ')
      .trimEnd()
      .slice(0, MAX_MESSAGE_LENGTH);
    return {
      type: 'outcome',
      id,
      outcome: {
        kind: 'failed',
        reason,
        message: text.startsWith(prefix) ? line : `${prefix}the fetch process gave no reason`,
      },
    };
  }

  if (o['kind'] !== 'response') return undefined;
  const { status, headers, body, location } = o;
  if (typeof status !== 'number' || !Number.isInteger(status) || status < 100 || status > 999) {
    return undefined;
  }
  if (!(body instanceof Uint8Array) || body.byteLength > job.maxResponseBytes) return undefined;
  if (location !== undefined && typeof location !== 'string') return undefined;
  if (typeof headers !== 'object' || headers === null) return undefined;
  const copied: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (typeof value !== 'string' || name !== name.toLowerCase()) return undefined;
    try {
      // What Node's HTTP parser let through, checked again on this side.
      validateHeaderName(name);
      validateHeaderValue(name, value);
    } catch {
      return undefined;
    }
    copied[name] = value;
  }
  return {
    type: 'outcome',
    id,
    outcome: { kind: 'response', status, headers: copied, body, location },
  };
}

/** A call the pool has not answered yet. */
interface Call {
  readonly job: ExchangeJob;
  readonly family: string;
  readonly signal: AbortSignal;
  /** Answers the call; only the first answer counts. */
  readonly settle: (outcome: ExchangeOutcome) => void;
  /** Ends the call while it waits for a process. */
  onWaitAbort?: () => void;
}

/** One fetch process. */
interface FetchProcess {
  readonly child: ChildProcess;
  /** The call it runs. */
  call: Call | undefined;
  /** The id of the exchange it runs. */
  id: number;
  /**
   * The family whose slot it holds: from the start of a call to its end or,
   * when the process is killed, until it has exited.
   */
  family: string | undefined;
  /** Killed or told to exit: it takes no more calls. */
  ending: boolean;
  /** It has started and said so. */
  ready: boolean;
  /** It has reported the end of the TLS handshake of its call. */
  secured: boolean;
  /** Runs from the process being ready, or the call's start, to the end of the TLS handshake. */
  connectTimer: NodeJS.Timeout | undefined;
  onCallAbort: (() => void) | undefined;
  idleTimer: NodeJS.Timeout | undefined;
  /** Resolves when the process has exited. */
  readonly exited: Promise<void>;
}

function bump(counts: Map<string, number>, key: string, by: 1 | -1): void {
  const next = (counts.get(key) ?? 0) + by;
  if (next > 0) counts.set(key, next);
  else counts.delete(key);
}

/**
 * A pool of fetch processes, started on demand. The egress client shares one
 * (see {@link sharedProcessPool}); tests create their own.
 */
export function createProcessPool(overrides: Partial<ProcessPoolLimits> = {}): ProcessPool {
  const limits: ProcessPoolLimits = { ...DEFAULT_POOL_LIMITS, ...overrides };
  const processes = new Set<FetchProcess>();
  const idle: FetchProcess[] = [];
  /** Processes held per family. */
  const held = new Map<string, number>();
  const waiting: Call[] = [];
  const waitingByFamily = new Map<string, number>();
  let deadlineKills = 0;
  let nextId = 0;
  let closed = false;

  const canStart = (family: string): boolean =>
    (held.get(family) ?? 0) < limits.maxProcessesPerFamily &&
    (idle.length > 0 || processes.size < limits.maxProcesses);

  const leaveIdle = (proc: FetchProcess): void => {
    clearTimeout(proc.idleTimer);
    proc.idleTimer = undefined;
    const index = idle.indexOf(proc);
    if (index !== -1) idle.splice(index, 1);
  };

  /** End the running call of `proc`, if any, with `outcome`. */
  const endCall = (proc: FetchProcess, outcome: ExchangeOutcome): Call | undefined => {
    const { call } = proc;
    if (call === undefined) return undefined;
    proc.call = undefined;
    clearTimeout(proc.connectTimer);
    proc.connectTimer = undefined;
    if (proc.onCallAbort) call.signal.removeEventListener('abort', proc.onCallAbort);
    proc.onCallAbort = undefined;
    call.settle(outcome);
    return call;
  };

  const releaseFamily = (proc: FetchProcess): void => {
    if (proc.family === undefined) return;
    bump(held, proc.family, -1);
    proc.family = undefined;
  };

  /**
   * Kill `proc` at once. Its call, if it still runs one, ends with `outcome`.
   * Its family slot and its place in the pool are held until it has exited.
   */
  const kill = (
    proc: FetchProcess,
    outcome: ExchangeOutcome | undefined,
    atDeadline: boolean
  ): void => {
    if (atDeadline) deadlineKills += 1;
    proc.ending = true;
    leaveIdle(proc);
    proc.child.kill('SIGKILL');
    if (outcome !== undefined) endCall(proc, outcome);
  };

  const onExit = (proc: FetchProcess): void => {
    if (!processes.delete(proc)) return;
    proc.ending = true;
    leaveIdle(proc);
    if (proc.call !== undefined) {
      endCall(proc, failed(proc.call.job, 'network', 'the fetch process ended without a result'));
    }
    releaseFamily(proc);
    drain();
  };

  const send = (proc: FetchProcess, message: ToFetchProcess): void => {
    const unreachable = (): void => {
      if (proc.ending) return;
      kill(
        proc,
        proc.call && failed(proc.call.job, 'network', 'the fetch process could not be reached'),
        false
      );
    };
    try {
      proc.child.send(message, (err: Error | null) => {
        if (err !== null) unreachable();
      });
    } catch {
      // A message that cannot be serialized throws here.
      unreachable();
    }
  };

  /**
   * The connect time of `call` runs while its process connects, not while the
   * process starts: from the call's start on a ready process, else from the
   * process saying it is ready. The call's total time covers both.
   */
  const startConnectTimer = (proc: FetchProcess, call: Call): void => {
    proc.connectTimer = setTimeout(
      () => kill(proc, failed(call.job, 'timeout', 'the connection timed out'), true),
      call.job.connectTimeoutMs
    );
  };

  const onMessage = (proc: FetchProcess, raw: unknown): void => {
    if (!proc.ready && (raw as { type?: unknown } | null)?.type === 'ready') {
      proc.ready = true;
      if (proc.call !== undefined) startConnectTimer(proc, proc.call);
      return;
    }
    const { call } = proc;
    const message = call && parseFetchProcessMessage(raw, proc.id, call.job);
    if (
      call === undefined ||
      message === undefined ||
      (message.type === 'secured' && proc.secured)
    ) {
      // Nothing is asked of an idle process, and a process that answers out
      // of turn or out of shape is not given another call.
      kill(
        proc,
        call && failed(call.job, 'network', 'the fetch process sent an invalid answer'),
        false
      );
      return;
    }
    if (message.type === 'secured') {
      proc.secured = true;
      clearTimeout(proc.connectTimer);
      proc.connectTimer = undefined;
      return;
    }
    endCall(proc, message.outcome);
    releaseFamily(proc);
    if (!proc.ending) {
      idle.push(proc);
      proc.idleTimer = setTimeout(() => {
        // Not killed at a deadline: it simply has nothing to do. SIGKILL all
        // the same: a process that ignored SIGTERM would hold its place.
        proc.ending = true;
        leaveIdle(proc);
        proc.child.kill('SIGKILL');
      }, limits.idleTimeoutMs);
      proc.idleTimer.unref();
    }
    drain();
  };

  const spawnProcess = (): FetchProcess => {
    const source = fetchProcessProgram();
    const openssl = opensslSetup(process.execArgv, process.env['NODE_OPTIONS'], process.env);
    const inherited = inheritedDescriptors();
    const child = spawn(
      process.execPath,
      [
        ...FETCH_PROCESS_FLAGS,
        ...openssl.flags,
        '--input-type=module-typescript',
        '--eval',
        source,
        FETCH_PROCESS_TAG,
        // The descriptors the process closes first: what it would otherwise
        // hold of this process beside the channel.
        ...(inherited ? [inherited] : []),
      ],
      {
        // Nothing of the server's environment (database URL, key material,
        // proxy settings, NODE_OPTIONS) is the fetch's business. Node adds the
        // channel's two variables, which the process removes at start.
        env: {},
        // `/dev/null` for the standard streams and the IPC channel as `stdio[3]`
        // (FETCH_PROCESS_CHANNEL_FD). Any other descriptor the exec keeps, the
        // process closes before it reads a message.
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        // Bodies cross as bytes, not as JSON arrays of numbers.
        serialization: 'advanced',
        windowsHide: true,
      }
    );
    let markExited: () => void = () => undefined;
    const proc: FetchProcess = {
      child,
      call: undefined,
      id: 0,
      family: undefined,
      ending: false,
      ready: false,
      secured: false,
      connectTimer: undefined,
      onCallAbort: undefined,
      idleTimer: undefined,
      exited: new Promise<void>((resolve) => {
        markExited = resolve;
      }),
    };
    processes.add(proc);
    // An idle process never keeps the server's process alive; a call's own
    // timers do that for as long as the caller waits.
    child.unref();
    child.channel?.unref();
    child.on('message', (raw: unknown) => onMessage(proc, raw));
    child.once('exit', () => {
      onExit(proc);
      markExited();
    });
    child.on('error', () => {
      if (child.pid === undefined) {
        // It never started, so it never exits.
        onExit(proc);
        markExited();
      } else if (!proc.ending) {
        kill(
          proc,
          proc.call && failed(proc.call.job, 'network', 'the fetch process failed'),
          false
        );
      }
    });
    // The trust store of this process, so an exchange there trusts exactly
    // what one here would: the bundled roots, NODE_EXTRA_CA_CERTS and the
    // system store when Node uses it, or OpenSSL's store. And its TLS
    // defaults, which flags such as --tls-min-v1.3 set and the empty
    // environment would drop.
    send(proc, {
      type: 'init',
      ca: openssl.opensslStore ? [] : tls.getCACertificates('default'),
      opensslStore: { certFile: openssl.certFile, certDir: openssl.certDir },
      tls: {
        ciphers: tls.DEFAULT_CIPHERS,
        minVersion: tls.DEFAULT_MIN_VERSION,
        maxVersion: tls.DEFAULT_MAX_VERSION,
      },
    });
    return proc;
  };

  const start = (call: Call): void => {
    let proc = idle.pop();
    if (proc === undefined) {
      try {
        proc = spawnProcess();
      } catch {
        call.settle(failed(call.job, 'network', 'no fetch process could be started'));
        return;
      }
    }
    const running = proc;
    leaveIdle(running);
    nextId += 1;
    running.id = nextId;
    running.call = call;
    running.secured = false;
    running.family = call.family;
    bump(held, call.family, 1);
    if (running.ready) startConnectTimer(running, call);
    running.onCallAbort = () =>
      kill(running, failed(call.job, 'timeout', 'the call timed out'), true);
    call.signal.addEventListener('abort', running.onCallAbort, { once: true });
    send(running, { type: 'exchange', id: running.id, job: call.job });
  };

  /** Start every waiting call that may start now, in the order they came. */
  function drain(): void {
    for (let i = 0; i < waiting.length;) {
      const call = waiting[i];
      if (closed || !canStart(call.family)) {
        i += 1;
        continue;
      }
      waiting.splice(i, 1);
      bump(waitingByFamily, call.family, -1);
      if (call.onWaitAbort) call.signal.removeEventListener('abort', call.onWaitAbort);
      start(call);
    }
  }

  const exchange = (job: ExchangeJob, signal: AbortSignal): Promise<ExchangeOutcome> =>
    new Promise((resolve) => {
      let answered = false;
      const call: Call = {
        job,
        family: hostFamily(job.hostname, job.literalFamily),
        signal,
        settle: (outcome) => {
          if (answered) return;
          answered = true;
          resolve(outcome);
        },
      };
      if (closed) {
        call.settle(failed(job, 'network', 'the egress client is closed'));
        return;
      }
      if (signal.aborted) {
        call.settle(failed(job, 'timeout', 'the call timed out'));
        return;
      }
      if (canStart(call.family)) {
        start(call);
        return;
      }
      if (
        waiting.length >= limits.maxWaiting ||
        (waitingByFamily.get(call.family) ?? 0) >= limits.maxWaitingPerFamily
      ) {
        call.settle(failed(job, 'busy', 'too many calls in progress'));
        return;
      }
      waiting.push(call);
      bump(waitingByFamily, call.family, 1);
      call.onWaitAbort = () => {
        const index = waiting.indexOf(call);
        if (index !== -1) {
          waiting.splice(index, 1);
          bump(waitingByFamily, call.family, -1);
        }
        call.settle(failed(job, 'timeout', 'the call timed out'));
      };
      signal.addEventListener('abort', call.onWaitAbort, { once: true });
    });

  const stats = (): EgressPoolStats => {
    let busy = 0;
    for (const proc of processes) if (proc.call !== undefined) busy += 1;
    return {
      processes: processes.size,
      busy,
      waiting: waiting.length,
      deadlineKills,
      maxProcesses: limits.maxProcesses,
    };
  };

  const close = async (): Promise<void> => {
    closed = true;
    for (const call of waiting.splice(0)) {
      if (call.onWaitAbort) call.signal.removeEventListener('abort', call.onWaitAbort);
      call.settle(failed(call.job, 'network', 'the egress client is closed'));
    }
    waitingByFamily.clear();
    const all = [...processes];
    for (const proc of all) {
      kill(
        proc,
        proc.call && failed(proc.call.job, 'network', 'the egress client is closed'),
        false
      );
    }
    await Promise.all(all.map((proc) => proc.exited));
  };

  return { exchange, stats, close };
}

let shared: ProcessPool | undefined;

/** The pool every egress client of this process shares, started on first use. */
export function sharedProcessPool(): ProcessPool {
  shared ??= createProcessPool();
  return shared;
}

/**
 * What the egress client's pool of fetch processes is doing: the processes
 * alive, how many run an exchange, the calls waiting for one, and how many
 * were killed at a deadline. All zero until the first call.
 */
export function egressPoolStats(): EgressPoolStats {
  return (
    shared?.stats() ?? {
      processes: 0,
      busy: 0,
      waiting: 0,
      deadlineKills: 0,
      maxProcesses: DEFAULT_POOL_LIMITS.maxProcesses,
    }
  );
}
