import { extname, join } from 'node:path';
import { Worker } from 'node:worker_threads';

import {
  checkFetchTarget,
  GUARDED_GET_WORKER_TAG,
  type GuardedGetJob,
  type GuardedGetOutcome,
} from './ssrf-fetch-worker';

export { isPublicUnicastAddress } from './ssrf-fetch-worker';

/**
 * SSRF-safe HTTPS fetcher (CIMD §6 / OWASP API7 / OWASP A?:2025 SSRF).
 *
 * A `client_id` in CIMD is a fully attacker-controlled URL that the
 * authorization server fetches on demand. Without hardening this is a
 * textbook SSRF primitive: an attacker registers
 * `client_id=https://169.254.169.254/latest/meta-data/...` (or a name that
 * resolves to a loopback / RFC 1918 address) and the AS happily proxies the
 * request into the deployment's private network or cloud metadata service.
 *
 * Defenses layered here (defense-in-depth):
 *   1. **Scheme allowlist** — https only. http/file/gopher/data rejected.
 *   2. **No credentials / non-default surprises** — userinfo (`user:pass@`)
 *      in the URL is rejected.
 *   3. **DNS-pinned IP validation that is TOCTOU-safe.** We do NOT resolve
 *      the host, validate, and then let the HTTP client resolve again
 *      (classic DNS-rebinding window). Instead we hand `node:https` a custom
 *      `lookup` callback. The IP that callback returns is the exact IP the
 *      socket connects to, and we validate it inside the callback — so the
 *      address that is checked and the address that is dialed are guaranteed
 *      identical. Every A/AAAA record is checked; if any is non-public the
 *      whole connection is refused. The records come from a c-ares
 *      `Resolver` per fetch, with a timeout per query and cancelled with the
 *      fetch — never from `dns.lookup()`, whose getaddrinfo(3) calls share
 *      the process's small libuv thread pool and cannot be cancelled.
 *   4. **No redirect following.** A 3xx is surfaced as an error, never
 *      transparently followed — otherwise the upstream could 302 us to
 *      `http://169.254.169.254` and bypass every check above.
 *   5. **Response size + time bounds.** A slow-loris or multi-GB body can't
 *      exhaust the server.
 *   6. **Off the main thread.** The network part (resolution, TLS, HTTP, byte
 *      cap — `ssrf-fetch-worker.ts`) runs on a worker thread per fetch. The
 *      host is the TLS peer, and OpenSSL works through each handshake message
 *      synchronously: on the main thread a host could stall every route, and
 *      every timer, for as long as its certificates take to decode
 *      (ANT-2026-3OJSXV7G). The deadline below lives on the main thread, where
 *      it always fires, and it stops the worker.
 *   7. **A bounded, fair number of fetches.** At most
 *      {@link MAX_FETCH_THREADS} fetch threads exist at once, at most
 *      {@link MAX_FETCH_THREADS_PER_HOST} of them for one host, and a bounded
 *      number of fetches may wait for one; past that a fetch is refused at
 *      once.
 *
 * The blocklist covers the ranges CIMD §6 and the SSRF literature call out:
 * loopback, link-local (incl. the 169.254.169.254 cloud-metadata address and
 * its IPv6 fd00:ec2 equivalent), private/RFC1918, CGNAT, IPv4-mapped IPv6,
 * unique-local IPv6, and unspecified addresses. For IPv6 the check is an
 * allowlist: only global unicast (2000::/3, minus its special-purpose blocks)
 * is dialed, and an address that embeds an IPv4 address (mapped, compatible,
 * NAT64, 6to4) is judged by that IPv4 address (`ssrf-fetch-worker.ts`).
 */

export interface SsrfSafeFetchOptions {
  /**
   * Time bound in milliseconds. The promise settles no later than this after
   * the call, whatever the host does — waiting for a fetch thread included.
   */
  timeoutMs: number;
  /** Maximum response body size in bytes. */
  maxBytes: number;
  /**
   * Escape hatch for local dev/integration fixtures only. When true the
   * private/loopback/link-local IP checks are skipped. MUST be false in
   * production — it removes the core SSRF guard.
   */
  allowPrivateAddresses?: boolean;
}

export interface SsrfSafeFetchResult {
  status: number;
  body: string;
  /**
   * Lower-cased response headers, single value per header — only
   * `cache-control`, `expires` and `content-type`, the ones callers read.
   */
  headers: Record<string, string>;
}

/**
 * Reason a fetch was refused. `ssrf_blocked` specifically flags a target
 * that resolved to a disallowed address so callers can audit-log it
 * distinctly from a generic network failure.
 */
export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfBlockedError';
    Object.setPrototypeOf(this, SsrfBlockedError.prototype);
  }
}

export class SsrfFetchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfFetchError';
    Object.setPrototypeOf(this, SsrfFetchError.prototype);
  }
}

/* -------------------------------------------------------------------------- */
/*                                Fetch threads                               */
/* -------------------------------------------------------------------------- */

/**
 * Fetch threads alive at once. A thread is counted until it has EXITED, not
 * until it was told to stop: `worker.terminate()` takes effect only when the
 * thread is back from native code, so a thread a host keeps inside OpenSSL
 * past the deadline still holds its slot. That is what keeps such threads
 * from piling up.
 */
const MAX_FETCH_THREADS = 8;

/**
 * Fetch threads one host — the URL's host name — may hold at once, so that a
 * slow or hostile host cannot take every thread from the others.
 */
const MAX_FETCH_THREADS_PER_HOST = 2;

/** Fetches that may wait for a thread, across all hosts. */
const MAX_WAITING_FETCHES = 64;

/** Fetches one host may have waiting, so that one host cannot fill the queue. */
const MAX_WAITING_FETCHES_PER_HOST = 8;

/**
 * The worker's entry point: `ssrf-fetch-worker` next to this module, in this
 * module's own form — `.ts` when the server runs from its sources (tsx,
 * vitest), `.js` in the esbuild output, which compiles every source file one
 * to one (`bundle: false`).
 */
const WORKER_ENTRY = join(__dirname, `ssrf-fetch-worker${extname(__filename)}`);

/**
 * Node flags of a fetch thread. It inherits none of the server's: the `.ts`
 * entry is loaded with Node's own type stripping rather than the server's
 * loader, and it is ESM syntax under a package.json without `"type"`, which
 * Node detects — and would announce on every start.
 */
const WORKER_EXEC_ARGV = ['--disable-warning=MODULE_TYPELESS_PACKAGE_JSON'];

/**
 * A fetch thread holds one document of at most `maxBytes` (64 KiB by default)
 * and the TLS state of one connection; these limits leave room for that and
 * bound what a thread can grow to.
 */
const WORKER_RESOURCE_LIMITS = {
  maxOldGenerationSizeMb: 32,
  maxYoungGenerationSizeMb: 8,
  stackSizeMb: 4,
};

/** A fetch waiting for a thread. */
interface WaitingFetch {
  host: string;
  start: () => void;
}

let liveThreads = 0;
const liveThreadsByHost = new Map<string, number>();
const waiting: WaitingFetch[] = [];
const waitingByHost = new Map<string, number>();

function bump(counts: Map<string, number>, host: string, by: 1 | -1): void {
  const next = (counts.get(host) ?? 0) + by;
  if (next > 0) counts.set(host, next);
  else counts.delete(host);
}

function hasThreadFor(host: string): boolean {
  return (
    liveThreads < MAX_FETCH_THREADS &&
    (liveThreadsByHost.get(host) ?? 0) < MAX_FETCH_THREADS_PER_HOST
  );
}

function takeThread(host: string): void {
  liveThreads += 1;
  bump(liveThreadsByHost, host, 1);
}

/** A thread has exited: hand its slot to the first waiting fetch that may have it. */
function releaseThread(host: string): void {
  liveThreads -= 1;
  bump(liveThreadsByHost, host, -1);
  for (let i = 0; i < waiting.length && liveThreads < MAX_FETCH_THREADS;) {
    const next = waiting[i];
    if (hasThreadFor(next.host)) {
      waiting.splice(i, 1);
      bump(waitingByHost, next.host, -1);
      next.start();
    } else {
      i += 1;
    }
  }
}

/** Remove a fetch from the waiting list, if it is still on it. */
function stopWaiting(entry: WaitingFetch): void {
  const index = waiting.indexOf(entry);
  if (index === -1) return;
  waiting.splice(index, 1);
  bump(waitingByHost, entry.host, -1);
}

/** Map a worker's report to the caller's result, trusting nothing about its shape. */
function settleFromOutcome(
  outcome: unknown,
  resolve: (result: SsrfSafeFetchResult) => void,
  reject: (err: Error) => void
): void {
  const o = outcome as Partial<GuardedGetOutcome> | null;
  if (
    o?.kind === 'response' &&
    typeof o.status === 'number' &&
    typeof o.body === 'string' &&
    typeof o.headers === 'object' &&
    o.headers !== null
  ) {
    resolve({ status: o.status, body: o.body, headers: { ...o.headers } });
    return;
  }
  const message =
    o !== null && 'message' in o && typeof o.message === 'string' ? o.message : 'CIMD fetch failed';
  reject(o?.kind === 'blocked' ? new SsrfBlockedError(message) : new SsrfFetchError(message));
}

/**
 * Perform an SSRF-guarded HTTPS GET. Resolves with status/headers/body on a
 * completed (non-redirect) response; rejects with {@link SsrfBlockedError}
 * for a disallowed target or {@link SsrfFetchError} for any other failure —
 * including the deadline and a fetch refused because too many are in
 * progress.
 */
export function ssrfSafeGet(
  targetUrl: string,
  options: SsrfSafeFetchOptions
): Promise<SsrfSafeFetchResult> {
  return new Promise((resolve, reject) => {
    const allowPrivateAddresses = options.allowPrivateAddresses === true;
    const target = checkFetchTarget(targetUrl, allowPrivateAddresses);
    if (target.kind === 'blocked') {
      reject(new SsrfBlockedError(target.message));
      return;
    }
    const { host } = target;
    const startedAt = Date.now();

    let settled = false;
    let worker: Worker | undefined;
    let queued: WaitingFetch | undefined;

    const settle = (outcome: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      outcome();
    };

    // The deadline is a main-thread timer: it fires even while the fetch
    // thread is stuck in native code, which the fetch's own timers cannot.
    const deadline = setTimeout(() => {
      settle(() => reject(new SsrfFetchError('CIMD fetch timed out')));
      if (queued) stopWaiting(queued);
      // Takes effect once the thread is back from native code; the thread
      // keeps its slot until it has exited.
      void worker?.terminate();
    }, options.timeoutMs);

    const start = (): void => {
      queued = undefined;
      takeThread(host);
      const job: GuardedGetJob = {
        url: targetUrl,
        timeoutMs: Math.max(1, options.timeoutMs - (Date.now() - startedAt)),
        maxBytes: options.maxBytes,
        allowPrivateAddresses,
      };
      try {
        worker = new Worker(WORKER_ENTRY, {
          workerData: { tag: GUARDED_GET_WORKER_TAG, job },
          // Nothing of the server's environment (signing keys, database URL)
          // is the fetch's business.
          env: {},
          execArgv: WORKER_EXEC_ARGV,
          resourceLimits: WORKER_RESOURCE_LIMITS,
        });
      } catch (err) {
        releaseThread(host);
        settle(() =>
          reject(new SsrfFetchError(err instanceof Error ? err.message : 'CIMD fetch failed'))
        );
        return;
      }
      const thread = worker;
      // A fetch thread never keeps the process alive; the deadline timer
      // does that for as long as the caller waits.
      thread.unref();
      thread.on('message', (outcome: unknown) => {
        settle(() => settleFromOutcome(outcome, resolve, reject));
        void thread.terminate();
      });
      thread.on('error', (err: Error) => {
        settle(() => reject(new SsrfFetchError(err.message)));
      });
      thread.once('exit', () => {
        releaseThread(host);
        settle(() => reject(new SsrfFetchError('CIMD fetch ended without a result')));
      });
    };

    if (hasThreadFor(host)) {
      start();
      return;
    }
    if (
      waiting.length >= MAX_WAITING_FETCHES ||
      (waitingByHost.get(host) ?? 0) >= MAX_WAITING_FETCHES_PER_HOST
    ) {
      settle(() => reject(new SsrfFetchError('too many CIMD fetches in progress')));
      return;
    }
    queued = { host, start };
    waiting.push(queued);
    bump(waitingByHost, host, 1);
  });
}
