import type { LookupAddress } from 'node:dns';
import { writeFileSync } from 'node:fs';
import type { IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as netConnect, type Socket } from 'node:net';
import { setPriority } from 'node:os';
import tls, { type SecureVersion } from 'node:tls';

/**
 * One HTTPS request over a connection of its own: the TLS handshake with a
 * host the caller names, the HTTP exchange and the byte caps. This is the part
 * of an egress call that talks to the destination.
 *
 * Outside tests it runs in a fetch process (`process-pool.ts`), never in the
 * server's own process. OpenSSL works through each handshake message in one
 * synchronous call, and a host can make that call take seconds (a Certificate
 * message of certificates whose EC keys use an explicit curve) or longer. No
 * timer of the process that runs it fires meanwhile, and nothing short of
 * ending the process stops it. The pool keeps the deadlines in the server's
 * process and kills a fetch process that passes one.
 *
 * ## Loaded by Node itself
 *
 * The pool starts a fetch process from this file's source, which Node runs
 * with its own type stripping (`--input-type=module-typescript`), without the
 * server's toolchain and without a file to resolve relative imports from. So
 * this file imports `node:` builtins only, imports types with `import type`,
 * and uses erasable TypeScript syntax only: no enums, namespaces or parameter
 * properties. Its failures are plain data, not `EgressFailure`s, because they
 * cross a process boundary. The server's process imports it too, for the
 * types and the tests; the code at the bottom runs only in a fetch process.
 */

/**
 * Opens a TCP connection to one of `addresses` — already checked — on `port`.
 * `hostname` is the URL's host; it is never resolved again.
 */
export type Dial = (hostname: string, addresses: readonly LookupAddress[], port: number) => Socket;

/** One request on one connection, as plain data that can cross to a fetch process. */
export interface ExchangeJob {
  /**
   * The URL's host: lower-case, without IPv6 brackets or a trailing dot. TLS
   * names it in SNI and checks the certificate against it.
   */
  readonly hostname: string;
  readonly port: number;
  /** The IP family when the host is an IP literal, else `0`. */
  readonly literalFamily: 0 | 4 | 6;
  /** The path and query string of the URL. */
  readonly path: string;
  /** The checked addresses of the host; the only ones dialled. */
  readonly addresses: readonly LookupAddress[];
  readonly method: string;
  /** Lower-case names. The exchange adds `host`, `connection` and `content-length`. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array | undefined;
  /** Time to connect and finish the TLS handshake, in milliseconds. */
  readonly connectTimeoutMs: number;
  readonly maxResponseBytes: number;
}

/**
 * Why an exchange did not complete. `busy` comes only from the pool, when it
 * has no room for the exchange.
 */
export type ExchangeFailureReason = 'timeout' | 'network' | 'size' | 'busy';

/** The answer to one {@link ExchangeJob}, or why there is none. */
export type ExchangeOutcome =
  | {
      readonly kind: 'response';
      readonly status: number;
      /** Lower-case names; a repeated header's values joined with `, `. */
      readonly headers: Record<string, string>;
      /** Empty for a redirect, which is not read. */
      readonly body: Uint8Array;
      /** The `Location` of a redirect, which the caller decides whether to follow. */
      readonly location: string | undefined;
    }
  | {
      readonly kind: 'failed';
      readonly reason: ExchangeFailureReason;
      /** Names the host, never the path, the query string or a header. */
      readonly message: string;
    };

/**
 * Dial one of the checked addresses and nothing else. `net.connect` is handed
 * a `lookup` that answers with those addresses whatever it is asked, so the
 * host is not resolved a second time between the check and the connection
 * (DNS rebinding). With several addresses it tries them in turn, alternating
 * families. An IP literal is dialled as it is; `lookup` is not consulted.
 */
export const dialPinned: Dial = (hostname, addresses, port) => {
  const pinned = addresses.map(({ address, family }) => ({ address, family }));
  const lookup = (
    _hostname: string,
    options: { all?: boolean } | number | undefined,
    callback: (err: Error | null, address: string | LookupAddress[], family?: number) => void
  ): void => {
    if (typeof options === 'object' && options?.all === true) {
      callback(null, pinned);
      return;
    }
    callback(null, pinned[0].address, pinned[0].family);
  };
  return netConnect({
    host: hostname,
    port,
    lookup: lookup as unknown as typeof import('node:dns').lookup,
    autoSelectFamily: true,
  });
};

/**
 * The TLS defaults an exchange uses: those of the process it runs in, which a
 * fetch process replaces with the server's (`init`), so that `--tls-min-v1.3`
 * or `--tls-cipher-list` in the server's `NODE_OPTIONS` still applies.
 */
export interface TlsDefaults {
  readonly ciphers: string;
  readonly minVersion: SecureVersion;
  readonly maxVersion: SecureVersion;
}

let tlsDefaults: TlsDefaults = {
  ciphers: tls.DEFAULT_CIPHERS,
  minVersion: tls.DEFAULT_MIN_VERSION,
  maxVersion: tls.DEFAULT_MAX_VERSION,
};

/**
 * Cipher list. Finite-field DHE is left out: a host can name a 10 000-bit
 * group in its ServerKeyExchange and make the client compute in it (about a
 * second of CPU per handshake). ECDHE and TLS 1.3 are unaffected.
 */
const egressCiphers = (): string => `${tlsDefaults.ciphers}:!kDHE`;

/** Largest response head, in bytes, whatever `--max-http-header-size` says. */
const MAX_HEADER_BYTES = 16 * 1024;

/**
 * 1xx interim responses tolerated ahead of the final response: room for a
 * `103 Early Hints` or two, not for a stream of them.
 */
const MAX_INTERIM_RESPONSES = 3;

/** Statuses that are redirects when they carry a `Location`. */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

function responseHeaders(res: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(res.headers)) {
    if (value === undefined) continue;
    headers[name] = Array.isArray(value) ? value.join(', ') : value;
  }
  return headers;
}

/** The `Host` header: brackets around IPv6, port unless 443. */
function hostHeader(job: ExchangeJob): string {
  const host = job.literalFamily === 6 ? `[${job.hostname}]` : job.hostname;
  return job.port === 443 ? host : `${host}:${job.port}`;
}

/**
 * Send one request over a connection of its own, to a checked address, and
 * read the answer within the caps. TLS names the URL's host in SNI and checks
 * the certificate against it, whichever address was dialled. No agent is
 * involved: nothing is pooled, and no proxy setting of the environment or of
 * Node's global agents can route the connection elsewhere, where the address
 * checks would not reach.
 *
 * Never rejects: every failure is an outcome. `signal` aborts the exchange
 * when the call's total time runs out; `onSecured` is called once the TLS
 * handshake is done.
 */
export function exchange(
  job: ExchangeJob,
  dial: Dial,
  signal: AbortSignal,
  onSecured?: () => void
): Promise<ExchangeOutcome> {
  return new Promise((resolve) => {
    let settled = false;
    // The TCP socket and the TLS socket over it; both are destroyed at the end.
    const sockets: Socket[] = [];

    const failure = (reason: ExchangeFailureReason, what: string): ExchangeOutcome => ({
      kind: 'failed',
      reason,
      message: `egress to ${job.hostname} failed: ${what}`,
    });

    // Connect time runs from here to the end of the TLS handshake.
    const connectTimer = setTimeout(
      () => finish(failure('timeout', 'the connection timed out')),
      job.connectTimeoutMs
    );

    const finish = (outcome: ExchangeOutcome): void => {
      if (settled) return;
      settled = true;
      clearTimeout(connectTimer);
      signal.removeEventListener('abort', onAbort);
      for (const socket of sockets) socket.destroy();
      resolve(outcome);
    };
    const failed = (what: string): void => finish(failure('network', what));

    const onAbort = (): void => finish(failure('timeout', 'the call timed out'));
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });

    // Node throws for some bad input (a path with a space) rather than
    // emitting an error; that is a failure too.
    try {
      let tcp: Socket;
      try {
        tcp = dial(job.hostname, job.addresses, job.port);
      } catch (err) {
        failed(err instanceof Error ? err.message : 'could not connect');
        return;
      }
      sockets.push(tcp);
      tcp.on('error', (err) => failed(err.message));
      const secure = tls.connect({
        socket: tcp,
        host: job.hostname,
        // RFC 6066 has no SNI for an IP literal; the certificate is then checked
        // against the address.
        ...(job.literalFamily === 0 ? { servername: job.hostname } : {}),
        ciphers: egressCiphers(),
        minVersion: tlsDefaults.minVersion,
        maxVersion: tlsDefaults.maxVersion,
        ALPNProtocols: ['http/1.1'],
        // Explicit, so NODE_TLS_REJECT_UNAUTHORIZED=0 cannot turn it off.
        rejectUnauthorized: true,
      });
      sockets.push(secure);
      secure.on('error', (err) => failed(err.message));

      const tooLarge = (): ExchangeOutcome =>
        failure('size', `the response is larger than ${job.maxResponseBytes} bytes`);

      // The body cap counts body bytes only. Chunk-size lines, chunk extensions
      // and trailers are not body, and a host could send them without end; this
      // caps everything read from the connection: the heads, and twice the body
      // cap for the body with its framing.
      const maxWireBytes =
        2 * job.maxResponseBytes + MAX_HEADER_BYTES * (MAX_INTERIM_RESPONSES + 2);
      let wireBytes = 0;
      secure.on('data', (chunk: Buffer) => {
        wireBytes += chunk.length;
        // Fail once this chunk has reached the HTTP parser, which listens after
        // this listener: a socket destroyed under it in the middle of a 'data'
        // event trips an assertion in Node's HTTP client, an uncaught exception.
        if (wireBytes > maxWireBytes) process.nextTick(() => finish(tooLarge()));
      });
      secure.once('secureConnect', () => {
        clearTimeout(connectTimer);
        if (!settled) onSecured?.();
      });

      const headers: Record<string, string> = {
        ...job.headers,
        host: hostHeader(job),
        connection: 'close',
      };
      if (job.body !== undefined) headers['content-length'] = String(job.body.byteLength);

      const req = httpsRequest(
        {
          method: job.method,
          host: job.hostname,
          port: job.port,
          path: job.path,
          headers,
          setHost: false,
          maxHeaderSize: MAX_HEADER_BYTES,
          insecureHTTPParser: false,
          createConnection: () => secure,
        },
        (res) => {
          const status = res.statusCode ?? 0;
          const resHeaders = responseHeaders(res);
          const location = resHeaders['location'];
          if (REDIRECT_STATUSES.has(status) && location !== undefined) {
            finish({
              kind: 'response',
              status,
              headers: resHeaders,
              body: Buffer.alloc(0),
              location,
            });
            return;
          }

          // A HEAD answer, a 204 and a 304 declare a length they do not send.
          const hasBody = job.method !== 'HEAD' && status !== 204 && status !== 304;
          const declared = Number(resHeaders['content-length']);
          if (hasBody && Number.isFinite(declared) && declared > job.maxResponseBytes) {
            finish(tooLarge());
            return;
          }
          let received = 0;
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => {
            received += chunk.length;
            if (received > job.maxResponseBytes) {
              finish(tooLarge());
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () =>
            finish({
              kind: 'response',
              status,
              headers: resHeaders,
              body: Buffer.concat(chunks),
              location: undefined,
            })
          );
          res.on('error', (err) => failed(err.message));
        }
      );

      // 1xx responses never reach the response callback, so the byte cap does
      // not see them; a host could stream them until the deadline.
      let interim = 0;
      req.on('information', () => {
        interim += 1;
        if (interim > MAX_INTERIM_RESPONSES) failed('too many interim responses');
      });
      req.on('error', (err) => failed(err.message));
      // Once the request has closed the exchange is over, whatever else
      // happened. An unsolicited `101`, which Node answers by dropping the
      // socket, is reported with nothing but 'close'.
      req.on('close', () => failed('the connection closed without a response'));
      req.end(job.body);
    } catch (err) {
      failed(err instanceof Error ? err.message : 'the request could not be sent');
    }
  });
}

/* -------------------------------------------------------------------------- */
/*                              The fetch process                             */
/* -------------------------------------------------------------------------- */

/** The argument that marks a process started as a fetch process. */
export const FETCH_PROCESS_TAG = 'qauth:egress-fetch-process';

/** What the pool sends a fetch process. */
export type ToFetchProcess =
  /** First, once: how the server's process sets up TLS. */
  | {
      readonly type: 'init';
      /**
       * The server's trust store, as PEM. Empty when the server uses OpenSSL's
       * store (`--use-openssl-ca`), which the process then uses too.
       */
      readonly ca: readonly string[];
      readonly tls: TlsDefaults;
      /** `SSL_CERT_FILE` and `SSL_CERT_DIR` of the server, for OpenSSL's store. */
      readonly opensslStore: { readonly certFile?: string; readonly certDir?: string };
    }
  /** One exchange at a time; the next only after the outcome of this one. */
  | { readonly type: 'exchange'; readonly id: number; readonly job: ExchangeJob };

/** What a fetch process sends the pool. */
export type FromFetchProcess =
  /** Once, after `init`: the process is up and takes exchanges. */
  | { readonly type: 'ready' }
  /** The TLS handshake of exchange `id` is done. */
  | { readonly type: 'secured'; readonly id: number }
  | { readonly type: 'outcome'; readonly id: number; readonly outcome: ExchangeOutcome };

/**
 * How much later than the pool a fetch process's own connect timer fires. The
 * pool keeps the deadlines and kills a process that passes one; the timer here
 * only ends a connection the pool would otherwise leave to the kill.
 */
const OWN_TIMER_SLACK_MS = 1000;

/**
 * The fetch process: take an exchange from the pool, run it, report, and wait
 * for the next. It holds nothing between exchanges. It exits when the pool's
 * channel closes, so it never outlives the server's process.
 */
function runFetchProcess(send: (message: FromFetchProcess) => void): void {
  // The process is its own: lowering its priority leaves the server's process
  // first in line for the CPU while a host keeps this one inside OpenSSL.
  try {
    setPriority(19);
  } catch {
    // Not permitted: the process still runs, at the default priority.
  }
  // And when memory runs out, Linux ends this process before the server.
  try {
    writeFileSync('/proc/self/oom_score_adj', '1000');
  } catch {
    // Not Linux, or not permitted.
  }
  process.on('disconnect', () => process.exit(0));
  // Never aborted: the pool ends the call by killing the process.
  const noAbort = new AbortController().signal;
  process.on('message', (received: unknown) => {
    // The pool is the server's process, the side this process trusts.
    const message = received as ToFetchProcess;
    if (message.type === 'init') {
      // OpenSSL reads these when it first loads its store, after this.
      const { certFile, certDir } = message.opensslStore;
      if (certFile !== undefined) process.env['SSL_CERT_FILE'] = certFile;
      if (certDir !== undefined) process.env['SSL_CERT_DIR'] = certDir;
      if (message.ca.length > 0) tls.setDefaultCACertificates([...message.ca]);
      tlsDefaults = { ...message.tls };
      send({ type: 'ready' });
      return;
    }
    const { id, job } = message;
    void exchange(
      { ...job, connectTimeoutMs: job.connectTimeoutMs + OWN_TIMER_SLACK_MS },
      dialPinned,
      noAbort,
      () => send({ type: 'secured', id })
    )
      .catch((err: unknown): ExchangeOutcome => ({
        kind: 'failed',
        reason: 'network',
        message: `egress to ${job.hostname} failed: ${err instanceof Error ? err.message : 'unknown error'}`,
      }))
      .then((outcome) => send({ type: 'outcome', id, outcome }));
  });
}

if (process.argv[1] === FETCH_PROCESS_TAG && process.send !== undefined) {
  const toPool = process.send.bind(process);
  runFetchProcess((message) => {
    toPool(message, undefined, undefined, (err: Error | null) => {
      // The pool is gone or the message cannot be sent: nothing left to do.
      if (err) process.exit(1);
    });
  });
}
