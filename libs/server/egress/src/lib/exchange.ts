import type { LookupAddress } from 'node:dns';
import { closeSync, fstatSync, writeFileSync } from 'node:fs';
import type { IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as netConnect, Socket } from 'node:net';
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

/**
 * Largest response head, in bytes, whatever `--max-http-header-size` says.
 * The names and values of the response's headers together are no larger, so
 * it bounds them too, on both sides of the channel.
 */
export const MAX_HEADER_BYTES = 16 * 1024;

/** Response headers an exchange returns, at most, counting a repeated one once. */
export const MAX_RESPONSE_HEADERS = 100;

/** Longest response header name, in bytes. */
export const MAX_HEADER_NAME_BYTES = 256;

/** Longest response header value, in bytes, a repeated header's values joined. */
export const MAX_HEADER_VALUE_BYTES = 8 * 1024;

/** Longest redirect `Location`, in bytes. */
export const MAX_LOCATION_BYTES = 8 * 1024;

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

/**
 * Why a response head is beyond what an exchange returns, or `undefined`.
 * Node's parser has already held the head to {@link MAX_HEADER_BYTES}; these
 * are the bounds the pool holds a fetch process's answer to, applied here
 * first, so that a host's unusual response fails with its reason rather than
 * as an answer the pool refuses. Node gives header names and values as
 * Latin-1, one character per byte, so a length is a byte count.
 */
export function responseHeadProblem(
  headers: Readonly<Record<string, string>>,
  location: string | undefined
): string | undefined {
  const entries = Object.entries(headers);
  if (entries.length > MAX_RESPONSE_HEADERS) {
    return `the response has more than ${MAX_RESPONSE_HEADERS} headers`;
  }
  let bytes = 0;
  for (const [name, value] of entries) {
    if (name.length > MAX_HEADER_NAME_BYTES) {
      return `a response header name is longer than ${MAX_HEADER_NAME_BYTES} bytes`;
    }
    if (value.length > MAX_HEADER_VALUE_BYTES) {
      return `a response header value is longer than ${MAX_HEADER_VALUE_BYTES} bytes`;
    }
    bytes += name.length + value.length;
  }
  if (bytes > MAX_HEADER_BYTES)
    return `the response headers are larger than ${MAX_HEADER_BYTES} bytes`;
  if (location !== undefined && location.length > MAX_LOCATION_BYTES) {
    return `the redirect location is longer than ${MAX_LOCATION_BYTES} bytes`;
  }
  return undefined;
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
          const redirect = REDIRECT_STATUSES.has(status) && location !== undefined;
          const problem = responseHeadProblem(resHeaders, redirect ? location : undefined);
          if (problem !== undefined) {
            failed(problem);
            return;
          }
          if (redirect) {
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
/*                           The channel to the pool                          */
/* -------------------------------------------------------------------------- */

/*
 * The pool and a fetch process talk over one socket, the process's descriptor
 * 3, in frames: a five-byte header, which is the frame's type (one byte) and
 * the length of its payload (four bytes, big-endian), then the payload.
 *
 * A fetch process is the side the server does not trust: a host may have
 * taken it over. So the pool checks each header against what the process may
 * send at that moment, and refuses a frame of another type, or one longer than
 * the cap of its type, before it reads a byte of its payload. What a process
 * sends has a fixed binary layout, and each field is checked against its own
 * bound before it is read. Node's IPC channel, used before, did neither: it
 * deserialized a whole message, of any size, before the pool saw it.
 *
 * The pool's own frames come from the side a fetch process trusts, and carry
 * JSON.
 */

/** The bytes of a frame's header: its type and its payload's length. */
export const FRAME_HEADER_BYTES = 5;

/** The largest payload a frame's four-byte length can announce. */
export const MAX_FRAME_PAYLOAD_BYTES = 0xffff_ffff;

/** Frame types. The pool sends `init` and `exchange`; a fetch process the rest. */
export const FRAME = Object.freeze({
  /** First, once: {@link FetchProcessInit} as JSON. */
  init: 1,
  /** One exchange at a time; the next only after the outcome of this one ({@link encodeExchange}). */
  exchange: 2,
  /** Once, after `init`, empty: the process is up and takes exchanges. */
  ready: 3,
  /** The id of an exchange whose TLS handshake is done ({@link encodeSecured}). */
  secured: 4,
  /** The outcome of an exchange that has a response ({@link encodeOutcome}). */
  response: 5,
  /** The outcome of an exchange that failed ({@link encodeOutcome}). */
  failure: 6,
} as const);

/**
 * The reasons a fetch process may give for a failure, each sent as its index
 * here. `busy` is the pool's own.
 */
export const FETCH_PROCESS_FAILURE_REASONS: readonly ExchangeFailureReason[] = Object.freeze([
  'timeout',
  'network',
  'size',
]);

/** Longest failure message a fetch process sends, in bytes of UTF-8; the pool keeps less. */
export const MAX_FAILURE_MESSAGE_BYTES = 2 * 1024;

/** The payload of a `secured` frame: the exchange's id. */
export const SECURED_PAYLOAD_BYTES = 4;

/** The largest payload of a `failure` frame: id, reason, the message's length and the message. */
export const MAX_FAILURE_PAYLOAD_BYTES = 4 + 1 + 2 + MAX_FAILURE_MESSAGE_BYTES;

/**
 * The largest payload of a `response` frame without its body: id, status,
 * header count, each header with the lengths of its name and value, the
 * location's flag, length and bytes.
 */
export const MAX_RESPONSE_FIELDS_BYTES =
  4 + 2 + 2 + MAX_RESPONSE_HEADERS * 4 + MAX_HEADER_BYTES + 1 + 2 + MAX_LOCATION_BYTES;

/** A frame of `type` with `parts` as its payload: the buffers to write, in order. */
export function encodeFrame(type: number, parts: readonly Uint8Array[] = []): Uint8Array[] {
  let length = 0;
  for (const part of parts) length += part.byteLength;
  if (length > MAX_FRAME_PAYLOAD_BYTES) {
    throw new RangeError(`a frame payload of ${length} bytes is too large`);
  }
  const header = Buffer.alloc(FRAME_HEADER_BYTES);
  header.writeUInt8(type, 0);
  header.writeUInt32BE(length, 1);
  return [header, ...parts.filter((part) => part.byteLength > 0)];
}

/** How a frame reader treats the frames of its channel. */
export interface FrameRules {
  /**
   * The largest payload a frame of `type` may carry now, or `undefined` when
   * no frame of that type may come now. Asked once a frame's header is in,
   * after every earlier frame was handled.
   */
  limit(type: number): number | undefined;
  /** A whole frame. `false` stops the reader. */
  frame(type: number, payload: Buffer): boolean;
  /**
   * A frame refused from its header, before any of its payload was read:
   * `oversized` when a frame of its type may come now, but not that long.
   * The reader takes nothing more.
   */
  refuse(type: number, length: number, oversized: boolean): void;
}

/**
 * Reads the frames of a stream from its chunks: `push(chunk)` for each. It
 * keeps a frame's header and, once the header has passed its limit, a buffer
 * of the payload's length; never a chunk, and nothing after a refused header.
 * `push` returns `false` once the reader has stopped.
 */
export function createFrameReader(rules: FrameRules): (chunk: Buffer) => boolean {
  const header = Buffer.alloc(FRAME_HEADER_BYTES);
  let headerFill = 0;
  let type = 0;
  let payload: Buffer | undefined;
  let payloadFill = 0;
  let stopped = false;

  return (chunk) => {
    let at = 0;
    while (!stopped) {
      if (payload === undefined) {
        if (at === chunk.length) break;
        const n = Math.min(FRAME_HEADER_BYTES - headerFill, chunk.length - at);
        chunk.copy(header, headerFill, at, at + n);
        headerFill += n;
        at += n;
        if (headerFill < FRAME_HEADER_BYTES) break;
        headerFill = 0;
        type = header.readUInt8(0);
        const length = header.readUInt32BE(1);
        const limit = rules.limit(type);
        if (limit === undefined || length > limit) {
          stopped = true;
          rules.refuse(type, length, limit !== undefined);
          break;
        }
        payload = Buffer.alloc(length);
        payloadFill = 0;
      }
      const n = Math.min(payload.length - payloadFill, chunk.length - at);
      chunk.copy(payload, payloadFill, at, at + n);
      payloadFill += n;
      at += n;
      if (payloadFill < payload.length) break;
      const whole = payload;
      payload = undefined;
      if (!rules.frame(type, whole)) stopped = true;
    }
    return !stopped;
  };
}

/** How the server's process sets up TLS, which a fetch process takes first. */
export interface FetchProcessInit {
  /**
   * The server's trust store, as PEM. Empty when the server uses OpenSSL's
   * store (`--use-openssl-ca`), which the process then uses too.
   */
  readonly ca: readonly string[];
  readonly tls: TlsDefaults;
  /** `SSL_CERT_FILE` and `SSL_CERT_DIR` of the server, for OpenSSL's store. */
  readonly opensslStore: { readonly certFile?: string; readonly certDir?: string };
}

/** The pool's `init` frame. */
export function encodeInit(init: FetchProcessInit): Uint8Array[] {
  return encodeFrame(FRAME.init, [Buffer.from(JSON.stringify(init), 'utf8')]);
}

/** The head of an `exchange` frame: the job but its body. */
interface ExchangeHead {
  readonly id: number;
  readonly job: Omit<ExchangeJob, 'body'>;
  readonly hasBody: boolean;
}

/**
 * The pool's `exchange` frame: the length of a JSON head (u32), the head (the
 * id and the job without its body) and the body's bytes.
 */
export function encodeExchange(id: number, job: ExchangeJob): Uint8Array[] {
  const { body, ...rest } = job;
  const head: ExchangeHead = { id, job: rest, hasBody: body !== undefined };
  const headBytes = Buffer.from(JSON.stringify(head), 'utf8');
  const headLength = Buffer.alloc(4);
  headLength.writeUInt32BE(headBytes.length);
  return encodeFrame(
    FRAME.exchange,
    body === undefined ? [headLength, headBytes] : [headLength, headBytes, body]
  );
}

function decodeExchange(payload: Buffer): { id: number; job: ExchangeJob } {
  const headLength = payload.readUInt32BE(0);
  const head = JSON.parse(payload.toString('utf8', 4, 4 + headLength)) as ExchangeHead;
  return {
    id: head.id,
    job: { ...head.job, body: head.hasBody ? payload.subarray(4 + headLength) : undefined },
  };
}

/** A fetch process's `ready` frame. */
export function encodeReady(): Uint8Array[] {
  return encodeFrame(FRAME.ready);
}

/** A fetch process's `secured` frame: the exchange's id (u32). */
export function encodeSecured(id: number): Uint8Array[] {
  const payload = Buffer.alloc(SECURED_PAYLOAD_BYTES);
  payload.writeUInt32BE(id);
  return encodeFrame(FRAME.secured, [payload]);
}

/** `text` in UTF-8, cut at a character boundary to `maxBytes` at most. */
function utf8Prefix(text: string, maxBytes: number): Buffer {
  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length <= maxBytes) return bytes;
  let end = maxBytes;
  // A continuation byte (10xxxxxx) after the cut: the cut is inside a
  // character, which is left out whole.
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
  return bytes.subarray(0, end);
}

/**
 * A fetch process's frame for the outcome of exchange `id`.
 *
 * - `failure`: the id (u32), the reason (u8, its index in
 *   {@link FETCH_PROCESS_FAILURE_REASONS}), the message's length (u16) and the
 *   message in UTF-8, cut to {@link MAX_FAILURE_MESSAGE_BYTES}.
 * - `response`: the id (u32), the status (u16), the number of headers (u16);
 *   for each header the length of its name (u16), the name, the length of its
 *   value (u16) and the value, in Latin-1 as Node gives them; whether there is
 *   a location (u8, 0 or 1) and, when there is, its length (u16) and the
 *   location in Latin-1; then the body, to the end of the frame. The exchange
 *   has held the fields to their bounds ({@link responseHeadProblem}).
 */
export function encodeOutcome(id: number, outcome: ExchangeOutcome): Uint8Array[] {
  if (outcome.kind === 'failed') {
    const reason = FETCH_PROCESS_FAILURE_REASONS.indexOf(outcome.reason);
    if (reason === -1) throw new RangeError(`a fetch process does not fail with ${outcome.reason}`);
    const message = utf8Prefix(outcome.message, MAX_FAILURE_MESSAGE_BYTES);
    const fields = Buffer.alloc(7);
    fields.writeUInt32BE(id, 0);
    fields.writeUInt8(reason, 4);
    fields.writeUInt16BE(message.length, 5);
    return encodeFrame(FRAME.failure, [fields, message]);
  }
  const entries = Object.entries(outcome.headers);
  const { location } = outcome;
  let length = 4 + 2 + 2 + 1 + (location === undefined ? 0 : 2 + location.length);
  for (const [name, value] of entries) length += 2 + name.length + 2 + value.length;
  const fields = Buffer.alloc(length);
  let at = fields.writeUInt32BE(id, 0);
  at = fields.writeUInt16BE(outcome.status, at);
  at = fields.writeUInt16BE(entries.length, at);
  for (const [name, value] of entries) {
    at = fields.writeUInt16BE(name.length, at);
    at += fields.write(name, at, 'latin1');
    at = fields.writeUInt16BE(value.length, at);
    at += fields.write(value, at, 'latin1');
  }
  at = fields.writeUInt8(location === undefined ? 0 : 1, at);
  if (location !== undefined) {
    at = fields.writeUInt16BE(location.length, at);
    fields.write(location, at, 'latin1');
  }
  return encodeFrame(FRAME.response, [fields, outcome.body]);
}

/** What a fetch process tells the pool, once the pool has checked it. */
export type FromFetchProcess =
  /** Once, after `init`: the process is up and takes exchanges. */
  | { readonly type: 'ready' }
  /** The TLS handshake of exchange `id` is done. */
  | { readonly type: 'secured'; readonly id: number }
  | { readonly type: 'outcome'; readonly id: number; readonly outcome: ExchangeOutcome };

/* -------------------------------------------------------------------------- */
/*                              The fetch process                             */
/* -------------------------------------------------------------------------- */

/** The argument that marks a process started as a fetch process. */
export const FETCH_PROCESS_TAG = 'qauth:egress-fetch-process';

/** The descriptor of a fetch process's channel to the pool (`stdio[3]`). */
export const FETCH_PROCESS_CHANNEL_FD = 3;

/**
 * How much later than the pool a fetch process's own connect timer fires. The
 * pool keeps the deadlines and kills a process that passes one; the timer here
 * only ends a connection the pool would otherwise leave to the kill.
 */
const OWN_TIMER_SLACK_MS = 1000;

/** The frame of an outcome, or of a failure when it cannot be framed. */
function outcomeFrame(id: number, job: ExchangeJob, outcome: ExchangeOutcome): Uint8Array[] {
  try {
    return encodeOutcome(id, outcome);
  } catch {
    return encodeOutcome(id, {
      kind: 'failed',
      reason: 'network',
      message: `egress to ${job.hostname} failed: the outcome could not be sent`,
    });
  }
}

/**
 * The fetch process: take an exchange from the pool, run it, report, and wait
 * for the next. It holds nothing between exchanges. It exits when the pool's
 * end of the channel closes, so it never outlives the server's process.
 */
function runFetchProcess(channel: Socket): void {
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
  const send = (parts: readonly Uint8Array[]): void => {
    for (const part of parts) {
      channel.write(part, (err?: Error | null) => {
        // The pool is gone: nothing left to do.
        if (err) process.exit(1);
      });
    }
  };
  channel.on('end', () => process.exit(0));
  channel.on('error', () => process.exit(1));
  // Never aborted: the pool ends the call by killing the process.
  const noAbort = new AbortController().signal;
  let initialized = false;
  // The pool is the server's process, the side this process trusts: `init`
  // once, then one exchange at a time.
  const read = createFrameReader({
    limit: (type) =>
      type === (initialized ? FRAME.exchange : FRAME.init) ? MAX_FRAME_PAYLOAD_BYTES : undefined,
    frame: (type, payload) => {
      if (type === FRAME.init) {
        const init = JSON.parse(payload.toString('utf8')) as FetchProcessInit;
        // OpenSSL reads these when it first loads its store, after this.
        const { certFile, certDir } = init.opensslStore;
        if (certFile !== undefined) process.env['SSL_CERT_FILE'] = certFile;
        if (certDir !== undefined) process.env['SSL_CERT_DIR'] = certDir;
        if (init.ca.length > 0) tls.setDefaultCACertificates([...init.ca]);
        tlsDefaults = { ...init.tls };
        initialized = true;
        send(encodeReady());
        return true;
      }
      const { id, job } = decodeExchange(payload);
      void exchange(
        { ...job, connectTimeoutMs: job.connectTimeoutMs + OWN_TIMER_SLACK_MS },
        dialPinned,
        noAbort,
        () => send(encodeSecured(id))
      )
        .catch((err: unknown): ExchangeOutcome => ({
          kind: 'failed',
          reason: 'network',
          message: `egress to ${job.hostname} failed: ${err instanceof Error ? err.message : 'unknown error'}`,
        }))
        .then((outcome) => send(outcomeFrame(id, job, outcome)));
      return true;
    },
    refuse: () => process.exit(1),
  });
  channel.on('data', (chunk: Buffer) => {
    read(chunk);
  });
}

/**
 * Closes the descriptors this process got from the server's process beyond
 * its standard streams and channel. The pool lists them as `fd:dev:ino`
 * (`inheritedDescriptors` in `process-pool.ts`): those the server held without
 * close-on-exec, which survive the exec. Node marks the descriptors it opens,
 * and a low few it inherits, close-on-exec, but a supervisor such as a CI
 * runner can hand the server higher ones, and libuv's spawn closes nothing.
 *
 * A descriptor is closed only when it is the same file here (device and
 * inode), so none this process opened itself at that number is touched.
 */
export function closeInheritedDescriptors(list: string | undefined): void {
  if (!list) return;
  for (const entry of list.split(',')) {
    const [fdText, dev, ino] = entry.split(':');
    const fd = Number(fdText);
    if (!Number.isInteger(fd) || fd <= FETCH_PROCESS_CHANNEL_FD) continue;
    try {
      const stat = fstatSync(fd, { bigint: true });
      if (String(stat.dev) === dev && String(stat.ino) === ino) closeSync(fd);
    } catch {
      // Not open here: nothing to close.
    }
  }
}

/** This process's end of the channel, or `undefined` when descriptor 3 is not a socket. */
function openChannel(): Socket | undefined {
  try {
    if (!fstatSync(FETCH_PROCESS_CHANNEL_FD).isSocket()) return undefined;
    return new Socket({ fd: FETCH_PROCESS_CHANNEL_FD, readable: true, writable: true });
  } catch {
    return undefined;
  }
}

if (process.argv[1] === FETCH_PROCESS_TAG) {
  // First, before any frame: nothing of the server's process but the channel.
  closeInheritedDescriptors(process.argv[2]);
  const channel = openChannel();
  if (channel === undefined) process.exit(1);
  else runFetchProcess(channel);
}
