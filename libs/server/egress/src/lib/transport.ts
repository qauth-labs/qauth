import type { LookupAddress } from 'node:dns';
import { Resolver } from 'node:dns/promises';
import type { IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as netConnect, type Socket } from 'node:net';
import { connect as tlsConnect, DEFAULT_CIPHERS } from 'node:tls';

import type { CheckedUrl, ResolveHost } from './destination';
import { EgressFailure } from './errors';

/**
 * Opens a TCP connection to one of `addresses` — already checked — on `port`.
 * `hostname` is the URL's host; it is never resolved again.
 */
export type Dial = (hostname: string, addresses: readonly LookupAddress[], port: number) => Socket;

/** What the client needs from the network. Tests replace both. */
export interface EgressTransport {
  readonly resolveHost: ResolveHost;
  readonly dial: Dial;
}

/**
 * Per-query bounds of the c-ares resolver: how long one query waits for an
 * answer, and how often it is sent. The call's deadline cancels what is left.
 */
const DNS_QUERY_TIMEOUT_MS = 2000;
const DNS_QUERY_TRIES = 2;

/**
 * Every A and AAAA record of `hostname`, from c-ares, never from
 * `dns.lookup()`. That one is a blocking getaddrinfo(3) on the libuv thread
 * pool, which the whole process shares, and nothing cancels it: a name server
 * that never answers would hold those threads past every deadline. c-ares
 * queries run on the event loop, each with its own timeout, and the call's
 * signal cancels them. It also reads neither `/etc/hosts` nor any other local
 * source, only DNS. One family failing (a v4-only host has no AAAA) is not an
 * error as long as the other one answered.
 */
export const resolveWithCares: ResolveHost = async (hostname, { timeoutMs, signal }) => {
  const resolver = new Resolver({
    timeout: Math.min(DNS_QUERY_TIMEOUT_MS, timeoutMs),
    tries: DNS_QUERY_TRIES,
  });
  const cancel = (): void => resolver.cancel();
  signal.addEventListener('abort', cancel, { once: true });
  try {
    const [a, aaaa] = await Promise.allSettled([
      resolver.resolve4(hostname),
      resolver.resolve6(hostname),
    ]);
    const addresses: LookupAddress[] = [];
    if (a.status === 'fulfilled') {
      addresses.push(...a.value.map((address) => ({ address, family: 4 })));
    }
    if (aaaa.status === 'fulfilled') {
      addresses.push(...aaaa.value.map((address) => ({ address, family: 6 })));
    }
    if (addresses.length === 0 && a.status === 'rejected') throw a.reason;
    return addresses;
  } finally {
    signal.removeEventListener('abort', cancel);
  }
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

/** The network the client uses outside tests. */
export const NODE_TRANSPORT: EgressTransport = Object.freeze({
  resolveHost: resolveWithCares,
  dial: dialPinned,
});

/**
 * Cipher list. Finite-field DHE is left out: a host can name a 10 000-bit
 * group in its ServerKeyExchange and make the client compute in it (about a
 * second of CPU per handshake). ECDHE and TLS 1.3 are unaffected.
 */
const EGRESS_CIPHERS = `${DEFAULT_CIPHERS}:!kDHE`;

/** Largest response head, in bytes, whatever `--max-http-header-size` says. */
const MAX_HEADER_BYTES = 16 * 1024;

/**
 * 1xx interim responses tolerated ahead of the final response: room for a
 * `103 Early Hints` or two, not for a stream of them.
 */
const MAX_INTERIM_RESPONSES = 3;

/** Statuses that are redirects when they carry a `Location`. */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/** One request on one connection. */
export interface Exchange {
  readonly target: CheckedUrl;
  readonly addresses: readonly LookupAddress[];
  readonly method: string;
  /** Lower-case names. The exchange adds `host`, `connection` and `content-length`. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer | undefined;
  readonly connectTimeoutMs: number;
  readonly maxResponseBytes: number;
  /** Aborted when the call's total time runs out. */
  readonly signal: AbortSignal;
}

/** The answer to one {@link Exchange}. */
export interface ExchangeResult {
  readonly status: number;
  /** Lower-case names; a repeated header's values joined with `, `. */
  readonly headers: Record<string, string>;
  /** Empty for a redirect, which is not read. */
  readonly body: Buffer;
  /** The `Location` of a redirect, which the caller decides whether to follow. */
  readonly location: string | undefined;
}

function responseHeaders(res: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(res.headers)) {
    if (value === undefined) continue;
    headers[name] = Array.isArray(value) ? value.join(', ') : value;
  }
  return headers;
}

/** The `Host` header of a checked URL: brackets around IPv6, port unless 443. */
function hostHeader(target: CheckedUrl): string {
  const host = target.literalFamily === 6 ? `[${target.hostname}]` : target.hostname;
  return target.port === 443 ? host : `${host}:${target.port}`;
}

/**
 * Send one request over a connection of its own, to a checked address, and
 * read the answer within the caps. TLS names the URL's host in SNI and checks
 * the certificate against it, whichever address was dialled. No agent is
 * involved: nothing is pooled, and no proxy setting of the environment or of
 * Node's global agents can route the connection elsewhere, where the address
 * checks would not reach.
 */
export function exchange(job: Exchange, dial: Dial): Promise<ExchangeResult> {
  return new Promise((resolve, reject) => {
    const { target } = job;
    let settled = false;
    // The TCP socket and the TLS socket over it; both are destroyed at the end.
    const sockets: Socket[] = [];

    // Connect time runs from here to the end of the TLS handshake.
    const connectTimer = setTimeout(
      () =>
        fail(
          new EgressFailure(
            'timeout',
            'failed',
            `egress to ${target.hostname} failed: the connection timed out`
          )
        ),
      job.connectTimeoutMs
    );

    const finish = (outcome: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(connectTimer);
      job.signal.removeEventListener('abort', onAbort);
      for (const socket of sockets) socket.destroy();
      outcome();
    };
    const fail = (failure: EgressFailure): void => finish(() => reject(failure));
    const failed = (what: string): EgressFailure =>
      new EgressFailure('network', 'failed', `egress to ${target.hostname} failed: ${what}`);

    const onAbort = (): void =>
      fail(
        new EgressFailure(
          'timeout',
          'failed',
          `egress to ${target.hostname} failed: the call timed out`
        )
      );
    if (job.signal.aborted) {
      onAbort();
      return;
    }
    job.signal.addEventListener('abort', onAbort, { once: true });

    let tcp: Socket;
    try {
      tcp = dial(target.hostname, job.addresses, target.port);
    } catch (err) {
      fail(failed(err instanceof Error ? err.message : 'could not connect'));
      return;
    }
    sockets.push(tcp);
    tcp.on('error', (err) => fail(failed(err.message)));
    const tls = tlsConnect({
      socket: tcp,
      host: target.hostname,
      // RFC 6066 has no SNI for an IP literal; the certificate is then checked
      // against the address.
      ...(target.literalFamily === 0 ? { servername: target.hostname } : {}),
      ciphers: EGRESS_CIPHERS,
      ALPNProtocols: ['http/1.1'],
      // Explicit, so NODE_TLS_REJECT_UNAUTHORIZED=0 cannot turn it off.
      rejectUnauthorized: true,
    });
    sockets.push(tls);
    tls.on('error', (err) => fail(failed(err.message)));
    tls.once('secureConnect', () => clearTimeout(connectTimer));

    const headers: Record<string, string> = {
      ...job.headers,
      host: hostHeader(target),
      connection: 'close',
    };
    if (job.body !== undefined) headers['content-length'] = String(job.body.length);

    const req = httpsRequest(
      {
        method: job.method,
        host: target.hostname,
        port: target.port,
        path: `${target.url.pathname}${target.url.search}`,
        headers,
        setHost: false,
        maxHeaderSize: MAX_HEADER_BYTES,
        insecureHTTPParser: false,
        createConnection: () => tls,
      },
      (res) => {
        const status = res.statusCode ?? 0;
        const resHeaders = responseHeaders(res);
        const location = resHeaders['location'];
        if (REDIRECT_STATUSES.has(status) && location !== undefined) {
          finish(() => resolve({ status, headers: resHeaders, body: Buffer.alloc(0), location }));
          return;
        }

        // A HEAD answer, a 204 and a 304 declare a length they do not send.
        const hasBody = job.method !== 'HEAD' && status !== 204 && status !== 304;
        const declared = Number(resHeaders['content-length']);
        if (hasBody && Number.isFinite(declared) && declared > job.maxResponseBytes) {
          fail(tooLarge());
          return;
        }
        let received = 0;
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => {
          received += chunk.length;
          if (received > job.maxResponseBytes) {
            fail(tooLarge());
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () =>
          finish(() =>
            resolve({
              status,
              headers: resHeaders,
              body: Buffer.concat(chunks),
              location: undefined,
            })
          )
        );
        res.on('error', (err) => fail(failed(err.message)));
      }
    );
    const tooLarge = (): EgressFailure =>
      new EgressFailure(
        'size',
        'failed',
        `egress to ${target.hostname} failed: the response is larger than ${job.maxResponseBytes} bytes`
      );

    // 1xx responses never reach the response callback, so the byte cap does
    // not see them; a host could stream them until the deadline.
    let interim = 0;
    req.on('information', () => {
      interim += 1;
      if (interim > MAX_INTERIM_RESPONSES) fail(failed('too many interim responses'));
    });
    req.on('error', (err) => fail(failed(err.message)));
    // Once the request has closed the exchange is over, whatever else
    // happened. An unsolicited `101`, which Node answers by dropping the
    // socket, is reported with nothing but 'close'.
    req.on('close', () => fail(failed('the connection closed without a response')));
    req.end(job.body);
  });
}
