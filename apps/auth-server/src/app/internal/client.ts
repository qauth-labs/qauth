import type { IncomingHttpHeaders } from 'node:http';
import { Agent, request as httpsRequest } from 'node:https';
import type { PeerCertificate } from 'node:tls';

import { parsePeerSan, type PeerSan } from '@qauth-labs/server-config';

import { certificateSans, holdsSan } from './peer-certificate';
import { INTERNAL_TLS_VERSION } from './tls-files';

/**
 * THE INTERNAL CLIENT (ADR-019 Decision 8, issue #496).
 *
 * How a role calls another role's internal listener, such as the signer
 * service at SIGNER_URL (#497). Internal traffic, not an outbound call: its
 * destination comes only from the deployment's configuration, never from a
 * realm, a client, a user or a fetched document, so it does not go through
 * the egress client, which refuses the private addresses internal services
 * sit on. It carries its own limits instead:
 *
 * - `https` only, TLS 1.3 only, with this process's certificate and key
 *   (mutual TLS) and only the CA file's certificates trusted;
 * - the server is known by a subject alternative name of its certificate,
 *   `expectedServerSan`, a DNS name or a URI such as a SPIFFE ID, and the
 *   connection is refused before any byte of the request is sent when the
 *   certificate does not hold it; the URL's host name is not what is checked,
 *   so a SPIFFE certificate with no DNS name works;
 * - a keep-alive pool of connections, closed when idle;
 * - every request has a deadline and a cap on the size of its response;
 * - no redirect is followed, and the request never leaves the URL's origin.
 *
 * Errors carry a code and say nothing of the request's or the response's
 * contents.
 */

/** A request's deadline, from its start to the last byte of the response, when nothing else is asked. */
export const DEFAULT_INTERNAL_TIMEOUT_MS = 5_000;

/** The largest response body accepted when nothing else is asked. */
export const DEFAULT_INTERNAL_MAX_RESPONSE_BYTES = 1024 * 1024;

/** The most connections the pool opens to the server at once when nothing else is asked. */
export const DEFAULT_INTERNAL_MAX_SOCKETS = 32;

/**
 * How long an idle pooled connection stays open: below the 72 s Fastify's
 * server keeps one, so the client closes it first, and a request never lands
 * on a connection the server is closing.
 */
const IDLE_SOCKET_TIMEOUT_MS = 30_000;

/** Options for {@link createInternalClient}. */
export interface InternalClientOptions {
  /** The server's base URL, `https` only, such as SIGNER_URL. A path in it prefixes every request's. */
  readonly url: string;
  /** This process's certificate (PEM), INTERNAL_TLS_CERT_PATH's content. */
  readonly cert: string | Buffer;
  /** Its private key (PEM), INTERNAL_TLS_KEY_PATH's content. */
  readonly key: string | Buffer;
  /** The CA certificates (PEM) that issue the server's certificate, INTERNAL_TLS_CA_PATH's content. */
  readonly ca: string | Buffer;
  /**
   * A SAN the server's certificate must hold: a DNS name, or a URI such as
   * `spiffe://example.org/qauth/signer` (`parsePeerSan`).
   */
  readonly expectedServerSan: string;
  /** {@link DEFAULT_INTERNAL_TIMEOUT_MS} unless set. */
  readonly timeoutMs?: number;
  /** {@link DEFAULT_INTERNAL_MAX_RESPONSE_BYTES} unless set. */
  readonly maxResponseBytes?: number;
  /** {@link DEFAULT_INTERNAL_MAX_SOCKETS} unless set. */
  readonly maxSockets?: number;
}

/** The certificate, key and CA of the client's side of mutual TLS. */
export interface InternalClientCredentials {
  readonly cert: string | Buffer;
  readonly key: string | Buffer;
  readonly ca: string | Buffer;
}

/** One request to the internal listener. */
export interface InternalRequest {
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** The path below the base URL, starting with `/`, with any query. */
  readonly path: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string | Uint8Array;
  /** Abort the request early. */
  readonly signal?: AbortSignal;
}

/** The server's answer, whatever its status: the caller decides what a status means. */
export interface InternalResponse {
  readonly status: number;
  readonly headers: IncomingHttpHeaders;
  readonly body: Buffer;
}

/**
 * Why a request has no answer.
 *
 * - `server_identity`: the server's certificate does not hold `expectedServerSan`;
 * - `timeout`: no complete answer within the deadline;
 * - `response_too_large`: the answer is larger than the cap;
 * - `unreachable`: no connection, a handshake that failed (a certificate the
 *   CA file did not issue among them) or a connection that broke;
 * - `aborted`: the caller's signal aborted it;
 * - `closed`: the client was closed.
 */
export type InternalClientErrorCode =
  | 'server_identity'
  | 'timeout'
  | 'response_too_large'
  | 'unreachable'
  | 'aborted'
  | 'closed';

/** A request to the internal listener that has no answer. */
export class InternalClientError extends Error {
  readonly code: InternalClientErrorCode;
  /** The platform's error code behind it, such as `ECONNREFUSED`, when there is one. */
  readonly platformCode?: string;

  constructor(code: InternalClientErrorCode, message: string, platformCode?: string) {
    super(message);
    this.name = 'InternalClientError';
    this.code = code;
    if (platformCode !== undefined) this.platformCode = platformCode;
  }
}

/** A client of one internal listener. */
export interface InternalClient {
  /** Send `request` and read the whole answer, within the deadline and the cap. */
  request(request: InternalRequest): Promise<InternalResponse>;
  /**
   * Use new credentials, such as a rotated certificate, for every request
   * from now on. The requests in flight finish on their connections, which
   * close then.
   */
  reloadCredentials(credentials: InternalClientCredentials): void;
  /** Close every connection. A later request fails with `closed`. */
  close(): void;
}

/** A pool and the requests in flight on it. */
interface Pool {
  readonly agent: Agent;
  active: number;
  retired: boolean;
}

function positiveInteger(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`createInternalClient: ${name} must be a positive integer`);
  }
  return value;
}

/** The base URL, checked: `https`, no credentials, no query or fragment. */
function baseUrl(text: string): URL {
  if (!URL.canParse(text)) throw new TypeError('createInternalClient: url must be a URL');
  const url = new URL(text);
  if (url.protocol !== 'https:') {
    throw new TypeError('createInternalClient: url must be https: internal traffic is mutual TLS');
  }
  if (url.username !== '' || url.password !== '') {
    throw new TypeError('createInternalClient: url must not carry credentials');
  }
  if (url.search !== '' || url.hash !== '') {
    throw new TypeError('createInternalClient: url must not carry a query or a fragment');
  }
  return url;
}

/** The URL of `path` below `base`, on `base`'s origin only. */
function targetOf(base: URL, path: string): URL {
  if (!path.startsWith('/') || path.startsWith('//') || /[\s\\\p{Cc}]/u.test(path)) {
    throw new TypeError(
      'InternalClient.request: path must start with a single / and hold no white space'
    );
  }
  const target = new URL(`${base.pathname.replace(/\/+$/, '')}${path}`, base.origin);
  if (target.origin !== base.origin) {
    throw new TypeError('InternalClient.request: path must stay on the base URL');
  }
  return target;
}

/** Make an internal listener's client: see the module's comment for its limits. */
export function createInternalClient(options: InternalClientOptions): InternalClient {
  const base = baseUrl(options.url);
  const parsedSan = parsePeerSan(options.expectedServerSan);
  if ('problem' in parsedSan) {
    throw new TypeError(
      `createInternalClient: expectedServerSan is not a SAN: ${parsedSan.problem}`
    );
  }
  const expected: PeerSan = parsedSan.san;
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_INTERNAL_TIMEOUT_MS, 'timeoutMs');
  const maxResponseBytes = positiveInteger(
    options.maxResponseBytes,
    DEFAULT_INTERNAL_MAX_RESPONSE_BYTES,
    'maxResponseBytes'
  );
  const maxSockets = positiveInteger(
    options.maxSockets,
    DEFAULT_INTERNAL_MAX_SOCKETS,
    'maxSockets'
  );

  const checkServerIdentity = (_host: string, certificate: PeerCertificate): Error | undefined =>
    holdsSan(certificateSans(certificate.subjectaltname), expected)
      ? undefined
      : new InternalClientError(
          'server_identity',
          `The internal server's certificate does not hold the expected SAN ${expected.type}:${expected.value}`
        );

  const createPool = (credentials: InternalClientCredentials): Pool => ({
    agent: new Agent({
      keepAlive: true,
      maxSockets,
      maxFreeSockets: maxSockets,
      timeout: IDLE_SOCKET_TIMEOUT_MS,
      cert: credentials.cert,
      key: credentials.key,
      ca: credentials.ca,
      minVersion: INTERNAL_TLS_VERSION,
      maxVersion: INTERNAL_TLS_VERSION,
      rejectUnauthorized: true,
      checkServerIdentity,
      // Every connection checks the server's certificate in full: no
      // session is resumed past a rotation or a credential reload.
      maxCachedSessions: 0,
    }),
    active: 0,
    retired: false,
  });

  let pool = createPool(options);
  const retired = new Set<Pool>();
  let closed = false;

  const release = (used: Pool): void => {
    used.active -= 1;
    if (used.retired && used.active === 0) {
      used.agent.destroy();
      retired.delete(used);
    }
  };

  const send = (request: InternalRequest, used: Pool): Promise<InternalResponse> =>
    new Promise((resolve, reject) => {
      const target = targetOf(base, request.path);
      if (request.signal?.aborted) {
        reject(new InternalClientError('aborted', 'The internal request was aborted'));
        return;
      }
      const body = request.body === undefined ? undefined : Buffer.from(request.body);
      const outgoing = httpsRequest(target, {
        method: request.method,
        agent: used.agent,
        headers: {
          ...request.headers,
          ...(body === undefined ? {} : { 'content-length': String(body.length) }),
        },
      });
      let settled = false;
      const finish = (outcome: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        request.signal?.removeEventListener('abort', onAbort);
        outcome();
      };
      const fail = (error: InternalClientError): void => {
        finish(() => {
          outgoing.destroy();
          reject(error);
        });
      };
      const onAbort = (): void =>
        fail(new InternalClientError('aborted', 'The internal request was aborted'));
      const deadline = setTimeout(() => {
        fail(
          new InternalClientError(
            'timeout',
            `The internal server did not answer within ${timeoutMs} ms`
          )
        );
      }, timeoutMs);
      request.signal?.addEventListener('abort', onAbort, { once: true });

      outgoing.on('error', (error: NodeJS.ErrnoException) => {
        if (error instanceof InternalClientError) {
          fail(error);
          return;
        }
        fail(
          new InternalClientError(
            'unreachable',
            `The internal server could not be reached${error.code === undefined ? '' : ` (${error.code})`}`,
            error.code
          )
        );
      });
      outgoing.on('response', (response) => {
        const tooLarge = (): void =>
          fail(
            new InternalClientError(
              'response_too_large',
              `The internal server's answer is larger than ${maxResponseBytes} bytes`
            )
          );
        const declared = Number(response.headers['content-length']);
        if (Number.isFinite(declared) && declared > maxResponseBytes) {
          tooLarge();
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxResponseBytes) {
            tooLarge();
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          finish(() =>
            resolve({
              status: response.statusCode ?? 0,
              headers: response.headers,
              body: Buffer.concat(chunks),
            })
          );
        });
        response.on('error', () => {
          fail(
            new InternalClientError(
              'unreachable',
              'The internal connection broke during the answer'
            )
          );
        });
        response.on('aborted', () => {
          fail(
            new InternalClientError(
              'unreachable',
              'The internal connection broke during the answer'
            )
          );
        });
      });
      outgoing.end(body);
    });

  return {
    async request(request: InternalRequest): Promise<InternalResponse> {
      if (closed) throw new InternalClientError('closed', 'The internal client is closed');
      const used = pool;
      used.active += 1;
      try {
        return await send(request, used);
      } finally {
        release(used);
      }
    },

    reloadCredentials(credentials: InternalClientCredentials): void {
      if (closed) return;
      const previous = pool;
      pool = createPool(credentials);
      previous.retired = true;
      if (previous.active === 0) previous.agent.destroy();
      else retired.add(previous);
    },

    close(): void {
      closed = true;
      pool.agent.destroy();
      for (const old of retired) old.agent.destroy();
      retired.clear();
    },
  };
}
