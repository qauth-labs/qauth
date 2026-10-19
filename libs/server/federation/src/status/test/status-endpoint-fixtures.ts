import { request as httpRequest, type RequestOptions } from 'node:http';
import type { request } from 'node:https';
import { type AddressInfo, createServer, type Socket } from 'node:net';

import { STATUS_LIST_TOKEN_MEDIA_TYPE } from '../status-list-spec';

/**
 * A status endpoint on a real loopback socket, for the #297 transport tests.
 *
 * Raw bytes over `node:net` rather than an HTTP server, because what the
 * transport has to survive is how a peer frames its answer and when it hangs
 * up — exactly what a server library decides on the test's behalf. A stubbed
 * response object never reaches the HTTP parser at all, which is where an
 * abandoned body does its damage.
 *
 * Plain TCP, because TLS is not under test: `node:https` and `node:http` share
 * one client and differ only in the socket under it.
 */
export interface TestStatusEndpoint {
  /** `node:https`'s `request`, re-aimed at this endpoint whatever host the URI names. */
  readonly request: typeof request;
  /** The head of every request received, in order. */
  readonly requests: string[];
  /** Resolves once every connection accepted so far is closed, by either side. */
  hungUp(): Promise<void>;
  close(): Promise<void>;
}

/**
 * Start an endpoint.
 *
 * @param respond - called with the connection once a request has arrived on it.
 */
export async function startTestStatusEndpoint(
  respond: (socket: Socket) => void
): Promise<TestStatusEndpoint> {
  const requests: string[] = [];
  const sockets: Socket[] = [];
  const closed: Promise<void>[] = [];

  const server = createServer((socket) => {
    sockets.push(socket);
    closed.push(new Promise((resolve) => socket.once('close', () => resolve())));
    socket.on('error', () => undefined);
    socket.once('data', (head) => {
      requests.push(head.toString('latin1'));
      respond(socket);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  return {
    request: ((uri: string, options: RequestOptions) =>
      httpRequest(`http://127.0.0.1:${port}${new URL(uri).pathname}`, options)) as typeof request,
    requests,
    hungUp: async () => {
      await Promise.all(closed);
    },
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** The bytes of an HTTP/1.1 response from a server that does not keep connections alive. */
export function httpResponseBytes(
  body: string | Buffer,
  init: {
    status?: number;
    contentType?: string | null;
    headers?: Record<string, string>;
  } = {}
): Buffer {
  const headers: Record<string, string> = {
    ...(init.contentType === null
      ? {}
      : { 'Content-Type': init.contentType ?? STATUS_LIST_TOKEN_MEDIA_TYPE }),
    'Content-Length': String(Buffer.byteLength(body)),
    Connection: 'close',
    ...init.headers,
  };
  const head = [
    `HTTP/1.1 ${init.status ?? 200} Status`,
    ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
  ].join('\r\n');
  return Buffer.concat([Buffer.from(`${head}\r\n\r\n`, 'latin1'), Buffer.from(body)]);
}
