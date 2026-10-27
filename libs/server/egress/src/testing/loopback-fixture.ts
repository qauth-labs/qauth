import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer } from 'node:https';
import type { AddressInfo, Socket } from 'node:net';
import { getCACertificates, setDefaultCACertificates } from 'node:tls';

import { createTestCertificate } from './test-certificate';

/**
 * TEST SUPPORT — an HTTPS server on 127.0.0.1 with a certificate for
 * `localhost`, for a test that reaches it through `createTestEgressClient`
 * (issue #481). Its CA is trusted by this process while the server is up.
 * The production egress client refuses it: loopback is never public.
 */
export interface LocalHttpsFixture {
  /** `https://localhost:<port>`, without a trailing slash. */
  readonly origin: string;
  readonly port: number;
  /** Requests the server has read, with their bodies. */
  readonly requests: { method: string; url: string; body: Buffer }[];
  /** TCP connections the server has accepted. */
  connections: number;
  handler: LocalFixtureHandler;
  close(): Promise<void>;
}

export type LocalFixtureHandler = (req: IncomingMessage, body: Buffer, res: ServerResponse) => void;

const answerOk: LocalFixtureHandler = (_req, _body, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('local fixture');
};

export async function startLocalHttpsFixture(
  handler: LocalFixtureHandler = answerOk
): Promise<LocalHttpsFixture> {
  const ca = createTestCertificate({ subject: 'egress local fixture CA' });
  const leaf = createTestCertificate({ subject: 'localhost', issuer: ca, dnsNames: ['localhost'] });

  const requests: LocalHttpsFixture['requests'] = [];
  const sockets = new Set<Socket>();
  const state = { connections: 0, handler };
  const server = createServer({ key: leaf.keyPem, cert: leaf.pem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      requests.push({ method: req.method ?? '', url: req.url ?? '', body });
      state.handler(req, body, res);
    });
  });
  server.on('connection', (socket: Socket) => {
    state.connections += 1;
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  const trustedBefore = getCACertificates('default');
  setDefaultCACertificates([...trustedBefore, ca.pem]);

  return {
    origin: `https://localhost:${port}`,
    port,
    requests,
    get connections() {
      return state.connections;
    },
    set connections(value: number) {
      state.connections = value;
    },
    get handler() {
      return state.handler;
    },
    set handler(value: LocalFixtureHandler) {
      state.handler = value;
    },
    async close() {
      setDefaultCACertificates(trustedBefore);
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
