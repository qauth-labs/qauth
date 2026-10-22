import type { LookupAddress } from 'node:dns';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer, type Server } from 'node:https';
import { type AddressInfo, connect, isIP, type Socket } from 'node:net';
import { getCACertificates, setDefaultCACertificates } from 'node:tls';

import type { ResolveHost } from '../lib/destination';
import type { EgressTransport } from '../lib/transport';
import { createTestCertificate } from './test-certificate';

/**
 * TEST SUPPORT — a network for the egress client made of local servers.
 *
 * The client refuses loopback, so the tests cannot point it at a local server
 * by name or address. Instead they replace its two network edges:
 *
 * - `resolveHost` answers from a table, so `api.egress.test` "resolves" to the
 *   public address the test chose, and counts every lookup;
 * - `dial` routes a checked address to the local server that stands for it,
 *   and records every address it is asked to dial.
 *
 * Everything between — the checks, TLS with SNI and certificate validation
 * against the URL's host, HTTP, redirects and caps — is the production code.
 * The servers' certificate covers `egress.test` and `*.egress.test`, signed by
 * a CA the test thread trusts while the network is up.
 */
export interface FixtureNetwork {
  readonly transport: EgressTransport;
  /** Host name → its addresses, or a function called at each lookup. */
  readonly dns: Map<string, readonly string[] | (() => readonly string[])>;
  /** Host names looked up, one entry per lookup. */
  readonly lookups: string[];
  /** Addresses the client asked to dial, one list per connection. */
  readonly dialled: string[][];
  /** Stand up a server for `address`. */
  serve(address: string, handler: FixtureHandler): Promise<FixtureServer>;
  /** Send connections to `address` to a local port of the test's own. */
  route(address: string, port: number): void;
  close(): Promise<void>;
}

export type FixtureHandler = (req: IncomingMessage, body: Buffer, res: ServerResponse) => void;

export interface FixtureServer {
  readonly address: string;
  /** Requests the server has read, with their bodies. */
  readonly requests: {
    method: string;
    url: string;
    headers: IncomingMessage['headers'];
    body: Buffer;
  }[];
  /** TCP connections the server has accepted. */
  connections: number;
  handler: FixtureHandler;
}

/** An address no server listens on; dialling an unrouted address goes here. */
const CLOSED_PORT = 1;

export async function createFixtureNetwork(): Promise<FixtureNetwork> {
  const ca = createTestCertificate({ subject: 'egress test CA' });
  const leaf = createTestCertificate({
    subject: 'egress.test',
    issuer: ca,
    dnsNames: ['egress.test', '*.egress.test'],
  });
  const trustedBefore = getCACertificates('default');
  setDefaultCACertificates([...trustedBefore, ca.pem]);

  const dns = new Map<string, readonly string[] | (() => readonly string[])>();
  const lookups: string[] = [];
  const dialled: string[][] = [];
  const ports = new Map<string, number>();
  const servers: Server[] = [];
  const sockets = new Set<Socket>();

  const resolveHost: ResolveHost = async (hostname) => {
    lookups.push(hostname);
    const entry = dns.get(hostname);
    if (entry === undefined) {
      throw Object.assign(new Error(`queryA ENOTFOUND ${hostname}`), { code: 'ENOTFOUND' });
    }
    const addresses = typeof entry === 'function' ? entry() : entry;
    return addresses.map((address): LookupAddress => ({ address, family: isIP(address) }));
  };

  const transport: EgressTransport = {
    resolveHost,
    dial: (_hostname, addresses) => {
      dialled.push(addresses.map(({ address }) => address));
      return connect(ports.get(addresses[0].address) ?? CLOSED_PORT, '127.0.0.1');
    },
  };

  const serve = async (address: string, handler: FixtureHandler): Promise<FixtureServer> => {
    const fixture: FixtureServer = { address, requests: [], connections: 0, handler };
    const server = createServer({ key: leaf.keyPem, cert: leaf.pem }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        const body = Buffer.concat(chunks);
        fixture.requests.push({
          method: req.method ?? '',
          url: req.url ?? '',
          headers: req.headers,
          body,
        });
        fixture.handler(req, body, res);
      });
    });
    server.on('connection', (socket: Socket) => {
      fixture.connections += 1;
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    ports.set(address, (server.address() as AddressInfo).port);
    servers.push(server);
    return fixture;
  };

  const close = async (): Promise<void> => {
    setDefaultCACertificates(trustedBefore);
    for (const socket of sockets) socket.destroy();
    await Promise.all(
      servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve())))
    );
  };

  const route = (address: string, port: number): void => {
    ports.set(address, port);
  };

  return { transport, dns, lookups, dialled, serve, route, close };
}
