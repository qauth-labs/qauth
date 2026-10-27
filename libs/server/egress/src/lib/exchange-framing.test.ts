import type { AddressInfo } from 'node:net';
import {
  createServer as createTlsServer,
  getCACertificates,
  type Server as TlsServer,
  setDefaultCACertificates,
  type TLSSocket,
} from 'node:tls';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createTestCertificate } from '../testing/test-certificate';
import { createTestEgressClient } from './egress-client';
import { EgressError } from './errors';

/*
 * How the exchange reads a response a host frames by hand, over a raw TLS
 * server on localhost reached through the test client (issue #481). Ported
 * from the tests of the auth server's former fetcher (`ssrf-fetch-worker.ts`),
 * whose regressions they keep: a deadline that every byte restarted
 * (ANT-2026-UE3G2DW3), and 1xx responses that no cap counted.
 */

let server: TlsServer;
let port: number;
const sockets = new Set<TLSSocket>();
/** What the host does once it has read the request; set per test. */
let respond: (write: (bytes: string) => void, socket: TLSSocket) => void;
const trustedBefore = getCACertificates('default');

beforeAll(async () => {
  const ca = createTestCertificate({ subject: 'egress framing test CA' });
  const leaf = createTestCertificate({ subject: 'localhost', issuer: ca, dnsNames: ['localhost'] });
  setDefaultCACertificates([...trustedBefore, ca.pem]);
  server = createTlsServer({ key: leaf.keyPem, cert: leaf.pem }, (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => undefined);
    socket.once('data', () =>
      respond((bytes) => {
        if (!socket.destroyed) socket.write(bytes);
      }, socket)
    );
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  setDefaultCACertificates(trustedBefore);
  for (const socket of sockets) socket.destroy();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

// The deadline the timeout tests trip. A test that must NOT reach it gets
// IN_TIME_MS: the first exchange in a process is cold (TLS context, CA store).
const DEADLINE_MS = 400;
const IN_TIME_MS = 4000;

const fetchFixture = (totalTimeoutMs = DEADLINE_MS) =>
  createTestEgressClient().request({
    method: 'GET',
    url: `https://localhost:${port}/doc.json`,
    purpose: 'test',
    source: 'client',
    limits: {
      totalTimeoutMs,
      connectTimeoutMs: Math.min(totalTimeoutMs, 4000),
      maxResponseBytes: 4096,
    },
  });

/** The EgressError a call rejects with. */
async function refusal(call: Promise<unknown>): Promise<EgressError> {
  const err = await call.then(
    () => undefined,
    (e: unknown) => e
  );
  expect(err).toBeInstanceOf(EgressError);
  return err as EgressError;
}

/** Run `send` every `ms` until the socket closes. */
const every = (ms: number, socket: TLSSocket, send: () => void) => {
  const timer = setInterval(send, ms);
  socket.on('close', () => clearInterval(timer));
};

describe('response framing', () => {
  it('returns a response that completes in time, early hints included', async () => {
    respond = (write) =>
      write(
        'HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n' +
          'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}'
      );
    const res = await fetchFixture(IN_TIME_MS);
    expect(res.status).toBe(200);
    expect(res.body.toString()).toBe('{}');
  });

  it('returns a body the host delimits by closing the connection', async () => {
    respond = (write, socket) => {
      write('HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{"a":1}');
      socket.end();
    };
    const res = await fetchFixture(IN_TIME_MS);
    expect(res.status).toBe(200);
    expect(res.body.toString()).toBe('{"a":1}');
  });

  it('gives up on a host that drips one body byte at a time', async () => {
    respond = (write, socket) => {
      write('HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n');
      every(50, socket, () => write(' '));
    };
    const started = performance.now();
    await expect(refusal(fetchFixture())).resolves.toMatchObject({ reason: 'timeout' });
    expect(performance.now() - started).toBeLessThan(DEADLINE_MS + 1500);
  }, 10_000);

  it('gives up on a host that keeps sending 1xx interim responses', async () => {
    respond = (write, socket) => every(150, socket, () => write('HTTP/1.1 102 Processing\r\n\r\n'));
    await expect(refusal(fetchFixture())).resolves.toMatchObject({ reason: 'timeout' });
  }, 10_000);

  // 1xx responses never reach the response callback, so without a cap of its
  // own a host could stream them as fast as it can.
  it('hangs up on a stream of 1xx interim responses before the deadline', async () => {
    respond = (write) => write('HTTP/1.1 102 Processing\r\n\r\n'.repeat(100));
    const err = await refusal(fetchFixture(IN_TIME_MS));
    expect(err).toMatchObject({ reason: 'network', outcome: 'failed' });
    expect(err.message).toContain('too many interim responses');
  }, 10_000);

  // Node answers an unsolicited `101` by dropping the socket, and the request
  // then emits nothing but 'close'.
  it('settles when the host answers with an unsolicited 101 upgrade', async () => {
    respond = (write) =>
      write('HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\n');
    const err = await refusal(fetchFixture(IN_TIME_MS));
    expect(err.reason).not.toBe('timeout');
  }, 10_000);
});
