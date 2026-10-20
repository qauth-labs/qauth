import type { AddressInfo } from 'node:net';
import {
  createServer as createTlsServer,
  getCACertificates,
  type Server as TlsServer,
  setDefaultCACertificates,
  type TLSSocket,
} from 'node:tls';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createTestCertificate, toPkcs8Pem } from '../../testing/x509-der';
import { guardedGet, type GuardedGetOutcome } from './ssrf-fetch-worker';

/*
 * `guardedGet` is what a fetch worker runs. These tests call it on the test's
 * own thread, which is what lets them trust a local CA:
 * `tls.setDefaultCACertificates` applies to the thread that calls it.
 */

describe('guardedGet — timeoutMs bounds the whole fetch', () => {
  let server: TlsServer;
  let port: number;
  const sockets = new Set<TLSSocket>();
  // What the fixture host does once it has read the request; set per test.
  let respond: (write: (bytes: string) => void, socket: TLSSocket) => void;
  const trustedBefore = getCACertificates('default');

  beforeAll(async () => {
    const ca = createTestCertificate({
      subject: 'ssrf-fetch-worker test CA',
      ca: true,
      keyUsage: ['keyCertSign'],
    });
    const host = createTestCertificate({
      subject: 'localhost',
      issuer: ca,
      dnsNames: ['localhost'],
    });
    setDefaultCACertificates([...trustedBefore, ca.pem]);
    server = createTlsServer({ key: toPkcs8Pem(host.privateKey), cert: host.pem }, (socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      socket.on('error', () => undefined);
      socket.on('data', () =>
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

  // The deadline the timeout tests trip. A test that must NOT reach the
  // deadline gets IN_TIME_MS instead: the first fetch in a process is cold
  // (TLS context, CA store), and on a CPU-starved host it has taken over
  // 400 ms and come back as "timed out".
  const DEADLINE_MS = 400;
  const IN_TIME_MS = 4000;

  const fetchFixture = (timeoutMs = DEADLINE_MS): Promise<GuardedGetOutcome> =>
    guardedGet({
      url: `https://localhost:${port}/cimd.json`,
      timeoutMs,
      maxBytes: 4096,
      allowPrivateAddresses: true,
    });

  /** Run `send` every `ms` until the socket closes. */
  const every = (ms: number, socket: TLSSocket, send: () => void) => {
    const timer = setInterval(send, ms);
    socket.on('close', () => clearInterval(timer));
  };

  it('returns a response that completes in time, early hints included', async () => {
    respond = (write) =>
      write(
        'HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n' +
          'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}'
      );
    await expect(fetchFixture(IN_TIME_MS)).resolves.toMatchObject({
      kind: 'response',
      status: 200,
      body: '{}',
    });
  });

  it('returns a body the host delimits by closing the connection', async () => {
    respond = (write, socket) => {
      write('HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{"a":1}');
      socket.end();
    };
    await expect(fetchFixture(IN_TIME_MS)).resolves.toMatchObject({
      kind: 'response',
      status: 200,
      body: '{"a":1}',
    });
  });

  // Regression (ANT-2026-UE3G2DW3): the only time bound was the socket's idle
  // timer, which every byte from the host restarts.
  it('gives up on a host that drips one body byte at a time', async () => {
    respond = (write, socket) => {
      write('HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n');
      every(50, socket, () => write(' '));
    };
    const started = performance.now();
    await expect(fetchFixture()).resolves.toEqual({
      kind: 'failed',
      message: 'CIMD fetch timed out',
    });
    expect(performance.now() - started).toBeLessThan(1500);
  }, 5000);

  it('gives up on a host that keeps sending 1xx interim responses', async () => {
    respond = (write, socket) => every(150, socket, () => write('HTTP/1.1 102 Processing\r\n\r\n'));
    await expect(fetchFixture()).resolves.toEqual({
      kind: 'failed',
      message: 'CIMD fetch timed out',
    });
  }, 5000);

  // 1xx responses never reach the response callback, so neither the deadline
  // nor `maxBytes` would otherwise stop a host streaming them as fast as it
  // can — on the fetch thread's CPU.
  it('hangs up on a stream of 1xx interim responses before the deadline', async () => {
    respond = (write) => write('HTTP/1.1 102 Processing\r\n\r\n'.repeat(100));
    // The message, not the clock, shows the cap tripped first: with a long
    // deadline, only the cap can end the fetch this way.
    await expect(fetchFixture(IN_TIME_MS)).resolves.toEqual({
      kind: 'failed',
      message: 'CIMD fetch received too many interim responses',
    });
  }, 5000);

  // Node answers an unsolicited `101` by dropping the socket, and the request
  // then emits nothing but 'close'.
  it('settles when the host answers with an unsolicited 101 upgrade', async () => {
    respond = (write) =>
      write('HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\n');
    const outcome = await fetchFixture(IN_TIME_MS);
    expect(outcome).toMatchObject({ kind: 'failed' });
    expect(outcome).not.toMatchObject({ message: 'CIMD fetch timed out' });
  }, 5000);
});
