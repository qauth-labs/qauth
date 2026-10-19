import { connect } from 'node:net';

import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { answerUnknownRouteBeforeBody, requestDeadlineOptions } from './request-bounds';

/**
 * Two things let one address park unfinished request bodies until the heap ran
 * out: Fastify's `requestTimeout` of 0 (no deadline, and Node's own 300 s limit
 * switched off), and a default 404 handler that reads and parses the body of a
 * request for a route that does not exist, outside the rate limiter, which
 * only sees registered routes.
 */

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('answerUnknownRouteBeforeBody', () => {
  function build() {
    const instance = Fastify();
    const parser = vi.fn((_request: unknown, body: string, done: (e: null, v: unknown) => void) =>
      done(null, body)
    );
    instance.removeContentTypeParser('application/json');
    instance.addContentTypeParser('application/json', { parseAs: 'string' }, parser);
    instance.addHook('onRequest', answerUnknownRouteBeforeBody);
    instance.post('/known', async () => ({ ok: true }));
    return { instance, parser };
  }

  it('answers an unknown route with a 404 before any body parser runs', async () => {
    const { instance, parser } = build();
    app = instance;

    const res = await instance.inject({
      method: 'POST',
      url: '/no-such-route?x=1',
      headers: { 'content-type': 'application/json' },
      payload: JSON.stringify({ padding: 'a'.repeat(10_000) }),
    });

    expect(res.statusCode).toBe(404);
    expect(parser).not.toHaveBeenCalled();
  });

  it('answers with the same body as Fastify’s own 404', async () => {
    const { instance } = build();
    app = instance;
    const vanilla = Fastify();

    for (const options of [
      { method: 'GET' as const, url: '/nope' },
      { method: 'POST' as const, url: '/nope?a=b', payload: { x: 1 } },
    ]) {
      const ours = await instance.inject(options);
      const theirs = await vanilla.inject(options);
      expect(ours.statusCode).toBe(theirs.statusCode);
      expect(ours.json()).toEqual(theirs.json());
    }
    await vanilla.close();
  });

  it('leaves a registered route alone', async () => {
    const { instance, parser } = build();
    app = instance;

    const res = await instance.inject({
      method: 'POST',
      url: '/known',
      headers: { 'content-type': 'application/json' },
      payload: '{}',
    });

    expect(res.statusCode).toBe(200);
    expect(parser).toHaveBeenCalledOnce();
  });
});

describe('requestDeadlineOptions', () => {
  it('sets a request deadline and keeps the headers deadline no longer than it', () => {
    // Node swaps the two when `headersTimeout` is the larger, so a request
    // deadline under Node's 60 s headers default would silently become 60 s.
    expect(requestDeadlineOptions(60_000)).toEqual({
      requestTimeout: 60_000,
      http: { headersTimeout: 60_000 },
    });
    expect(requestDeadlineOptions(5_000)).toEqual({
      requestTimeout: 5_000,
      http: { headersTimeout: 5_000 },
    });
    expect(requestDeadlineOptions(120_000)).toEqual({
      requestTimeout: 120_000,
      http: { headersTimeout: 60_000 },
    });
  });

  it('closes a request whose body stops short of its Content-Length at the deadline', async () => {
    const options = requestDeadlineOptions(1_000);
    // Node enforces the deadline on a sweep (30 s by default); a short sweep
    // keeps the test fast. Bounds are generous: expected ~1.1 s, allowed 8 s.
    app = Fastify({ ...options, http: { ...options.http, connectionsCheckingInterval: 100 } });
    app.post('/upload', async () => ({ ok: true }));
    await app.listen({ port: 0, host: '127.0.0.1' });
    const address = app.server.address();
    if (!address || typeof address === 'string') throw new Error('no port');

    const outcome = await new Promise<string>((resolve) => {
      const socket = connect(address.port, '127.0.0.1', () => {
        socket.write(
          'POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n' +
            'Content-Length: 1000\r\n\r\n{"a":'
        );
      });
      let received = '';
      socket.on('data', (chunk) => (received += chunk.toString()));
      socket.on('close', () => resolve(received.split('\r\n')[0] ?? 'closed'));
      setTimeout(() => {
        socket.destroy();
        resolve('still open');
      }, 8_000);
    });

    expect(outcome).toBe('HTTP/1.1 408 Request Timeout');
  }, 15_000);
});
