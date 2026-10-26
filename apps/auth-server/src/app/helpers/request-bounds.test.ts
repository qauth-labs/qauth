import { connect } from 'node:net';
import { Writable } from 'node:stream';

import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { serializeRequestForLog } from '../../config/logger';
import {
  answerClientError,
  answerFrameworkError,
  answerRouteNotFound,
  answerUnknownRouteBeforeBody,
  requestDeadlineOptions,
} from './request-bounds';

/** A logger stream that keeps every line, parsed. */
function capturedLog(): { stream: Writable; lines: Record<string, unknown>[] } {
  const lines: Record<string, unknown>[] = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      for (const line of chunk.toString().split('\n').filter(Boolean)) {
        lines.push(JSON.parse(line) as Record<string, unknown>);
      }
      callback();
    },
  });
  return { stream, lines };
}

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

  it('answers with the not_found problem document, the query left out (#513)', async () => {
    const { instance } = build();
    app = instance;

    for (const options of [
      { method: 'GET' as const, url: '/nope' },
      { method: 'POST' as const, url: '/nope?response_code=secret', payload: { x: 1 } },
    ]) {
      const res = await instance.inject(options);
      expect(res.statusCode).toBe(404);
      expect(res.headers['content-type']).toMatch(/^application\/problem\+json(?:;|$)/);
      const body = res.json() as Record<string, unknown>;
      expect(body).toMatchObject({
        type: 'https://docs.qauth.dev/reference/problem-types/#not-found',
        status: 404,
        instance: '/nope',
        code: 'not_found',
      });
      expect(typeof body['title']).toBe('string');
      expect(typeof body['trace_id']).toBe('string');
      expect(res.body).not.toContain('secret');
      for (const member of ['error', 'statusCode', 'message']) {
        expect(body).not.toHaveProperty(member);
      }
    }
  });

  it('logs the unknown path with its secret query values censored', async () => {
    const { stream, lines } = capturedLog();
    app = Fastify({ logger: { level: 'info', stream } });
    app.addHook('onRequest', answerUnknownRouteBeforeBody);

    await app.inject({ method: 'GET', url: '/ui/wallet-login/returns?response_code=s3cr3t&x=1' });

    // Fastify's own request line is censored by the app's `req` serializer,
    // which this bare instance does not install; the not-found line is ours.
    const notFound = lines.find((line) => String(line['msg']).endsWith('not found'));
    expect(notFound?.['msg']).toBe(
      'Route GET:/ui/wallet-login/returns?response_code=[Redacted]&x=1 not found'
    );
  });

  it('logs a GET of a mailed verification link without its token (#490)', async () => {
    const { stream, lines } = capturedLog();
    // With the app's `req` serializer, so Fastify's request line is checked too.
    app = Fastify({
      logger: { level: 'info', stream, serializers: { req: serializeRequestForLog } },
    });
    app.addHook('onRequest', answerUnknownRouteBeforeBody);
    const token = 'f0'.repeat(32);

    await app.inject({ method: 'GET', url: `/auth/verify?token=${token}` });

    const notFound = lines.find((line) => String(line['msg']).endsWith('not found'));
    expect(notFound?.['msg']).toBe('Route GET:/auth/verify?token=[Redacted] not found');
    const incoming = lines.find((line) => line['msg'] === 'incoming request');
    expect(incoming?.['req']).toMatchObject({ url: '/auth/verify?token=[Redacted]' });
    expect(JSON.stringify(lines)).not.toContain(token);
  });

  it('echoes the request id in the header the server reads it from (trace_id)', async () => {
    app = Fastify({ requestIdHeader: 'x-request-id' });
    app.addHook('onRequest', answerUnknownRouteBeforeBody);

    const res = await app.inject({
      method: 'GET',
      url: '/nope',
      headers: { 'x-request-id': 'trace-1234' },
    });

    expect(res.headers['x-request-id']).toBe('trace-1234');
    expect(res.json()).toMatchObject({ trace_id: 'trace-1234' });
  });

  it('is the not-found handler reply.callNotFound() reaches, so no route sends the old envelope', async () => {
    app = Fastify({ requestIdHeader: 'x-request-id' });
    app.setNotFoundHandler(answerRouteNotFound);
    // Like a static file handler that has no such file.
    app.get('/docs/static/*', async (_request, reply) => reply.callNotFound());

    const res = await app.inject({ method: 'GET', url: '/docs/static/missing.js' });

    expect(res.statusCode).toBe(404);
    expect(res.headers['content-type']).toMatch(/^application\/problem\+json(?:;|$)/);
    expect(res.json()).toMatchObject({
      status: 404,
      code: 'not_found',
      instance: '/docs/static/missing.js',
      trace_id: res.headers['x-request-id'],
    });
    for (const member of ['error', 'statusCode', 'message']) {
      expect(res.json()).not.toHaveProperty(member);
    }
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

/** Write `raw` to a listening instance and return what came back, whole. */
async function rawExchange(instance: FastifyInstance, raw: string): Promise<string> {
  await instance.listen({ port: 0, host: '127.0.0.1' });
  const address = instance.server.address();
  if (!address || typeof address === 'string') throw new Error('no port');
  return new Promise<string>((resolve) => {
    const socket = connect(address.port, '127.0.0.1', () => socket.write(raw));
    let received = '';
    socket.on('data', (chunk) => (received += chunk.toString()));
    socket.on('close', () => resolve(received));
    setTimeout(() => {
      socket.destroy();
      resolve(received);
    }, 3_000);
  });
}

/** The JSON body of a raw HTTP/1.1 answer. */
function rawBody(answer: string): Record<string, unknown> {
  return JSON.parse(answer.slice(answer.indexOf('\r\n\r\n') + 4)) as Record<string, unknown>;
}

describe("the router's refusals and unreadable requests (#513)", () => {
  /** Fastify's own envelope, which none of these answers may carry. */
  const LEGACY = ['error', 'statusCode', 'message'];

  it('answers a path that is not valid percent-encoding with bad_request, echoing nothing', async () => {
    app = Fastify({ frameworkErrors: answerFrameworkError });
    app.get('/items/:id', async () => ({ ok: true }));

    const res = await app.inject({
      method: 'GET',
      url: '/items/%E0%A4%A?response_code=secret',
    });

    expect(res.statusCode).toBe(400);
    expect(res.headers['content-type']).toMatch(/^application\/problem\+json(?:;|$)/);
    const body = res.json() as Record<string, unknown>;
    expect(body).toMatchObject({ status: 400, code: 'bad_request' });
    expect(typeof body['trace_id']).toBe('string');
    for (const member of LEGACY) expect(body).not.toHaveProperty(member);
    expect(res.body).not.toContain('secret');
    expect(res.body).not.toContain('FST_ERR');
  });

  it("echoes the request id on the router's refusal (trace_id)", async () => {
    app = Fastify({ frameworkErrors: answerFrameworkError, requestIdHeader: 'x-request-id' });
    app.get('/items/:id', async () => ({ ok: true }));

    const res = await app.inject({
      method: 'GET',
      url: '/items/%E0%A4%A',
      headers: { 'x-request-id': 'trace-5678' },
    });

    expect(res.statusCode).toBe(400);
    expect(res.headers['x-request-id']).toBe('trace-5678');
    expect(res.json()).toMatchObject({ trace_id: 'trace-5678' });
  });

  it("answers a path parameter over the router's limit with uri_too_long", async () => {
    app = Fastify({ frameworkErrors: answerFrameworkError });
    app.get('/items/:id', async () => ({ ok: true }));

    const res = await app.inject({ method: 'GET', url: `/items/${'x'.repeat(200)}` });

    expect(res.statusCode).toBe(414);
    expect(res.json()).toMatchObject({ status: 414, code: 'uri_too_long' });
    expect(res.body).not.toContain('x'.repeat(200));
  });

  it('answers a request it cannot parse with a bad_request problem document', async () => {
    app = Fastify({ clientErrorHandler: answerClientError });
    app.get('/', async () => ({ ok: true }));

    const answer = await rawExchange(app, 'NOT A REQUEST\r\n\r\n');

    expect(answer.split('\r\n')[0]).toBe('HTTP/1.1 400 Bad Request');
    expect(answer).toContain('Content-Type: application/problem+json');
    const body = rawBody(answer);
    expect(body).toMatchObject({ status: 400, code: 'bad_request' });
    expect(typeof body['trace_id']).toBe('string');
    for (const member of LEGACY) expect(body).not.toHaveProperty(member);
  });

  it('answers headers over the size limit with request_header_fields_too_large', async () => {
    app = Fastify({ clientErrorHandler: answerClientError, http: { maxHeaderSize: 1024 } });
    app.get('/', async () => ({ ok: true }));

    const answer = await rawExchange(
      app,
      `GET / HTTP/1.1\r\nHost: localhost\r\nX-Padding: ${'a'.repeat(4096)}\r\n\r\n`
    );

    expect(answer.split('\r\n')[0]).toBe('HTTP/1.1 431 Request Header Fields Too Large');
    expect(rawBody(answer)).toMatchObject({ status: 431, code: 'request_header_fields_too_large' });
  });

  it('logs an unreadable request at info by its code, trace id and status, never its bytes', async () => {
    const { stream, lines } = capturedLog();
    app = Fastify({
      clientErrorHandler: answerClientError,
      logger: { level: 'info', stream },
      requestIdHeader: 'x-request-id',
    });
    app.get('/', async () => ({ ok: true }));

    // Node's parser keeps what it could not parse as `rawPacket`: here, a
    // session cookie and an access token in front of a broken header.
    const answer = await rawExchange(
      app,
      'GET / HTTP/1.1\r\nHost: localhost\r\nCookie: __Host-qauth_session=s3cr3t-session\r\nAuthorization: Bearer s3cr3t-token\r\nBroken header\r\n\r\n'
    );

    const traceId = rawBody(answer)['trace_id'];
    expect(answer).toContain(`x-request-id: ${String(traceId)}`);
    const line = lines.find((entry) => entry['msg'] === 'Client error');
    expect(line).toMatchObject({ level: 30, traceId, statusCode: 400 });
    expect(line?.['code']).toEqual(expect.stringMatching(/^HPE_/));
    expect(line).not.toHaveProperty('err');
    expect(JSON.stringify(lines)).not.toContain('s3cr3t');
  });
});
