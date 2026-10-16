import type { request } from 'node:https';
import type { Socket } from 'node:net';
import { gzipSync } from 'node:zlib';

import { afterEach, describe, expect, it } from 'vitest';

import { createHttpsStatusListFetch, type StatusListFetchResult } from './status-list-fetch';
import { MAX_STATUS_LIST_TOKEN_BYTES, STATUS_LIST_TOKEN_MEDIA_TYPE } from './status-list-spec';
import {
  httpResponseBytes,
  startTestStatusEndpoint,
  type TestStatusEndpoint,
} from './test/status-endpoint-fixtures';

const URI = 'https://issuer.example/lists/1';

describe('createHttpsStatusListFetch (#297)', () => {
  let endpoint: TestStatusEndpoint;

  afterEach(() => endpoint?.close());

  /** Fetch {@link URI} from an endpoint that behaves as `respond` says. */
  async function fetchFrom(
    respond: (socket: Socket) => void,
    timeoutMs = 1_000
  ): Promise<StatusListFetchResult> {
    endpoint = await startTestStatusEndpoint(respond);
    return createHttpsStatusListFetch(endpoint.request)({ uri: URI, timeoutMs });
  }

  /** Fetch {@link URI} from an endpoint that sends one response and closes. */
  function fetchAnswer(...response: Parameters<typeof httpResponseBytes>) {
    return fetchFrom((socket) => socket.end(httpResponseBytes(...response)));
  }

  it('returns the token body on a well-formed response', async () => {
    expect(await fetchAnswer('header.payload.signature')).toEqual({
      outcome: 'ok',
      token: 'header.payload.signature',
    });
  });

  it('asks for the Status List Token media type', async () => {
    await fetchAnswer('a.b.c');

    const [requestLine, ...headers] = (endpoint.requests[0] as string).toLowerCase().split('\r\n');
    expect(requestLine).toBe('get /lists/1 http/1.1');
    expect(headers).toContain(`accept: ${STATUS_LIST_TOKEN_MEDIA_TYPE}`);
  });

  it('does not follow a redirect', async () => {
    // A redirect is the cheapest way out of the operator's URI allowlist.
    const result = await fetchAnswer('', { status: 302, headers: { Location: '/lists/2' } });

    expect(result).toEqual({ outcome: 'failed' });
    expect(endpoint.requests).toHaveLength(1);
  });

  it('accepts a media type carrying parameters', async () => {
    const result = await fetchAnswer('a.b.c', {
      contentType: `${STATUS_LIST_TOKEN_MEDIA_TYPE}; charset=utf-8`,
    });
    expect(result.outcome).toBe('ok');
  });

  it.each([
    ['a 404', { status: 404 }],
    ['a 500', { status: 500 }],
    ['a 403', { status: 403 }],
    ['a 421', { status: 421 }],
    ['a 204', { status: 204 }],
  ])('fails on %s', async (_label, init) => {
    expect(await fetchAnswer('a.b.c', init)).toEqual({ outcome: 'failed' });
  });

  it.each([
    ['an HTML error page', 'text/html'],
    ['a JSON error body', 'application/json'],
    ['a plain JWT', 'application/jwt'],
    ['no content type', null],
  ])('fails on %s', async (_label, contentType) => {
    // Without this the JWS parser is handed a captive-portal page and every
    // downstream failure is misreported as "unverifiable token".
    expect(await fetchAnswer('<html>nope</html>', { contentType })).toEqual({ outcome: 'failed' });
  });

  it.each([
    ['a 404 page', { status: 404, contentType: 'text/html' }],
    ['a redirect body', { status: 302, headers: { Location: '/lists/2' } }],
    ['a 421 body', { status: 421 }],
    ['the wrong media type', { contentType: 'text/html' }],
    [
      'an unsupported coding',
      { headers: { 'Content-Encoding': 'gzip, gzip, gzip, gzip, gzip, gzip' } },
    ],
  ])('survives %s too large to buffer from a peer that then closes', async (_label, init) => {
    // Over the 64 KiB at which the platform `fetch` pauses its parser on a body
    // nobody reads. The close that follows ended the PROCESS, from a socket
    // event handler: vitest reports that as an unhandled error and fails the run.
    expect(await fetchAnswer('x'.repeat(72 * 1024), init)).toEqual({ outcome: 'failed' });
    await endpoint.hungUp();
  });

  it('hangs up on a response it refuses', async () => {
    // The endpoint never closes; the refusal must not leave the socket behind.
    const result = await fetchFrom((socket) =>
      socket.write(httpResponseBytes('', { status: 404, headers: { 'Content-Length': '100000' } }))
    );

    expect(result).toEqual({ outcome: 'failed' });
    await endpoint.hungUp();
  });

  it('fails when the request cannot be made', async () => {
    const fetchToken = createHttpsStatusListFetch((() => {
      throw new Error('ERR_INVALID_PROTOCOL');
    }) as unknown as typeof request);
    expect(await fetchToken({ uri: URI, timeoutMs: 1_000 })).toEqual({ outcome: 'failed' });
  });

  it.each([
    ['is not https', 'http://issuer.example/lists/1'],
    ['is not a URI', 'lists/1'],
  ])('fails without dialling when the URI %s', async (_label, uri) => {
    expect(await createHttpsStatusListFetch()({ uri, timeoutMs: 1_000 })).toEqual({
      outcome: 'failed',
    });
  });

  it('fails when the connection is dropped before a response', async () => {
    expect(await fetchFrom((socket) => socket.destroy())).toEqual({ outcome: 'failed' });
  });

  it('fails on an empty body', async () => {
    expect(await fetchAnswer('   ')).toEqual({ outcome: 'failed' });
  });

  it('refuses an over-large declared Content-Length without reading the body', async () => {
    const result = await fetchFrom((socket) =>
      socket.write(
        httpResponseBytes('a.b.c', {
          headers: { 'Content-Length': String(MAX_STATUS_LIST_TOKEN_BYTES + 1) },
        })
      )
    );

    expect(result).toEqual({ outcome: 'failed' });
    await endpoint.hungUp();
  });

  it('aborts a body that exceeds the bound mid-stream', async () => {
    // The endpoint omits Content-Length and then streams for as long as anyone
    // listens. Buffering the body first would buffer all of it.
    let sent = 0;
    const result = await fetchFrom((socket) => {
      const chunk = Buffer.alloc(1024 * 1024, 'x');
      const stream = (error?: Error | null): void => {
        if (error) return;
        sent += chunk.byteLength;
        socket.write(chunk, stream);
      };
      socket.write(
        `HTTP/1.1 200 OK\r\nContent-Type: ${STATUS_LIST_TOKEN_MEDIA_TYPE}\r\n\r\n`,
        stream
      );
    }, 10_000);

    expect(result).toEqual({ outcome: 'failed' });
    await endpoint.hungUp();
    expect(sent).toBeLessThan(4 * MAX_STATUS_LIST_TOKEN_BYTES);
  });

  it('fails when the body stream errors', async () => {
    const result = await fetchFrom((socket) => {
      socket.write(httpResponseBytes('a.b', { headers: { 'Content-Length': '100' } }), () =>
        socket.resetAndDestroy()
      );
    });
    expect(result).toEqual({ outcome: 'failed' });
  });

  it('offers gzip and decodes it', async () => {
    // draft-14 §8.2: the response SHOULD use gzip Content-Encoding.
    const result = await fetchAnswer(gzipSync('a.b.c'), {
      headers: { 'Content-Encoding': 'gzip' },
    });

    expect(result).toEqual({ outcome: 'ok', token: 'a.b.c' });
    expect((endpoint.requests[0] as string).toLowerCase()).toContain('accept-encoding: gzip\r\n');
  });

  it.each([
    ['inflates past the bound', gzipSync(Buffer.alloc(MAX_STATUS_LIST_TOKEN_BYTES + 1)), 'gzip'],
    ['is not the gzip it claims to be', Buffer.from('a.b.c'), 'gzip'],
    ['uses a coding that was not offered', Buffer.from('a.b.c'), 'br'],
  ])('fails on a body that %s', async (_label, body, coding) => {
    expect(await fetchAnswer(body, { headers: { 'Content-Encoding': coding } })).toEqual({
      outcome: 'failed',
    });
  });

  it('gives up on an endpoint that drips its body, at the deadline', async () => {
    // Each byte restarts a socket idle timer; it must not restart this one.
    const result = await fetchFrom((socket) => {
      socket.write(httpResponseBytes('', { headers: { 'Content-Length': '4096' } }));
      const drip = setInterval(() => socket.write('x'), 20);
      socket.once('close', () => clearInterval(drip));
    }, 200);

    expect(result).toEqual({ outcome: 'failed' });
    await endpoint.hungUp();
  });

  it('tolerates early hints, and hangs up on a stream of interim responses', async () => {
    const hint = 'HTTP/1.1 103 Early Hints\r\n\r\n';

    expect(
      await fetchFrom((socket) =>
        socket.end(Buffer.concat([Buffer.from(hint), httpResponseBytes('a.b.c')]))
      )
    ).toEqual({ outcome: 'ok', token: 'a.b.c' });
    await endpoint.close();

    expect(await fetchFrom((socket) => socket.write(hint.repeat(100)), 10_000)).toEqual({
      outcome: 'failed',
    });
  });

  it('settles when the endpoint answers with an unsolicited 101 upgrade', async () => {
    const result = await fetchFrom(
      (socket) =>
        socket.write(
          'HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\n'
        ),
      10_000
    );
    expect(result).toEqual({ outcome: 'failed' });
  });
});
