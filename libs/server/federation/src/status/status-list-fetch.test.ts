import { describe, expect, it, vi } from 'vitest';

import { createHttpsStatusListFetch } from './status-list-fetch';
import { MAX_STATUS_LIST_TOKEN_BYTES, STATUS_LIST_TOKEN_MEDIA_TYPE } from './status-list-spec';

const URI = 'https://issuer.example/lists/1';

function respond(
  body: string,
  init: { status?: number; contentType?: string | null; contentLength?: string } = {}
): Response {
  const headers = new Headers();
  if (init.contentType !== null) {
    headers.set('content-type', init.contentType ?? STATUS_LIST_TOKEN_MEDIA_TYPE);
  }
  if (init.contentLength !== undefined) headers.set('content-length', init.contentLength);
  return new Response(body, { status: init.status ?? 200, headers });
}

describe('createHttpsStatusListFetch (#297)', () => {
  it('returns the token body on a well-formed response', async () => {
    const fetchImpl = vi.fn(async () => respond('header.payload.signature'));
    const fetchToken = createHttpsStatusListFetch(fetchImpl as unknown as typeof fetch);

    expect(await fetchToken({ uri: URI, timeoutMs: 1_000 })).toEqual({
      outcome: 'ok',
      token: 'header.payload.signature',
    });
  });

  it('asks for the Status List Token media type and refuses redirects', async () => {
    const fetchImpl = vi.fn(async () => respond('a.b.c'));
    const fetchToken = createHttpsStatusListFetch(fetchImpl as unknown as typeof fetch);
    await fetchToken({ uri: URI, timeoutMs: 1_000 });

    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(URI);
    expect(init.method).toBe('GET');
    // A redirect is the cheapest way out of the operator's URI allowlist.
    expect(init.redirect).toBe('error');
    expect((init.headers as Record<string, string>)['accept']).toBe(STATUS_LIST_TOKEN_MEDIA_TYPE);
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('accepts a media type carrying parameters', async () => {
    const fetchImpl = vi.fn(async () =>
      respond('a.b.c', { contentType: `${STATUS_LIST_TOKEN_MEDIA_TYPE}; charset=utf-8` })
    );
    const fetchToken = createHttpsStatusListFetch(fetchImpl as unknown as typeof fetch);
    expect((await fetchToken({ uri: URI, timeoutMs: 1_000 })).outcome).toBe('ok');
  });

  it.each([
    ['a 404', { status: 404 }],
    ['a 500', { status: 500 }],
    ['a 403', { status: 403 }],
    ['a 302 that the client did not follow', { status: 302 }],
  ])('fails on %s', async (_label, init) => {
    const fetchImpl = vi.fn(async () => respond('a.b.c', init));
    const fetchToken = createHttpsStatusListFetch(fetchImpl as unknown as typeof fetch);
    expect(await fetchToken({ uri: URI, timeoutMs: 1_000 })).toEqual({ outcome: 'failed' });
  });

  it.each([
    ['an HTML error page', 'text/html'],
    ['a JSON error body', 'application/json'],
    ['a plain JWT', 'application/jwt'],
    ['no content type', null],
  ])('fails on %s', async (_label, contentType) => {
    // Without this the JWS parser is handed a captive-portal page and every
    // downstream failure is misreported as "unverifiable token".
    const fetchImpl = vi.fn(async () => respond('<html>nope</html>', { contentType }));
    const fetchToken = createHttpsStatusListFetch(fetchImpl as unknown as typeof fetch);
    expect(await fetchToken({ uri: URI, timeoutMs: 1_000 })).toEqual({ outcome: 'failed' });
  });

  it('fails when the transport throws', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    });
    const fetchToken = createHttpsStatusListFetch(fetchImpl as unknown as typeof fetch);
    expect(await fetchToken({ uri: URI, timeoutMs: 1_000 })).toEqual({ outcome: 'failed' });
  });

  it('fails on an empty body', async () => {
    const fetchImpl = vi.fn(async () => respond('   '));
    const fetchToken = createHttpsStatusListFetch(fetchImpl as unknown as typeof fetch);
    expect(await fetchToken({ uri: URI, timeoutMs: 1_000 })).toEqual({ outcome: 'failed' });
  });

  it('refuses an over-large declared Content-Length without reading the body', async () => {
    const fetchImpl = vi.fn(async () =>
      respond('a.b.c', { contentLength: String(MAX_STATUS_LIST_TOKEN_BYTES + 1) })
    );
    const fetchToken = createHttpsStatusListFetch(fetchImpl as unknown as typeof fetch);
    expect(await fetchToken({ uri: URI, timeoutMs: 1_000 })).toEqual({ outcome: 'failed' });
  });

  it('aborts a body that exceeds the bound mid-stream', async () => {
    // The endpoint under-declares (or omits) Content-Length and then streams
    // forever. `await response.text()` would buffer all of it first.
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(1024 * 1024));
      },
      cancel() {
        cancelled = true;
      },
    });
    const fetchImpl = vi.fn(
      async () =>
        new Response(stream, {
          status: 200,
          headers: { 'content-type': STATUS_LIST_TOKEN_MEDIA_TYPE },
        })
    );
    const fetchToken = createHttpsStatusListFetch(fetchImpl as unknown as typeof fetch);

    expect(await fetchToken({ uri: URI, timeoutMs: 1_000 })).toEqual({ outcome: 'failed' });
    expect(cancelled).toBe(true);
  });

  it('fails when the body stream errors', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error('reset by peer'));
      },
    });
    const fetchImpl = vi.fn(
      async () =>
        new Response(stream, {
          status: 200,
          headers: { 'content-type': STATUS_LIST_TOKEN_MEDIA_TYPE },
        })
    );
    const fetchToken = createHttpsStatusListFetch(fetchImpl as unknown as typeof fetch);
    expect(await fetchToken({ uri: URI, timeoutMs: 1_000 })).toEqual({ outcome: 'failed' });
  });
});
