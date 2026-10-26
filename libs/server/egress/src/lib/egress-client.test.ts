import http from 'node:http';
import https from 'node:https';
import { type AddressInfo, createServer as createTcpServer, type Server } from 'node:net';

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  createFixtureNetwork,
  type FixtureNetwork,
  type FixtureServer,
} from '../testing/fixture-network';
import { parseEgressAllowlist } from './allowlist';
import {
  createEgressClient,
  type EgressClient,
  type EgressClientOptions,
  type EgressRequest,
} from './egress-client';
import { EgressError } from './errors';
import type { EgressTransport } from './transport';

/*
 * The egress client against local HTTPS servers. `fixture-network.ts` says how
 * public addresses reach them; everything else is the production code path.
 *
 * The library has no way to hand the client another network, so the tests
 * replace the transport module's NODE_TRANSPORT with one that delegates to
 * `network.current`. Its exchanges run in this process; the pool of fetch
 * processes that runs them outside tests has its own suite.
 */

const network = vi.hoisted(() => ({ current: undefined as EgressTransport | undefined }));

vi.mock('./transport', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./transport')>();
  const current = (): EgressTransport => {
    if (network.current === undefined) throw new Error('no fixture network');
    return network.current;
  };
  return {
    ...actual,
    NODE_TRANSPORT: {
      resolveHost: (...args: Parameters<EgressTransport['resolveHost']>) =>
        current().resolveHost(...args),
      exchange: (...args: Parameters<EgressTransport['exchange']>) => current().exchange(...args),
    },
  };
});

/** Public addresses the fixture DNS hands out; each is served by a local server. */
const PUBLIC_A = '93.184.215.14';
const PUBLIC_B = '151.101.1.140';
const PUBLIC_V6 = '2606:4700:4700::1111';
/** Non-public addresses; the "internal" server behind them must never be reached. */
const PRIVATE = '10.0.0.7';
const LOOPBACK = '127.0.0.1';
const METADATA = '169.254.169.254';

let net: FixtureNetwork;
let serverA: FixtureServer;
let serverB: FixtureServer;
let serverV6: FixtureServer;
let internal: FixtureServer;

const ok: FixtureServer['handler'] = (_req, _body, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('ok');
};

beforeAll(async () => {
  net = await createFixtureNetwork();
  serverA = await net.serve(PUBLIC_A, ok);
  serverB = await net.serve(PUBLIC_B, ok);
  serverV6 = await net.serve(PUBLIC_V6, ok);
  internal = await net.serve(PRIVATE, (_req, _body, res) => res.end('internal secret'));
  for (const address of [LOOPBACK, METADATA]) {
    await net.serve(address, (_req, _body, res) => res.end('internal secret'));
  }
});

afterAll(async () => {
  await net.close();
});

beforeEach(() => {
  net.dns.clear();
  net.dns.set('api.egress.test', [PUBLIC_A]);
  net.dns.set('other.egress.test', [PUBLIC_B]);
  net.dns.set('v6.egress.test', [PUBLIC_V6]);
  net.dns.set('internal.egress.test', [PRIVATE]);
  net.lookups.length = 0;
  net.dialled.length = 0;
  for (const server of [serverA, serverB, serverV6, internal]) {
    server.requests.length = 0;
    server.connections = 0;
    server.handler = ok;
  }
  internal.handler = (_req, _body, res) => res.end('internal secret');
  network.current = net.transport;
});

const client = (options: EgressClientOptions = {}): EgressClient => createEgressClient(options);

const get = (url: string, extra: Partial<EgressRequest> = {}, egress = client()) =>
  egress.request({
    method: 'GET',
    url,
    purpose: 'test',
    ...extra,
    source: extra.source ?? 'client',
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

function redirect(location: string, status = 302): FixtureServer['handler'] {
  return (_req, _body, res) => {
    res.writeHead(status, { location });
    res.end();
  };
}

describe('URL checks', () => {
  it.each([
    ['http://api.egress.test/', 'scheme'],
    ['ftp://api.egress.test/', 'scheme'],
    ['file:///etc/passwd', 'scheme'],
    ['not a url', 'scheme'],
    ['https://user:secret@api.egress.test/', 'credentials'],
    ['https://user@api.egress.test/', 'credentials'],
    ['https://:secret@api.egress.test/', 'credentials'],
  ])('refuses %s with %s, before any lookup', async (url, reason) => {
    const err = await refusal(get(url));
    expect(err).toMatchObject({ reason, outcome: 'blocked', purpose: 'test' });
    expect(err.message).not.toContain('secret');
    expect(net.lookups).toEqual([]);
    expect(net.dialled).toEqual([]);
  });

  it.each([
    'https://127.0.0.1/',
    'https://10.0.0.7/',
    'https://169.254.169.254/latest/meta-data/',
    'https://[::1]/',
    'https://[::ffff:127.0.0.1]/',
    'https://[::ffff:a9fe:a9fe]/',
    'https://[64:ff9b::a00:7]/',
    'https://[2002:a00:7::]/',
    'https://[fd00:ec2::254]/',
    'https://0x7f.1/',
    'https://2130706433/',
    'https://0177.0.0.1/',
    'https://100.64.0.1/',
    'https://192.0.2.1/',
  ])('refuses the IP literal in %s with address, without dialling', async (url) => {
    const err = await refusal(get(url));
    expect(err).toMatchObject({ reason: 'address', outcome: 'blocked' });
    expect(net.lookups).toEqual([]);
    expect(net.dialled).toEqual([]);
  });

  it('dials a public IP literal directly, without a lookup', async () => {
    // The certificate names egress.test, not the address, so TLS refuses it;
    // what matters is that the address itself was dialled.
    const err = await refusal(get(`https://${PUBLIC_A}/`));
    expect(err.reason).toBe('network');
    expect(net.lookups).toEqual([]);
    expect(net.dialled).toEqual([[PUBLIC_A]]);
  });
});

describe('address checks (local test servers)', () => {
  it('reaches a host whose addresses are all public', async () => {
    const res = await get('https://api.egress.test/doc?x=1');
    expect(res).toMatchObject({
      status: 200,
      redirects: 0,
      url: 'https://api.egress.test/doc?x=1',
    });
    expect(res.body.toString()).toBe('ok');
    expect(serverA.requests).toHaveLength(1);
    expect(serverA.requests[0]).toMatchObject({ method: 'GET', url: '/doc?x=1' });
    expect(serverA.requests[0].headers.host).toBe('api.egress.test');
  });

  it('reaches a public IPv6 address', async () => {
    const res = await get('https://v6.egress.test/');
    expect(res.status).toBe(200);
    expect(net.dialled).toEqual([[PUBLIC_V6]]);
  });

  it('refuses a name that resolves to one public and one private address', async () => {
    net.dns.set('mixed.egress.test', [PUBLIC_A, PRIVATE]);
    const err = await refusal(get('https://mixed.egress.test/'));
    expect(err).toMatchObject({ reason: 'address', outcome: 'blocked', host: 'mixed.egress.test' });
    expect(net.dialled).toEqual([]);
    expect(serverA.connections).toBe(0);
    expect(internal.connections).toBe(0);
  });

  it.each([
    ['loopback', [LOOPBACK]],
    ['metadata', [METADATA]],
    ['mapped metadata', ['::ffff:169.254.169.254']],
    ['NAT64 private', ['64:ff9b::a00:7']],
    ['6to4 private', ['2002:a00:7::1']],
    ['unique-local', ['fd00:ec2::254']],
    ['public IPv6 and loopback', [PUBLIC_V6, '::1']],
  ])('refuses a name that resolves to %s', async (_label, addresses) => {
    net.dns.set('bad.egress.test', addresses);
    const err = await refusal(get('https://bad.egress.test/'));
    expect(err.reason).toBe('address');
    expect(net.dialled).toEqual([]);
  });

  it('reports a name that does not resolve as a failure, not as blocked', async () => {
    const err = await refusal(get('https://nowhere.egress.test/'));
    expect(err).toMatchObject({ reason: 'network', outcome: 'failed' });
  });

  it('checks the certificate against the host name, not the dialled address', async () => {
    net.dns.set('elsewhere.example', [PUBLIC_A]);
    const err = await refusal(get('https://elsewhere.example/'));
    expect(err).toMatchObject({ reason: 'network', outcome: 'failed' });
    expect(serverA.requests).toHaveLength(0);
  });

  // DNS rebinding: the name is public when it is checked and private when a
  // second lookup would happen. The client looks it up once and dials the
  // address it checked.
  it('connects to the checked address when the name rebinds to a private one', async () => {
    let answers = 0;
    net.dns.set('rebind.egress.test', () => (answers++ === 0 ? [PUBLIC_A] : [PRIVATE]));
    const res = await get('https://rebind.egress.test/');
    expect(res.status).toBe(200);
    expect(net.lookups).toEqual(['rebind.egress.test']);
    expect(net.dialled).toEqual([[PUBLIC_A]]);
    expect(serverA.requests).toHaveLength(1);
    expect(internal.connections).toBe(0);
  });

  it('looks the name up again at the next request and refuses the private answer', async () => {
    let answers = 0;
    net.dns.set('rebind.egress.test', () => (answers++ === 0 ? [PUBLIC_A] : [PRIVATE]));
    const egress = client();
    await expect(get('https://rebind.egress.test/', {}, egress)).resolves.toMatchObject({
      status: 200,
    });
    const err = await refusal(get('https://rebind.egress.test/', {}, egress));
    expect(err.reason).toBe('address');
    expect(internal.connections).toBe(0);
  });
});

describe('redirects (local test servers)', () => {
  it('follows a redirect to a public host and re-resolves it', async () => {
    serverA.handler = redirect('https://other.egress.test/next');
    const res = await get('https://api.egress.test/start');
    expect(res).toMatchObject({ status: 200, redirects: 1, url: 'https://other.egress.test/next' });
    expect(net.lookups).toEqual(['api.egress.test', 'other.egress.test']);
    expect(serverB.requests[0].url).toBe('/next');
  });

  it('resolves a relative Location against the current URL', async () => {
    let hops = 0;
    serverA.handler = (req, _body, res) => {
      if (hops++ === 0) {
        res.writeHead(301, { location: '/moved?y=2' });
        res.end();
        return;
      }
      res.end(req.url);
    };
    const res = await get('https://api.egress.test/old');
    expect(res.body.toString()).toBe('/moved?y=2');
  });

  it.each([
    ['a private address', 'https://internal.egress.test/', 'address'],
    ['a private IP literal', 'https://10.0.0.7/', 'address'],
    ['the metadata address', 'https://169.254.169.254/latest/meta-data/', 'address'],
    ['loopback over IPv6', 'https://[::1]/', 'address'],
    ['http', 'http://other.egress.test/', 'scheme'],
    ['a URL with credentials', 'https://user:secret@other.egress.test/', 'credentials'],
  ])('refuses a redirect to %s', async (_label, location, reason) => {
    serverA.handler = redirect(location);
    const err = await refusal(get('https://api.egress.test/'));
    expect(err).toMatchObject({ reason, outcome: 'blocked' });
    expect(err.message).not.toContain('secret');
    expect(internal.connections).toBe(0);
    expect(serverB.connections).toBe(0);
  });

  it('follows three redirects and refuses the fourth', async () => {
    let hops = 0;
    serverA.handler = (_req, _body, res) => {
      hops += 1;
      res.writeHead(302, { location: `/hop${hops}` });
      res.end();
    };
    const err = await refusal(get('https://api.egress.test/hop0'));
    expect(err).toMatchObject({ reason: 'redirect', outcome: 'blocked' });
    // The first request and three redirects followed; the fourth is not.
    expect(serverA.requests.map((r) => r.url)).toEqual(['/hop0', '/hop1', '/hop2', '/hop3']);
  });

  it('reaches the target of the third redirect', async () => {
    serverA.handler = (req, _body, res) => {
      const n = Number(req.url?.slice(4));
      if (n < 3) {
        res.writeHead(307, { location: `/hop${n + 1}` });
        res.end();
        return;
      }
      res.end('arrived');
    };
    const res = await get('https://api.egress.test/hop0');
    expect(res).toMatchObject({ status: 200, redirects: 3 });
    expect(res.body.toString()).toBe('arrived');
  });

  it('follows none when the caller sets 0', async () => {
    serverA.handler = redirect('https://other.egress.test/');
    const err = await refusal(get('https://api.egress.test/', { limits: { maxRedirects: 0 } }));
    expect(err.reason).toBe('redirect');
    expect(serverA.requests).toHaveLength(1);
    expect(serverB.connections).toBe(0);
  });

  it('returns a 3xx without a Location as the response', async () => {
    serverA.handler = (_req, _body, res) => {
      res.writeHead(304);
      res.end();
    };
    await expect(get('https://api.egress.test/')).resolves.toMatchObject({ status: 304 });
  });

  it('never forwards Authorization or Cookie to another origin', async () => {
    serverA.handler = redirect('https://other.egress.test/');
    await get('https://api.egress.test/', {
      headers: { Authorization: 'Bearer secret', Cookie: 'sid=1', 'X-Trace': 't' },
    });
    expect(serverA.requests[0].headers.authorization).toBe('Bearer secret');
    expect(serverB.requests[0].headers.authorization).toBeUndefined();
    expect(serverB.requests[0].headers.cookie).toBeUndefined();
    expect(serverB.requests[0].headers['x-trace']).toBe('t');
  });

  it('treats another port of the same host as another origin', async () => {
    let hops = 0;
    serverA.handler = (_req, _body, res) => {
      if (hops++ === 0) {
        res.writeHead(302, { location: 'https://api.egress.test:8443/' });
        res.end();
        return;
      }
      res.end();
    };
    await get('https://api.egress.test/', { headers: { authorization: 'Bearer secret' } });
    // The fixture routes by address, so the second hop lands on server A too.
    expect(serverA.requests).toHaveLength(2);
    expect(serverA.requests[1].headers.host).toBe('api.egress.test:8443');
    expect(serverA.requests[1].headers.authorization).toBeUndefined();
  });

  it('keeps Authorization on a redirect within the same origin', async () => {
    let hops = 0;
    serverA.handler = (_req, _body, res) => {
      if (hops++ === 0) {
        res.writeHead(308, { location: '/again' });
        res.end();
        return;
      }
      res.end();
    };
    await get('https://api.egress.test/', { headers: { authorization: 'Bearer secret' } });
    expect(serverA.requests[1].headers.authorization).toBe('Bearer secret');
  });

  it('keeps the method and body on 307 and 308', async () => {
    let hops = 0;
    serverA.handler = (_req, _body, res) => {
      if (hops++ === 0) {
        res.writeHead(307, { location: '/again' });
        res.end();
        return;
      }
      res.end();
    };
    await client().request({
      method: 'PUT',
      url: 'https://api.egress.test/',
      body: '{"a":1}',
      headers: { 'content-type': 'application/json' },
      purpose: 'test',
      source: 'client',
    });
    expect(serverA.requests[1]).toMatchObject({ method: 'PUT' });
    expect(serverA.requests[1].body.toString()).toBe('{"a":1}');
  });

  it('turns a POST into a GET without a body on 303', async () => {
    serverA.handler = redirect('https://other.egress.test/result', 303);
    await client().request({
      method: 'POST',
      url: 'https://api.egress.test/',
      body: 'payload',
      headers: { 'content-type': 'text/plain' },
      purpose: 'test',
      source: 'client',
    });
    expect(serverB.requests[0]).toMatchObject({ method: 'GET' });
    expect(serverB.requests[0].body.length).toBe(0);
    expect(serverB.requests[0].headers['content-type']).toBeUndefined();
    expect(serverB.requests[0].headers['content-length']).toBeUndefined();
  });
});

describe('methods and bodies (local test servers)', () => {
  it.each(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'] as const)(
    'sends %s',
    async (method) => {
      const res = await client().request({
        method,
        url: 'https://api.egress.test/m',
        purpose: 'test',
        source: 'client',
      });
      expect(res.status).toBe(200);
      expect(serverA.requests[0].method).toBe(method);
      expect(res.body.toString()).toBe(method === 'HEAD' ? '' : 'ok');
    }
  );

  it('sends a POST body and returns the answer', async () => {
    serverA.handler = (_req, body, res) => {
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ got: body.toString() }));
    };
    const res = await client().request({
      method: 'POST',
      url: 'https://api.egress.test/hook',
      body: new TextEncoder().encode('{"event":"x"}'),
      headers: { 'content-type': 'application/json' },
      purpose: 'test',
      source: 'client',
    });
    expect(res.status).toBe(201);
    expect(res.headers['content-type']).toBe('application/json');
    expect(JSON.parse(res.body.toString())).toEqual({ got: '{"event":"x"}' });
    expect(serverA.requests[0].headers['content-length']).toBe('13');
  });

  it('accepts a body at the request cap', async () => {
    const res = await client().request({
      method: 'POST',
      url: 'https://api.egress.test/',
      body: 'x'.repeat(64),
      purpose: 'test',
      source: 'client',
      limits: { maxRequestBytes: 64 },
    });
    expect(res.status).toBe(200);
  });

  it('refuses a body above the request cap without contacting the host', async () => {
    const err = await refusal(
      client().request({
        method: 'POST',
        url: 'https://api.egress.test/',
        body: 'x'.repeat(65),
        purpose: 'test',
        source: 'client',
        limits: { maxRequestBytes: 64 },
      })
    );
    expect(err).toMatchObject({ reason: 'size', outcome: 'blocked', host: 'api.egress.test' });
    expect(net.lookups).toEqual([]);
    expect(serverA.connections).toBe(0);
  });

  it('refuses an oversized array before copying it', async () => {
    const big = new Uint8Array(65);
    const from = vi.spyOn(Buffer, 'from');
    try {
      const err = await refusal(
        client().request({
          method: 'POST',
          url: 'https://api.egress.test/',
          body: big,
          purpose: 'test',
          source: 'client',
          limits: { maxRequestBytes: 64 },
        })
      );
      expect(err.reason).toBe('size');
      expect(from).not.toHaveBeenCalledWith(big);
    } finally {
      from.mockRestore();
    }
  });

  it('measures and sends only the bytes of an array view', async () => {
    const backing = new Uint8Array(200).fill(0x61);
    const res = await client().request({
      method: 'POST',
      url: 'https://api.egress.test/',
      body: backing.subarray(100, 164),
      purpose: 'test',
      source: 'client',
      limits: { maxRequestBytes: 64 },
    });
    expect(res.status).toBe(200);
    expect(serverA.requests[0].body.length).toBe(64);
  });

  it('counts a multi-byte body in bytes, not characters', async () => {
    const err = await refusal(
      client().request({
        method: 'POST',
        url: 'https://api.egress.test/',
        body: 'é'.repeat(40),
        purpose: 'test',
        source: 'client',
        limits: { maxRequestBytes: 64 },
      })
    );
    expect(err.reason).toBe('size');
  });
});

describe('response size (local test servers)', () => {
  it('returns a body at the cap', async () => {
    serverA.handler = (_req, _body, res) => res.end('x'.repeat(100));
    const res = await get('https://api.egress.test/', { limits: { maxResponseBytes: 100 } });
    expect(res.body.length).toBe(100);
  });

  it('refuses a declared length above the cap without reading the body', async () => {
    // The head declares 101 bytes and no body byte ever follows: only the
    // declared length can fail the call before the total timeout.
    serverA.handler = (_req, _body, res) => {
      res.writeHead(200, { 'content-length': '101' });
      res.flushHeaders();
    };
    const started = performance.now();
    const err = await refusal(
      get('https://api.egress.test/', {
        limits: { maxResponseBytes: 100, totalTimeoutMs: 5000 },
      })
    );
    expect(err).toMatchObject({ reason: 'size', outcome: 'failed' });
    expect(performance.now() - started).toBeLessThan(2000);
  });

  // Chunk-size lines and chunk extensions are not body bytes; without a cap
  // on the bytes read from the connection, a host could stream them until the
  // total timeout.
  it.each([
    ['chunk extensions', `1;x=${'a'.repeat(8000)}\r\nb\r\n`],
    ['zero-padded chunk sizes', `${'0'.repeat(8000)}1\r\nb\r\n`],
  ])('stops reading a body framed with endless %s', async (_label, chunk) => {
    let written = 0;
    let closed = false;
    serverA.handler = (_req, _body, res) => {
      const socket = res.socket;
      if (socket === null) return;
      socket.on('close', () => {
        closed = true;
      });
      socket.write('HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n');
      const pump = (): void => {
        while (!closed && written < 64 * 1024 * 1024) {
          written += chunk.length;
          if (!socket.write(chunk)) {
            socket.once('drain', pump);
            return;
          }
        }
      };
      pump();
    };
    const started = performance.now();
    const err = await refusal(
      get('https://api.egress.test/', {
        limits: { maxResponseBytes: 1024, totalTimeoutMs: 10_000 },
      })
    );
    expect(err).toMatchObject({ reason: 'size', outcome: 'failed' });
    expect(performance.now() - started).toBeLessThan(5000);
    await vi.waitFor(() => expect(closed).toBe(true));
    expect(written).toBeLessThan(4 * 1024 * 1024);
  });

  it('cuts off an undeclared body at the cap and stops reading', async () => {
    let written = 0;
    let closed = false;
    serverA.handler = (_req, _body, res) => {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      const chunk = Buffer.alloc(16 * 1024, 0x61);
      const pump = (): void => {
        while (!closed && written < 64 * 1024 * 1024) {
          written += chunk.length;
          if (!res.write(chunk)) {
            res.once('drain', pump);
            return;
          }
        }
        res.end();
      };
      res.on('close', () => {
        closed = true;
      });
      pump();
    };
    const err = await refusal(
      get('https://api.egress.test/', { limits: { maxResponseBytes: 32 * 1024 } })
    );
    expect(err).toMatchObject({ reason: 'size', outcome: 'failed' });
    await vi.waitFor(() => expect(closed).toBe(true));
    // The server stopped long before its 64 MiB.
    expect(written).toBeLessThan(16 * 1024 * 1024);
  });

  it('ignores the declared length of a HEAD answer', async () => {
    serverA.handler = (_req, _body, res) => {
      res.writeHead(200, { 'content-length': '999999' });
      res.end();
    };
    const res = await client().request({
      method: 'HEAD',
      url: 'https://api.egress.test/',
      purpose: 'test',
      source: 'client',
      limits: { maxResponseBytes: 10 },
    });
    expect(res.status).toBe(200);
  });
});

describe('timeouts (local test servers)', () => {
  /** A public address whose host accepts TCP and never answers the TLS handshake. */
  const SILENT = '198.41.0.4';
  let silent: Server;

  beforeAll(async () => {
    // Reads the ClientHello and never answers. Reading is what lets it see
    // the client close the connection.
    silent = createTcpServer((socket) => socket.on('error', () => undefined).resume());
    await new Promise<void>((resolve) => silent.listen(0, '127.0.0.1', resolve));
    net.route(SILENT, (silent.address() as AddressInfo).port);
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => silent.close(() => resolve()));
  });

  it('gives up on a TLS handshake that never completes at the connect timeout', async () => {
    net.dns.set('silent.egress.test', [SILENT]);
    const started = performance.now();
    const err = await refusal(
      get('https://silent.egress.test/', {
        limits: { connectTimeoutMs: 200, totalTimeoutMs: 5000 },
      })
    );
    expect(err).toMatchObject({ reason: 'timeout', outcome: 'failed' });
    expect(err.message).toContain('connection timed out');
    expect(performance.now() - started).toBeLessThan(2000);
  });

  it('gives up on a host that drips its body at the total timeout', async () => {
    serverA.handler = (_req, _body, res) => {
      res.writeHead(200, { 'content-length': '4096' });
      const timer = setInterval(() => res.write(' '), 50);
      res.on('close', () => clearInterval(timer));
    };
    const started = performance.now();
    const err = await refusal(get('https://api.egress.test/', { limits: { totalTimeoutMs: 400 } }));
    expect(err).toMatchObject({ reason: 'timeout', outcome: 'failed' });
    expect(performance.now() - started).toBeLessThan(2000);
  });

  it('gives up on a name server that never answers at the total timeout', async () => {
    network.current = { ...net.transport, resolveHost: () => new Promise(() => undefined) };
    const err = await refusal(get('https://api.egress.test/', { limits: { totalTimeoutMs: 200 } }));
    expect(err).toMatchObject({ reason: 'timeout', outcome: 'failed' });
  });
});

describe('validateDestination', () => {
  it('resolves and checks without sending anything', async () => {
    const exchange = vi.fn(net.transport.exchange);
    network.current = { ...net.transport, exchange };
    await expect(
      client().validateDestination('https://api.egress.test/hook?token=abc', {
        purpose: 'webhook',
        source: 'client',
      })
    ).resolves.toEqual({
      url: 'https://api.egress.test/hook?token=abc',
      host: 'api.egress.test',
      port: 443,
      addresses: [PUBLIC_A],
    });
    expect(net.lookups).toEqual(['api.egress.test']);
    expect(exchange).not.toHaveBeenCalled();
    expect(net.dialled).toEqual([]);
    expect(serverA.connections).toBe(0);
  });

  it.each([
    ['http://api.egress.test/', 'scheme'],
    ['https://u:p@api.egress.test/', 'credentials'],
    ['https://internal.egress.test/', 'address'],
    ['https://[::1]:8443/', 'address'],
  ])('refuses %s with %s', async (url, reason) => {
    const err = await refusal(
      client().validateDestination(url, { purpose: 'webhook', source: 'client' })
    );
    expect(err).toMatchObject({ reason, outcome: 'blocked', purpose: 'webhook' });
    expect(net.dialled).toEqual([]);
  });
});

/*
 * The deployment allowlist (ADR-019 Decision 8, issue #481): an entry opens a
 * non-public host or range only for an `operator` or `admin` destination of a
 * realm it names. `internal.egress.test` resolves to 10.0.0.7, whose server
 * answers "internal secret".
 */
describe('the deployment allowlist', () => {
  const allowlist = parseEgressAllowlist({
    entries: [
      { cidr: '10.0.0.0/24', realms: ['acme'] },
      { host: 'internal.egress.test', realms: ['beta'] },
      { host: 'loopback.egress.test', realms: ['beta'] },
      { cidr: '169.254.0.0/16', realms: ['acme'] },
      { cidr: '127.0.0.0/8', realms: ['acme'] },
    ],
  });
  const listed = () => client({ allowlist });

  beforeEach(() => {
    net.dns.set('alias.egress.test', [PRIVATE]);
    net.dns.set('metadata.egress.test', [METADATA]);
    net.dns.set('loopback.egress.test', [LOOPBACK]);
    net.dns.set('mixed.egress.test', [PRIVATE, '10.0.1.7']);
  });

  it.each(['operator', 'admin'] as const)(
    'lets a %s destination reach a listed range for a realm the entry names',
    async (source) => {
      const res = await get('https://internal.egress.test/', { source, realm: 'acme' }, listed());
      expect(res.status).toBe(200);
      expect(res.body.toString()).toBe('internal secret');
      expect(net.dialled).toEqual([[PRIVATE]]);
    }
  );

  it('refuses the same destination for a realm no entry names', async () => {
    const err = await refusal(
      get('https://alias.egress.test/', { source: 'operator', realm: 'other' }, listed())
    );
    expect(err).toMatchObject({ reason: 'address', outcome: 'blocked' });
    expect(internal.connections).toBe(0);
  });

  it('refuses an operator destination that names no realm', async () => {
    const err = await refusal(
      get('https://internal.egress.test/', { source: 'operator' }, listed())
    );
    expect(err).toMatchObject({ reason: 'address', outcome: 'blocked' });
    expect(internal.connections).toBe(0);
  });

  it.each(['client', 'end_user', 'remote_document'] as const)(
    'never lets a %s destination use an entry, even for a realm it names',
    async (source) => {
      for (const realm of ['acme', 'beta']) {
        const err = await refusal(
          get('https://internal.egress.test/', { source, realm }, listed())
        );
        expect(err).toMatchObject({ reason: 'address', outcome: 'blocked' });
      }
      expect(net.dialled).toEqual([]);
      expect(internal.connections).toBe(0);
    }
  );

  it('matches a host entry by the URL host only, not by the address it resolves to', async () => {
    const res = await get(
      'https://internal.egress.test/',
      { source: 'admin', realm: 'beta' },
      listed()
    );
    expect(res.status).toBe(200);

    const err = await refusal(
      get('https://alias.egress.test/', { source: 'admin', realm: 'beta' }, listed())
    );
    expect(err).toMatchObject({ reason: 'address', outcome: 'blocked' });
  });

  it('refuses a name when one of its addresses lies outside every listed range', async () => {
    const err = await refusal(
      get('https://mixed.egress.test/', { source: 'operator', realm: 'acme' }, listed())
    );
    expect(err).toMatchObject({ reason: 'address', outcome: 'blocked' });
    expect(net.dialled).toEqual([]);
  });

  it('never opens the cloud metadata address, even inside a listed range', async () => {
    const err = await refusal(
      get('https://metadata.egress.test/', { source: 'operator', realm: 'acme' }, listed())
    );
    expect(err).toMatchObject({ reason: 'address', outcome: 'blocked' });
    expect(net.dialled).toEqual([]);

    const literal = await refusal(
      get('https://169.254.169.254/', { source: 'operator', realm: 'acme' }, listed())
    );
    expect(literal).toMatchObject({ reason: 'address', outcome: 'blocked' });
  });

  it('opens loopback through a range that lists it, never through a host entry', async () => {
    const res = await get(
      'https://loopback.egress.test/',
      { source: 'operator', realm: 'acme' },
      listed()
    );
    expect(res.status).toBe(200);
    const err = await refusal(
      get('https://loopback.egress.test/', { source: 'operator', realm: 'beta' }, listed())
    );
    expect(err).toMatchObject({ reason: 'address', outcome: 'blocked' });
  });

  it('checks an IP literal in the URL against the ranges too', async () => {
    // The fixture certificate names egress.test hosts only, so a literal that
    // passes the address check then fails the certificate check.
    const opened = await refusal(
      get(`https://${PRIVATE}/`, { source: 'operator', realm: 'acme' }, listed())
    );
    expect(opened).toMatchObject({ reason: 'network', outcome: 'failed' });
    expect(net.dialled).toEqual([[PRIVATE]]);

    const refused = await refusal(
      get(`https://${PRIVATE}/`, { source: 'operator', realm: 'beta' }, listed())
    );
    expect(refused).toMatchObject({ reason: 'address', outcome: 'blocked' });
    expect(net.dialled).toEqual([[PRIVATE]]);
  });

  it('does not follow a redirect to another host onto a listed range', async () => {
    serverA.handler = redirect('https://internal.egress.test/');
    const err = await refusal(
      get('https://api.egress.test/', { source: 'operator', realm: 'acme' }, listed())
    );
    expect(err).toMatchObject({ reason: 'address', outcome: 'blocked' });
    expect(internal.connections).toBe(0);
  });

  it('follows a redirect that stays on the listed host', async () => {
    let first = true;
    internal.handler = (_req, _body, res) => {
      if (first) {
        first = false;
        res.writeHead(302, { location: '/moved' });
        res.end();
        return;
      }
      res.end('internal secret');
    };
    const res = await get(
      'https://internal.egress.test/',
      { source: 'operator', realm: 'acme' },
      listed()
    );
    expect(res).toMatchObject({ status: 200, redirects: 1 });
    expect(internal.requests.map(({ url }) => url)).toEqual(['/', '/moved']);
  });

  it('applies the same rules in validateDestination', async () => {
    const egress = listed();
    await expect(
      egress.validateDestination('https://internal.egress.test/', {
        purpose: 'webhook',
        source: 'admin',
        realm: 'acme',
      })
    ).resolves.toMatchObject({ host: 'internal.egress.test', addresses: [PRIVATE] });
    for (const options of [
      { source: 'admin', realm: 'other' },
      { source: 'client', realm: 'acme' },
    ] as const) {
      const err = await refusal(
        egress.validateDestination('https://internal.egress.test/', {
          purpose: 'webhook',
          ...options,
        })
      );
      expect(err).toMatchObject({ reason: 'address', outcome: 'blocked' });
    }
    expect(net.dialled).toEqual([]);
  });

  it('names the source and the realm in the log line of a refusal', async () => {
    const warn = vi.fn();
    await refusal(
      get(
        'https://internal.egress.test/',
        { source: 'operator', realm: 'other' },
        client({ allowlist, logger: { warn } })
      )
    );
    expect(warn).toHaveBeenCalledWith(
      {
        purpose: 'test',
        source: 'operator',
        realm: 'other',
        host: 'internal.egress.test',
        reason: 'address',
        outcome: 'blocked',
      },
      'egress call blocked'
    );
  });

  it('refuses an allowlist that did not come from the parser', () => {
    expect(() =>
      createEgressClient({
        allowlist: { entries: [{ cidr: '10.0.0.0/8', realms: ['acme'] }] },
      })
    ).toThrow(TypeError);
  });
});

describe('proxy settings', () => {
  const PROXY_VARIABLES = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY'];
  let proxy: Server;
  let proxyConnections = 0;
  const savedEnv: Record<string, string | undefined> = {};
  const savedAgents = { http: http.globalAgent, https: https.globalAgent };

  beforeAll(async () => {
    proxy = createTcpServer((socket) => {
      proxyConnections += 1;
      socket.destroy();
    });
    await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  });

  beforeEach(() => {
    const url = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
    for (const name of PROXY_VARIABLES) {
      savedEnv[name] = process.env[name];
      process.env[name] = url;
    }
    // What NODE_USE_ENV_PROXY=1 does at startup: global agents that honour
    // the variables.
    http.globalAgent = new http.Agent({ proxyEnv: process.env });
    https.globalAgent = new https.Agent({ proxyEnv: process.env });
    proxyConnections = 0;
  });

  afterEach(() => {
    for (const name of PROXY_VARIABLES) {
      if (savedEnv[name] === undefined) delete process.env[name];
      else process.env[name] = savedEnv[name];
    }
    http.globalAgent = savedAgents.http;
    https.globalAgent = savedAgents.https;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => proxy.close(() => resolve()));
  });

  it('would send a plain https.request to the proxy', async () => {
    await new Promise<void>((resolve) => {
      const req = https.request('https://api.egress.test/', () => resolve());
      req.on('error', () => resolve());
      req.end();
    });
    expect(proxyConnections).toBe(1);
  });

  it('has no effect on the egress client', async () => {
    const res = await get('https://api.egress.test/');
    expect(res.status).toBe(200);
    expect(serverA.requests).toHaveLength(1);
    expect(proxyConnections).toBe(0);
  });
});

describe('counting and logging', () => {
  it('counts blocked and failed calls per purpose and logs host and reason only', async () => {
    const warn = vi.fn();
    const inc = vi.fn();
    const egress = client({ logger: { warn }, counter: { inc } });

    await refusal(
      get('https://internal.egress.test/path?secret=1', { purpose: 'webhook' }, egress)
    );
    await refusal(get('http://api.egress.test/?secret=1', { purpose: 'webhook' }, egress));
    await refusal(get('https://nowhere.egress.test/', { purpose: 'cimd' }, egress));
    await get('https://api.egress.test/', { purpose: 'cimd' }, egress);

    expect(egress.counts()).toEqual({
      webhook: { blocked: 2, failed: 0, reasons: { address: 1, scheme: 1 } },
      cimd: { blocked: 0, failed: 1, reasons: { network: 1 } },
    });
    expect(inc.mock.calls).toEqual([
      [{ purpose: 'webhook', outcome: 'blocked', reason: 'address' }],
      [{ purpose: 'webhook', outcome: 'blocked', reason: 'scheme' }],
      [{ purpose: 'cimd', outcome: 'failed', reason: 'network' }],
    ]);
    expect(warn).toHaveBeenCalledWith(
      {
        purpose: 'webhook',
        source: 'client',
        host: 'internal.egress.test',
        reason: 'address',
        outcome: 'blocked',
      },
      'egress call blocked'
    );
    expect(warn).toHaveBeenCalledWith(
      {
        purpose: 'cimd',
        source: 'client',
        host: 'nowhere.egress.test',
        reason: 'network',
        outcome: 'failed',
      },
      'egress call failed'
    );
    const logged = JSON.stringify(warn.mock.calls);
    expect(logged).not.toContain('secret');
    expect(logged).not.toContain('/path');
  });

  it('reports a call the fetch pool has no room for as busy, without dialling', async () => {
    const inc = vi.fn();
    network.current = {
      ...net.transport,
      exchange: async (job) => ({
        kind: 'failed',
        reason: 'busy',
        message: `egress to ${job.hostname} failed: too many calls in progress`,
      }),
    };
    const err = await refusal(get('https://api.egress.test/', {}, client({ counter: { inc } })));
    expect(err).toMatchObject({ reason: 'busy', outcome: 'failed', host: 'api.egress.test' });
    expect(inc).toHaveBeenCalledWith({ purpose: 'test', outcome: 'failed', reason: 'busy' });
    expect(serverA.connections).toBe(0);
  });

  it('keeps headers and query strings out of error messages', async () => {
    serverA.handler = redirect('https://10.0.0.7/x?secret=1');
    const err = await refusal(
      get('https://api.egress.test/a?secret=2', { headers: { authorization: 'Bearer secret' } })
    );
    expect(err.message).not.toContain('secret');
    expect(err.message).not.toContain('/x');
  });

  it('counts a purpose that names an Object.prototype property like any other', async () => {
    const egress = client();
    const err = await refusal(
      get('https://internal.egress.test/', { purpose: 'constructor' }, egress)
    );
    expect(err.reason).toBe('address');
    expect(egress.counts()).toEqual({
      constructor: { blocked: 1, failed: 0, reasons: { address: 1 } },
    });
    expect(Object.hasOwn(Object, 'blocked')).toBe(false);
  });

  it('counts validateDestination refusals too', async () => {
    const egress = client();
    await refusal(
      egress.validateDestination('https://internal.egress.test/', {
        purpose: 'webhook',
        source: 'client',
      })
    );
    expect(egress.counts()).toEqual({
      webhook: { blocked: 1, failed: 0, reasons: { address: 1 } },
    });
  });
});

describe('caller mistakes', () => {
  it.each([
    ['an empty purpose', { purpose: '' }],
    ['a purpose with spaces', { purpose: 'web hook' }],
    ['an upper-case purpose', { purpose: 'Webhook' }],
    ['an unknown source', { source: 'partner' }],
    ['a missing source', { source: undefined }],
    ['an empty realm', { realm: '' }],
    ['a realm that is not a string', { realm: 7 }],
    ['an unknown method', { method: 'TRACE' }],
    ['a forbidden header', { headers: { host: 'internal' } }],
    ['a Content-Length header', { headers: { 'Content-Length': '1' } }],
    ['a header with a newline', { headers: { 'x-a': 'a\r\nb: c' } }],
    ['a GET body', { body: 'x' }],
    ['a negative limit', { limits: { maxResponseBytes: -1 } }],
    ['a zero timeout', { limits: { totalTimeoutMs: 0 } }],
  ])('throws a TypeError for %s, uncounted', async (_label, extra) => {
    const egress = client();
    await expect(
      egress.request({
        method: 'GET',
        url: 'https://api.egress.test/',
        purpose: 'test',
        source: 'client',
        ...(extra as Partial<EgressRequest>),
      })
    ).rejects.toThrow(TypeError);
    expect(egress.counts()).toEqual({});
    expect(serverA.connections).toBe(0);
  });
});
