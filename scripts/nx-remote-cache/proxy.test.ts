/**
 * Guard for `.github/actions/nx-remote-cache/proxy.mjs`, the local proxy CI puts
 * between Nx and the self-hosted remote cache (#960).
 *
 * Nx 24's HTTP remote cache fails the whole `nx` command when the server cannot be
 * reached, or answers anything but 200/404 to a read and 200/403/409 to a write.
 * The proxy must turn every such failure into a miss (read) or a refused write
 * (403), so losing the cache makes CI slower and never red. Each case runs the
 * proxy against a scripted upstream on loopback.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  createProxy,
  probe,
  safeUpstream,
  summary,
} from '../../.github/actions/nx-remote-cache/proxy.mjs';

type Behaviour = (req: http.IncomingMessage, res: http.ServerResponse, body: Buffer) => void;

interface Seen {
  method?: string;
  url?: string;
  auth?: string;
  length?: string;
}

interface Stats {
  hits: number;
  misses: number;
  stored: number;
  existing: number;
  refused: number;
  errors: number;
  gaveUp: boolean;
}

const TOKEN = 'nxc_test-token';
let upstream: http.Server;
let upstreamUrl: string;
let behave: Behaviour;
const seen: Seen[] = [];

/** Answer every request with `status` and an optional body. */
function answer(status: number, body = '', headers: http.OutgoingHttpHeaders = {}): Behaviour {
  return (_req, res) => {
    res.writeHead(status, headers);
    res.end(body);
  };
}

/** Never answer: the proxy's idle timeout has to give up. */
const silent: Behaviour = () => undefined;

function port(server: http.Server): number {
  return (server.address() as AddressInfo).port;
}

beforeAll(async () => {
  upstream = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      seen.push({
        method: req.method,
        url: req.url,
        auth: req.headers.authorization,
        length: req.headers['content-length'],
      });
      behave(req, res, Buffer.concat(chunks));
    });
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${port(upstream)}`;
});

afterAll(() => {
  upstream.closeAllConnections();
  upstream.close();
});

beforeEach(() => {
  seen.length = 0;
  behave = answer(404);
});

async function withProxy(
  fn: (run: { base: string; stats: Stats; warnings: string[] }) => Promise<void>,
  upstreamOverride?: string
) {
  const warnings: string[] = [];
  const { server, stats } = createProxy({
    upstream: upstreamOverride ?? upstreamUrl,
    token: TOKEN,
    warn: (message: string) => warnings.push(message),
    idleMs: 300,
    readDeadlineMs: 1000,
    writeDeadlineMs: 1000,
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await fn({ base: `http://127.0.0.1:${port(server)}`, stats, warnings });
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

async function get(base: string, hash = '123') {
  const res = await fetch(`${base}/v1/cache/${hash}`);
  return { status: res.status, body: Buffer.from(await res.arrayBuffer()) };
}

async function put(base: string, hash = '123', body = Buffer.from('tarball')) {
  const res = await fetch(`${base}/v1/cache/${hash}`, { method: 'PUT', body });
  await res.arrayBuffer();
  return res.status;
}

describe('reads', () => {
  it('relays a 200 with the whole body, adding the token', async () => {
    behave = answer(200, 'cached bytes', { 'Content-Type': 'application/octet-stream' });
    await withProxy(async ({ base, stats }) => {
      const r = await get(base);
      expect(r.status).toBe(200);
      expect(r.body.toString()).toBe('cached bytes');
      expect(seen[0]).toMatchObject({ auth: `Bearer ${TOKEN}`, url: '/v1/cache/123' });
      expect(stats.hits).toBe(1);
    });
  });

  const failures: [string, Behaviour][] = [
    ['a 404', answer(404)],
    ['a 500', answer(500, 'boom')],
    ['a 401', answer(401)],
    ['a 403', answer(403)],
    ['a 502 from a tunnel', answer(502, '<html>bad gateway</html>')],
    ['no answer in time', silent],
    [
      'a body cut off midway',
      (_req, res) => {
        res.writeHead(200, { 'Content-Length': '1000' });
        res.write('partial');
        setTimeout(() => res.destroy(), 20);
      },
    ],
  ];

  it.each(failures)('turns %s into a miss', async (_what, behaviour) => {
    behave = behaviour;
    await withProxy(async ({ base, stats }) => {
      expect((await get(base)).status).toBe(404);
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(1);
    });
  });

  it('turns an unreachable server into a miss', async () => {
    await withProxy(async ({ base, stats }) => {
      expect((await get(base)).status).toBe(404);
      expect(stats.errors).toBe(1);
    }, 'http://127.0.0.1:1');
  });

  it('answers a malformed path or hash without calling the server', async () => {
    await withProxy(async ({ base }) => {
      expect((await fetch(`${base}/v1/cache/..%2Fx`)).status).toBe(404);
      expect((await fetch(`${base}/elsewhere`)).status).toBe(404);
      expect(seen).toHaveLength(0);
    });
  });
});

describe('writes', () => {
  it('relays a 200, with the body and its length', async () => {
    let received = '';
    behave = (_req, res, body) => {
      received = body.toString();
      res.writeHead(200);
      res.end();
    };
    await withProxy(async ({ base, stats }) => {
      expect(await put(base)).toBe(200);
      expect(received).toBe('tarball');
      expect(seen[0]).toMatchObject({ method: 'PUT', length: '7' });
      expect(stats.stored).toBe(1);
    });
  });

  it('relays a 409', async () => {
    behave = answer(409);
    await withProxy(async ({ base, stats }) => {
      expect(await put(base)).toBe(409);
      expect(stats.existing).toBe(1);
    });
  });

  const refusals: [string, Behaviour][] = [
    ['a read-only token (403)', answer(403)],
    ['a 413 from the tunnel', answer(413)],
    ['a 500', answer(500)],
    ['a 401', answer(401)],
    ['no answer in time', silent],
  ];

  it.each(refusals)(
    'turns %s into a 403, which Nx reads as "not stored"',
    async (_what, behaviour) => {
      behave = behaviour;
      await withProxy(async ({ base, stats }) => {
        expect(await put(base)).toBe(403);
        expect(stats.refused).toBe(1);
      });
    }
  );
});

describe('giving up', () => {
  it('stops calling a failing server after three failures in a row', async () => {
    behave = answer(503);
    await withProxy(async ({ base, stats, warnings }) => {
      for (const hash of ['1', '2', '3']) expect((await get(base, hash)).status).toBe(404);
      expect(stats.gaveUp).toBe(true);
      expect(warnings).toHaveLength(1);
      const calls = seen.length;
      expect((await get(base, '9')).status).toBe(404);
      expect(await put(base, '9')).toBe(403);
      expect(seen.length, 'no call after giving up').toBe(calls);
    });
  });

  it('gives up at once on a refused token', async () => {
    behave = answer(401, 'unauthorized', { 'Content-Type': 'text/plain' });
    await withProxy(async ({ base, stats }) => {
      await get(base);
      expect(stats.gaveUp).toBe(true);
    });
  });

  it('counts only failures in a row', async () => {
    let n = 0;
    behave = (_req, res) => {
      n += 1;
      res.writeHead(n === 3 ? 404 : 500);
      res.end();
    };
    await withProxy(async ({ base, stats }) => {
      for (const hash of ['1', '2', '3', '4']) await get(base, hash);
      expect(stats.gaveUp).toBe(false);
    });
  });
});

describe('probe', () => {
  it('reads the namespace and access of the token', async () => {
    behave = answer(200, JSON.stringify({ namespace: 'qauth', access: 'read', entries: 3 }));
    expect(await probe(upstreamUrl, TOKEN)).toEqual({ namespace: 'qauth', access: 'read' });
    expect(seen[0].url).toBe('/v1/stats');
  });

  it('says why when the server refuses the token', async () => {
    behave = answer(401);
    expect((await probe(upstreamUrl, TOKEN)).error).toMatch(/HTTP 401/);
  });

  it('says why when the server cannot be reached', async () => {
    expect((await probe('http://127.0.0.1:1', TOKEN)).error).toMatch(/cannot reach/);
  });

  it('never sends the token over plain http to another host', async () => {
    expect(safeUpstream('http://cache.example.com')).toBe(false);
    expect(safeUpstream('https://cache.example.com')).toBe(true);
    expect(safeUpstream('http://127.0.0.1:8050')).toBe(true);
    expect((await probe('http://cache.example.com', TOKEN)).error).toMatch(/https/);
    expect(() => createProxy({ upstream: 'http://cache.example.com', token: TOKEN })).toThrow(
      /https/
    );
  });
});

describe('summary', () => {
  it('reports the hit rate', () => {
    const text = summary(
      {
        hits: 3,
        misses: 1,
        stored: 0,
        existing: 0,
        refused: 0,
        errors: 0,
        bytesDown: 3 * 1024 * 1024,
        bytesUp: 0,
        gaveUp: false,
        lastError: null,
      },
      { namespace: 'qauth', access: 'read' }
    );
    expect(text).toContain('4: 3 hit, 1 miss (hit rate 75%)');
    expect(text).toContain('`qauth` (read only)');
    expect(text).toContain('3.0 MB down');
  });
});
