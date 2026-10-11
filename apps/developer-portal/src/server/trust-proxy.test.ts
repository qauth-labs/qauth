import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';

import { serve } from 'srvx';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('./config', () => ({
  env: {
    AUTH_SERVER_URL: 'http://auth-server:3001',
    PORTAL_SESSION_SECRET: 'test-secret-minimum-32-chars-long!!',
    PORTAL_SESSION_TTL: 900,
  },
}));

// Stands in for Start's getRequestIP(), which returns the srvx request's `ip`.
const { mockGetRequestIP } = vi.hoisted(() => ({ mockGetRequestIP: vi.fn() }));
vi.mock('@tanstack/react-start/server', () => ({
  getRequestIP: mockGetRequestIP,
  getRequestHeader: vi.fn(),
}));

import { authServerClient } from './auth-server-client';
import { parsePortalTrustProxy } from './trust-proxy';

/**
 * PORTAL_TRUST_PROXY decides which proxies in front of the portal may report
 * the client address, and the portal forwards that one address to the
 * auth-server. Unset must mean "no proxy"; `true` and hop counts must never be
 * accepted, because they let any caller pick its own address.
 */
describe('parsePortalTrustProxy', () => {
  it('defaults to trusting no proxy', () => {
    expect(parsePortalTrustProxy(undefined)).toBe(false);
    expect(parsePortalTrustProxy('')).toBe(false);
    expect(parsePortalTrustProxy('  ')).toBe(false);
    expect(parsePortalTrustProxy('false')).toBe(false);
  });

  it('rejects true (trust every hop)', () => {
    expect(() => parsePortalTrustProxy('true')).toThrow(/PORTAL_TRUST_PROXY=true/);
  });

  it('rejects a hop count, which cannot tell a proxy from a direct client', () => {
    expect(() => parsePortalTrustProxy('1')).toThrow(/not a hop count/);
    expect(() => parsePortalTrustProxy('0')).toThrow(/not a hop count/);
  });

  it('accepts single addresses, in the form srvx compares', () => {
    expect(parsePortalTrustProxy('10.0.4.12, ::1,2001:DB8:0:0::7, ::ffff:192.0.2.5')).toEqual([
      '10.0.4.12',
      '::1',
      '2001:db8::7',
      '192.0.2.5',
    ]);
    expect(parsePortalTrustProxy('::ffff:7f00:1, ::FFFF:C000:205')).toEqual([
      '127.0.0.1',
      '192.0.2.5',
    ]);
  });

  it('rejects CIDR ranges and named ranges, which srvx would never match', () => {
    expect(() => parsePortalTrustProxy('10.0.0.0/8')).toThrow(/invalid: 10.0.0.0\/8/);
    expect(() => parsePortalTrustProxy('fd00::/8')).toThrow(/invalid: fd00::\/8/);
    expect(() => parsePortalTrustProxy('10.0.4.12, uniquelocal')).toThrow(/invalid: uniquelocal/);
    expect(() => parsePortalTrustProxy('loopback')).toThrow(/invalid: loopback/);
  });

  it('rejects malformed entries', () => {
    expect(() => parsePortalTrustProxy('proxy.internal')).toThrow(/invalid: proxy.internal/);
    expect(() => parsePortalTrustProxy('10.0.0.256')).toThrow(/invalid: 10.0.0.256/);
    expect(() => parsePortalTrustProxy('fe80::1%eth0')).toThrow(/invalid: fe80::1%eth0/);
    expect(() => parsePortalTrustProxy('*')).toThrow(/invalid/);
  });
});

/**
 * End to end through a real srvx server: the address the portal forwards for
 * a request carrying the given headers, with PORTAL_TRUST_PROXY set to
 * `trustProxy`. The test client connects from 127.0.0.1, so listing
 * 127.0.0.1 makes it a trusted proxy.
 */
async function throughPortal(
  trustProxy: string | undefined,
  headers: Record<string, string>,
  hostname = '127.0.0.1'
): Promise<{ forwardedFor: string | undefined; url: string }> {
  let seen: { forwardedFor: string | undefined; url: string } | undefined;
  const server = serve({
    port: 0,
    hostname,
    silent: true,
    gracefulShutdown: false,
    trustProxy: parsePortalTrustProxy(trustProxy),
    fetch: async (request) => {
      mockGetRequestIP.mockReturnValue(request.ip);
      const upstream = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({}),
      } as Response);
      global.fetch = upstream;
      await authServerClient.login('dev@example.com', 'pw');
      const [, init] = upstream.mock.calls[0] as [string, RequestInit];
      const sent = (init.headers ?? {}) as Record<string, string>;
      seen = { forwardedFor: sent['X-Forwarded-For'], url: request.url };
      return new Response('ok');
    },
  });
  await server.ready();
  try {
    const { port } = server.node?.server?.address() as AddressInfo;
    await new Promise<void>((resolve, reject) => {
      const req = httpRequest(
        { host: '127.0.0.1', port, path: '/login', method: 'POST', headers },
        (res) => {
          res.resume();
          res.on('end', resolve);
        }
      );
      req.on('error', reject);
      req.end();
    });
  } finally {
    await server.close(true);
  }
  if (!seen) throw new Error('the request did not reach the handler');
  return seen;
}

describe('the address forwarded through srvx and PORTAL_TRUST_PROXY', () => {
  const realFetch = global.fetch;
  afterEach(() => {
    mockGetRequestIP.mockReset();
    global.fetch = realFetch;
  });

  it('unset: forwards the peer and ignores the caller X-Forwarded-For', async () => {
    const seen = await throughPortal(undefined, { 'X-Forwarded-For': '203.0.113.9' });
    expect(seen.forwardedFor).toBe('127.0.0.1');
  });

  it('set, and the peer is a listed proxy: forwards the client the proxy appended', async () => {
    const seen = await throughPortal('127.0.0.1', { 'X-Forwarded-For': '203.0.113.9' });
    expect(seen.forwardedFor).toBe('203.0.113.9');
  });

  it('set, and the peer is not listed: forwards the peer and ignores X-Forwarded-For', async () => {
    const seen = await throughPortal('192.0.2.10', { 'X-Forwarded-For': '203.0.113.9' });
    expect(seen.forwardedFor).toBe('127.0.0.1');
  });

  it('forwards the address the listed proxy appended, never entries sent before it', async () => {
    const seen = await throughPortal('127.0.0.1', {
      'X-Forwarded-For': '198.51.100.66, 198.51.100.67, 203.0.113.9',
    });
    expect(seen.forwardedFor).toBe('203.0.113.9');
  });

  it('forwards nothing when a listed proxy reports something that is not an IP address', async () => {
    const word = await throughPortal('127.0.0.1', { 'X-Forwarded-For': 'not-an-ip' });
    expect(word.forwardedFor).toBeUndefined();
    const withPort = await throughPortal('127.0.0.1', { 'X-Forwarded-For': '203.0.113.9:5678' });
    expect(withPort.forwardedFor).toBeUndefined();
  });

  it('matches a listed IPv4 proxy on a dual-stack listener and forwards plain IPv4', async () => {
    const unlisted = await throughPortal(undefined, {}, '::');
    expect(unlisted.forwardedFor).toBe('127.0.0.1');
    const listed = await throughPortal('127.0.0.1', { 'X-Forwarded-For': '203.0.113.9' }, '::');
    expect(listed.forwardedFor).toBe('203.0.113.9');
  });

  it('takes the protocol and host from a listed proxy only', async () => {
    const headers = {
      Host: 'portal-internal:3001',
      'X-Forwarded-For': '203.0.113.9',
      'X-Forwarded-Proto': 'https',
      'X-Forwarded-Host': 'portal.example.com',
    };
    const listed = await throughPortal('127.0.0.1', headers);
    expect(new URL(listed.url).origin).toBe('https://portal.example.com');
    const unlisted = await throughPortal('192.0.2.10', headers);
    expect(new URL(unlisted.url).origin).toBe('http://portal-internal:3001');
  });
});
