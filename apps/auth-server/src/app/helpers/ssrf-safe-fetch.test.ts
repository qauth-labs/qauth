import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { isPublicUnicastAddress, SsrfBlockedError, ssrfSafeGet } from './ssrf-safe-fetch';

describe('isPublicUnicastAddress — SSRF blocklist (CIMD §6)', () => {
  it('blocks IPv4 loopback', () => {
    expect(isPublicUnicastAddress('127.0.0.1')).toBe(false);
    expect(isPublicUnicastAddress('127.255.255.254')).toBe(false);
  });

  it('blocks the cloud-metadata link-local address and the whole 169.254/16', () => {
    expect(isPublicUnicastAddress('169.254.169.254')).toBe(false); // AWS/GCP/Azure metadata
    expect(isPublicUnicastAddress('169.254.0.1')).toBe(false);
  });

  it('blocks RFC 1918 private ranges', () => {
    expect(isPublicUnicastAddress('10.0.0.1')).toBe(false);
    expect(isPublicUnicastAddress('172.16.5.4')).toBe(false);
    expect(isPublicUnicastAddress('172.31.255.255')).toBe(false);
    expect(isPublicUnicastAddress('192.168.1.1')).toBe(false);
  });

  it('blocks CGNAT, unspecified, multicast and reserved IPv4', () => {
    expect(isPublicUnicastAddress('100.64.0.1')).toBe(false); // CGNAT
    expect(isPublicUnicastAddress('0.0.0.0')).toBe(false);
    expect(isPublicUnicastAddress('224.0.0.1')).toBe(false); // multicast
    expect(isPublicUnicastAddress('255.255.255.255')).toBe(false);
  });

  it('blocks IPv6 loopback, link-local, unique-local, and IPv4-mapped private', () => {
    expect(isPublicUnicastAddress('::1')).toBe(false);
    expect(isPublicUnicastAddress('::')).toBe(false);
    expect(isPublicUnicastAddress('fe80::1')).toBe(false); // link-local
    expect(isPublicUnicastAddress('fd00::1')).toBe(false); // unique-local
    expect(isPublicUnicastAddress('fd00:ec2::254')).toBe(false); // AWS IPv6 metadata
    expect(isPublicUnicastAddress('::ffff:169.254.169.254')).toBe(false); // mapped metadata
    expect(isPublicUnicastAddress('::ffff:10.0.0.1')).toBe(false); // mapped private
  });

  it('allows genuine public addresses', () => {
    expect(isPublicUnicastAddress('8.8.8.8')).toBe(true);
    expect(isPublicUnicastAddress('1.1.1.1')).toBe(true);
    expect(isPublicUnicastAddress('203.0.113.10')).toBe(true);
    expect(isPublicUnicastAddress('2606:4700:4700::1111')).toBe(true); // Cloudflare DNS
  });

  it('rejects non-IP input', () => {
    expect(isPublicUnicastAddress('not-an-ip')).toBe(false);
    expect(isPublicUnicastAddress('')).toBe(false);
  });
});

describe('ssrfSafeGet — request-level guards', () => {
  it('rejects non-https schemes', async () => {
    await expect(
      ssrfSafeGet('http://example.com/doc', { timeoutMs: 1000, maxBytes: 1024 })
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('rejects embedded credentials in the URL', async () => {
    await expect(
      ssrfSafeGet('https://user:pass@example.com/doc', { timeoutMs: 1000, maxBytes: 1024 })
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('rejects an unparseable URL', async () => {
    await expect(
      ssrfSafeGet('::::not a url::::', { timeoutMs: 1000, maxBytes: 1024 })
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });
});

describe('ssrfSafeGet — DNS/IP pinning blocks loopback targets end-to-end', () => {
  let server: Server;
  let port: number;

  beforeAll(async () => {
    server = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ secret: 'should-never-be-reachable' }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('refuses to connect to a 127.0.0.1 target (the SSRF primitive)', async () => {
    // Even though the target is reachable over plain http on loopback, the
    // https-only + IP-guard combination must refuse it. We point at https on
    // the loopback IP: the IP guard fires before any TLS handshake.
    await expect(
      ssrfSafeGet(`https://127.0.0.1:${port}/cimd.json`, {
        timeoutMs: 1500,
        maxBytes: 4096,
      })
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('can be opted into private addresses for local fixtures only', async () => {
    // With allowPrivateAddresses the IP guard is skipped; the request now
    // fails at the TLS layer instead of the SSRF guard (the fixture is plain
    // http), proving the guard — not a network error — is what blocked it
    // above. Either way it is NOT an SsrfBlockedError here.
    await expect(
      ssrfSafeGet(`https://127.0.0.1:${port}/cimd.json`, {
        timeoutMs: 1500,
        maxBytes: 4096,
        allowPrivateAddresses: true,
      })
    ).rejects.not.toBeInstanceOf(SsrfBlockedError);
  });
});
