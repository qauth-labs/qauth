import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { AddressInfo, createServer as createTcpServer, type Socket } from 'node:net';

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { createExplicitCurveCertificate, SLOW_SQUARE_ROOT_PRIME } from '../../testing/x509-der';
import {
  isPublicUnicastAddress,
  SsrfBlockedError,
  SsrfFetchError,
  ssrfSafeGet,
} from './ssrf-safe-fetch';

/** A plain TCP host on 127.0.0.1 that runs `onConnection` for each client. */
async function startTcpHost(onConnection: (socket: Socket) => void): Promise<{
  port: number;
  connections: () => number;
  maxConcurrent: () => number;
  close: () => void;
}> {
  const sockets = new Set<Socket>();
  let total = 0;
  let maxConcurrent = 0;
  const server = createTcpServer((socket) => {
    total += 1;
    sockets.add(socket);
    maxConcurrent = Math.max(maxConcurrent, sockets.size);
    socket.on('error', () => undefined);
    socket.on('close', () => sockets.delete(socket));
    onConnection(socket);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as AddressInfo).port,
    connections: () => total,
    maxConcurrent: () => maxConcurrent,
    close: () => {
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}

/**
 * The server's first TLS 1.2 flight — ServerHello and Certificate — written by
 * hand, so that the Certificate message can carry certificates no TLS server
 * would load. ECDHE-RSA-AES128-GCM-SHA256 is picked from the client's offer;
 * the empty `renegotiation_info` is what OpenSSL 3 insists on before it reads
 * further.
 */
function serverFirstFlight(certificates: readonly Buffer[]): Buffer {
  const uint16 = (n: number) => Buffer.from([n >> 8, n & 0xff]);
  const uint24 = (n: number) => Buffer.from([n >> 16, (n >> 8) & 0xff, n & 0xff]);
  const message = (type: number, body: Buffer) =>
    Buffer.concat([Buffer.from([type]), uint24(body.length), body]);
  const serverHello = message(
    2,
    Buffer.concat([
      Buffer.from([3, 3]),
      randomBytes(32),
      Buffer.from([0]),
      Buffer.from([0xc0, 0x2f]),
      Buffer.from([0]),
      uint16(5),
      Buffer.from([0xff, 0x01, 0x00, 0x01, 0x00]),
    ])
  );
  const list = Buffer.concat(certificates.map((der) => Buffer.concat([uint24(der.length), der])));
  const handshake = Buffer.concat([
    serverHello,
    message(11, Buffer.concat([uint24(list.length), list])),
  ]);
  const records: Buffer[] = [];
  for (let offset = 0; offset < handshake.length; offset += 16_384) {
    const fragment = handshake.subarray(offset, offset + 16_384);
    records.push(Buffer.from([22, 3, 3]), uint16(fragment.length), fragment);
  }
  return Buffer.concat(records);
}

/**
 * A host an anonymous caller can name as a `client_id` (ANT-2026-3OJSXV7G): it
 * answers the ClientHello with certificates nobody signed whose keys sit on a
 * curve that is slow to decode, then says nothing more. OpenSSL decodes every
 * certificate of the message in one synchronous call, whatever the outcome.
 */
async function hostileTlsHost(certificates: number) {
  const flight = serverFirstFlight(
    Array.from({ length: certificates }, () =>
      createExplicitCurveCertificate(SLOW_SQUARE_ROOT_PRIME)
    )
  );
  let flightWritten!: () => void;
  const flightSent = new Promise<void>((resolve) => (flightWritten = resolve));
  const host = await startTcpHost((socket) => {
    let received = Buffer.alloc(0);
    let answered = false;
    socket.on('data', (bytes: Buffer) => {
      if (answered) return;
      received = Buffer.concat([received, bytes]);
      // Wait for the whole ClientHello record, then send the flight once.
      if (received.length < 5 || received.length < 5 + received.readUInt16BE(3)) return;
      answered = true;
      socket.write(flight, () => flightWritten());
    });
  });
  return { ...host, flightSent };
}

/** The longest gap between ticks of a 10 ms interval while `work` runs. */
async function longestEventLoopGap<T>(
  work: () => Promise<T>
): Promise<{ result: T; gapMs: number }> {
  let last = performance.now();
  let gapMs = 0;
  const ticker = setInterval(() => {
    const now = performance.now();
    gapMs = Math.max(gapMs, now - last);
    last = now;
  }, 10);
  try {
    const result = await work();
    return { result, gapMs: Math.max(gapMs, performance.now() - last) };
  } finally {
    clearInterval(ticker);
  }
}

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

  // Regression: the IPv4-mapped check previously only matched the
  // dot-decimal text form (::ffff:127.0.0.1). The pure-hex form of the SAME
  // address (::ffff:7f00:1) bypassed every range check (its first hextet is
  // 0) and was wrongly classified public — a loopback/RFC1918 SSRF bypass.
  // Both notations must now normalise to the same embedded v4 and be blocked.
  it('blocks the HEX form of IPv4-mapped private/loopback addresses (SSRF bypass)', () => {
    expect(isPublicUnicastAddress('::ffff:7f00:1')).toBe(false); // == 127.0.0.1
    expect(isPublicUnicastAddress('::ffff:7f00:0001')).toBe(false); // == 127.0.0.1
    expect(isPublicUnicastAddress('::ffff:a9fe:a9fe')).toBe(false); // == 169.254.169.254 metadata
    expect(isPublicUnicastAddress('::ffff:a00:1')).toBe(false); // == 10.0.0.1
    expect(isPublicUnicastAddress('::ffff:c0a8:101')).toBe(false); // == 192.168.1.1
    expect(isPublicUnicastAddress('::ffff:ac10:5')).toBe(false); // == 172.16.0.5
    // Fully-expanded hex notation of the same mapped loopback address.
    expect(isPublicUnicastAddress('0:0:0:0:0:ffff:7f00:1')).toBe(false);
  });

  // IPv4-compatible (::a.b.c.d) addresses embed a v4 address under an all-zero
  // /96 prefix; the hex form (::7f00:1) must be blocked the same way.
  it('blocks IPv4-compatible addresses embedding private/loopback v4 (hex + dotted)', () => {
    expect(isPublicUnicastAddress('::7f00:1')).toBe(false); // == 127.0.0.1
    expect(isPublicUnicastAddress('::a9fe:a9fe')).toBe(false); // == 169.254.169.254 metadata
    expect(isPublicUnicastAddress('::a00:1')).toBe(false); // == 10.0.0.1
  });

  // Regression (ANT-2026-K1WCPR4R): the IPv6 check was a blocklist ending in
  // `return true`, so every range it did not name was dialed — site-local
  // fec0::/10 and NAT64 among them. Only global unicast (2000::/3) is public.
  it('blocks IPv6 outside global unicast without the range having to be listed', () => {
    expect(isPublicUnicastAddress('fec0::10')).toBe(false); // site-local
    expect(isPublicUnicastAddress('feff::1')).toBe(false); // site-local, top of fec0::/10
    expect(isPublicUnicastAddress('ff02::1')).toBe(false); // multicast
    expect(isPublicUnicastAddress('64:ff9b:1::a00:1')).toBe(false); // local-use NAT64
    expect(isPublicUnicastAddress('::ffff:0:a00:1')).toBe(false); // IPv4-translated
    expect(isPublicUnicastAddress('100::1')).toBe(false); // discard-only
    expect(isPublicUnicastAddress('4000::1')).toBe(false); // unallocated
    // Un-shortened spelling of mapped loopback: no prefix string matches it.
    expect(isPublicUnicastAddress('0000:0000:0000:0000:0000:ffff:7f00:0001')).toBe(false);
  });

  it('blocks the special-purpose blocks inside 2000::/3', () => {
    expect(isPublicUnicastAddress('2001::1')).toBe(false); // Teredo
    expect(isPublicUnicastAddress('2001:2::1')).toBe(false); // benchmarking
    expect(isPublicUnicastAddress('2001:db8::1')).toBe(false); // documentation
    expect(isPublicUnicastAddress('3fff::1')).toBe(false); // documentation
  });

  // A NAT64 gateway or 6to4 relay forwards to the embedded IPv4 address, so
  // that address decides — both ways: DNS64 synthesises 64:ff9b::/96 records
  // for public IPv4-only hosts, which must stay reachable.
  it('judges NAT64 and 6to4 addresses by the IPv4 address they embed', () => {
    expect(isPublicUnicastAddress('64:ff9b::a00:1')).toBe(false); // 10.0.0.1
    expect(isPublicUnicastAddress('64:ff9b::7f00:1')).toBe(false); // 127.0.0.1
    expect(isPublicUnicastAddress('64:ff9b::a9fe:a9fe')).toBe(false); // 169.254.169.254
    expect(isPublicUnicastAddress('2002:7f00:1::')).toBe(false); // 127.0.0.1
    expect(isPublicUnicastAddress('2002:c0a8:101::1')).toBe(false); // 192.168.1.1
    expect(isPublicUnicastAddress('64:ff9b::808:808')).toBe(true); // 8.8.8.8
    expect(isPublicUnicastAddress('2002:808:808::1')).toBe(true); // 8.8.8.8
  });

  // Guard against over-blocking: a genuine public IPv6 must NOT be mistaken
  // for an embedded-v4 form (its /96 prefix is neither ::ffff:0:0 nor ::).
  it('still allows genuine public IPv6 that is not an embedded-v4 form', () => {
    expect(isPublicUnicastAddress('2606:4700:4700::1111')).toBe(true); // Cloudflare
    expect(isPublicUnicastAddress('2001:4860:4860::8888')).toBe(true); // Google DNS
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

  it('refuses a NAT64 or site-local IPv6 literal before any connection', async () => {
    for (const host of ['[64:ff9b::a00:1]', '[fec0::10]', '[2002:a00:1::1]']) {
      await expect(
        ssrfSafeGet(`https://${host}/client.json`, { timeoutMs: 1000, maxBytes: 1024 })
      ).rejects.toBeInstanceOf(SsrfBlockedError);
    }
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

describe('ssrfSafeGet — fetch threads are shared fairly between hosts', () => {
  const hosts: Array<{ close: () => void }> = [];
  afterEach(() => {
    for (const host of hosts.splice(0)) host.close();
  });

  const silentHost = () => startTcpHost(() => undefined);
  const get = (url: string, timeoutMs = 1500) =>
    ssrfSafeGet(url, { timeoutMs, maxBytes: 4096, allowPrivateAddresses: true }).then(
      () => 'resolved',
      (err: unknown) => err
    );

  it('lets one host hold at most two fetches at a time', async () => {
    const host = await silentHost();
    hosts.push(host);

    const results = await Promise.all(
      Array.from({ length: 6 }, () => get(`https://127.0.0.1:${host.port}/client.json`))
    );

    expect(host.maxConcurrent()).toBeLessThanOrEqual(2);
    for (const result of results) {
      expect(result).toBeInstanceOf(SsrfFetchError);
      expect((result as Error).message).toMatch(/timed out/);
    }
  }, 20_000);

  it('still serves another host while one host has used up its share', async () => {
    const busy = await silentHost();
    // A host that answers at once (with something that is not TLS).
    const other = await startTcpHost((socket) => socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'));
    hosts.push(busy, other);

    let busyTimedOut = 0;
    const busyFetches = Array.from({ length: 10 }, () =>
      get(`https://127.0.0.1:${busy.port}/client.json`, 6000).then((result) => {
        if (result instanceof Error && /timed out/.test(result.message)) busyTimedOut += 1;
        return result;
      })
    );
    // `localhost` is a different host name for the same loopback address.
    const result = await get(`https://localhost:${other.port}/client.json`, 6000);

    // Answered by the host (with a TLS error), before the busy host's fetches
    // had run out of time.
    expect(result).toBeInstanceOf(SsrfFetchError);
    expect((result as Error).message).not.toMatch(/timed out|too many/);
    expect(other.connections()).toBe(1);
    expect(busyTimedOut).toBe(0);
    await Promise.all(busyFetches);
  }, 20_000);

  it('refuses at once, rather than queueing without bound, when one host has too many waiting', async () => {
    const host = await silentHost();
    hosts.push(host);

    // Two running and eight waiting is the most one host may have.
    const admitted = Array.from({ length: 10 }, () =>
      get(`https://127.0.0.1:${host.port}/client.json`)
    );
    const started = performance.now();
    const refused = await get(`https://127.0.0.1:${host.port}/client.json`);

    expect(refused).toBeInstanceOf(SsrfFetchError);
    expect((refused as Error).message).toMatch(/too many/);
    expect(performance.now() - started).toBeLessThan(500);
    await Promise.all(admitted);
  }, 20_000);
});

// Regression (ANT-2026-3OJSXV7G): the fetch used to run on the thread that
// serves every request. OpenSSL reads a Certificate message in one synchronous
// call, so a host presenting a chain of slow-to-decode certificates held the
// whole server — no route, no timer and not the fetch's own timeout could run
// until OpenSSL returned. (Last in the file: the fetch thread stays busy, and
// keeps its slot, until OpenSSL is done with the certificates.)
describe('ssrfSafeGet — a hostile TLS handshake cannot stall the server', () => {
  const hosts: Array<{ close: () => void }> = [];
  afterEach(() => {
    for (const host of hosts.splice(0)) host.close();
  });

  it('keeps timers firing on time while the certificates are decoded, and still ends the fetch', async () => {
    const host = await hostileTlsHost(3);
    hosts.push(host);
    const timeoutMs = 5000;

    const started = performance.now();
    const fetching = ssrfSafeGet(`https://127.0.0.1:${host.port}/client.json`, {
      timeoutMs,
      maxBytes: 4096,
      allowPrivateAddresses: true,
    }).then(
      () => 'resolved',
      (err: unknown) => err
    );

    // The certificates are on their way: from here on the fetch is busy
    // decoding them, for seconds.
    await host.flightSent;
    const timerDue = performance.now() + 100;
    const timerLateness = new Promise<number>((resolve) =>
      setTimeout(() => resolve(performance.now() - timerDue), 100)
    );
    const { result, gapMs } = await longestEventLoopGap(() => fetching);

    expect(await timerLateness).toBeLessThan(500);
    expect(gapMs).toBeLessThan(500);
    expect(result).toBeInstanceOf(SsrfFetchError);
    expect(performance.now() - started).toBeLessThan(timeoutMs + 500);
  }, 30_000);
});
