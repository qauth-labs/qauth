import type { LookupAddress } from 'node:dns';
import { lookup as dnsLookup } from 'node:dns';
import { Resolver } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { platform, setPriority } from 'node:os';
import { DEFAULT_CIPHERS } from 'node:tls';
import { isMainThread, parentPort, workerData } from 'node:worker_threads';

/**
 * The network half of `ssrfSafeGet()` (`ssrf-safe-fetch.ts`): name resolution,
 * the TLS handshake, the HTTP exchange and the body byte cap — plus the address
 * checks that decide which peers may be dialled at all.
 *
 * It runs on a worker thread of its own, one per fetch, and never on the thread
 * that serves requests (ANT-2026-3OJSXV7G). The peer of this code is a host an
 * unauthenticated caller names (a CIMD `client_id`, a `jwks_uri`), and OpenSSL
 * processes each handshake message synchronously: a Certificate message of
 * certificates whose EC keys use an explicit curve costs seconds of CPU, and no
 * timer of the thread — not even the fetch's own timeout — runs until OpenSSL
 * returns. On a worker thread only the fetch waits; `ssrf-safe-fetch.ts` keeps
 * the deadline on the main thread and stops the worker.
 *
 * ## Loaded by Node itself
 *
 * This file is the worker's entry point, so the worker loads it without the
 * app's toolchain: from the TypeScript sources (tsx, vitest) through Node's
 * built-in type stripping, from the esbuild output as plain JavaScript. It
 * therefore imports `node:` builtins only, imports types with `import type`,
 * and uses erasable TypeScript syntax only (no enums, namespaces or parameter
 * properties). The main thread imports it too, for the address checks; the
 * worker code at the bottom runs only in a thread started for a fetch.
 */

/** What the main thread asks a fetch worker to do. */
export interface GuardedGetJob {
  /** Absolute https URL to GET. */
  url: string;
  /** Time bound in milliseconds, see `SsrfSafeFetchOptions.timeoutMs`. */
  timeoutMs: number;
  /** Maximum response body size in bytes. */
  maxBytes: number;
  /** Skip the non-public address checks (local fixtures only). */
  allowPrivateAddresses: boolean;
}

/**
 * What a fetch worker reports back — the only data that crosses from the
 * thread that talked to the host. `blocked` marks a target the address checks
 * refused, `failed` any other failure.
 */
export type GuardedGetOutcome =
  | { kind: 'response'; status: number; body: string; headers: Record<string, string> }
  | { kind: 'blocked'; message: string }
  | { kind: 'failed'; message: string };

/**
 * Response headers handed back to the caller: what the callers read to decide
 * how long to cache a document. Everything else the host sent stays in the
 * worker.
 */
const RETURNED_HEADERS: readonly string[] = ['cache-control', 'expires', 'content-type'];

/**
 * Cipher list for the fetch. Finite-field DHE is left out: a host can name a
 * 10 000-bit group in its ServerKeyExchange and make the client compute in it
 * (about a second of CPU per handshake). ECDHE and TLS 1.3 are unaffected.
 */
const FETCH_CIPHERS = `${DEFAULT_CIPHERS}:!kDHE`;

/**
 * 1xx interim responses tolerated ahead of the final response — room for a
 * `103 Early Hints` or two, not for a stream of them.
 */
const MAX_INTERIM_RESPONSES = 3;

/**
 * Per-query bounds of the c-ares resolver: how long one query waits for an
 * answer, and how often it is sent. The fetch deadline cancels whatever is
 * left of them.
 */
const DNS_QUERY_TIMEOUT_MS = 2000;
const DNS_QUERY_TRIES = 2;

/** `workerData` tag that marks a thread started for a fetch. */
export const GUARDED_GET_WORKER_TAG = 'qauth:ssrf-guarded-get';

/**
 * Normalise an IPv6 address to a comparable lower-case form by expanding
 * `::`. We only need enough fidelity to range-check, so a light expansion
 * is sufficient.
 */
function expandIpv6(addr: string): string {
  let a = addr.toLowerCase();
  // Strip zone id (e.g. fe80::1%eth0).
  const pct = a.indexOf('%');
  if (pct !== -1) a = a.slice(0, pct);
  if (!a.includes('::')) return a;
  const [head, tail] = a.split('::');
  const headParts = head ? head.split(':') : [];
  const tailParts = tail ? tail.split(':') : [];
  const missing = 8 - headParts.length - tailParts.length;
  const middle = Array.from({ length: Math.max(missing, 0) }, () => '0');
  return [...headParts, ...middle, ...tailParts].map((p) => p || '0').join(':');
}

/**
 * True when `ip` (an already-resolved literal, family 4 or 6) is a public,
 * routable unicast address safe to connect to. Returns false for loopback,
 * private, link-local, CGNAT, multicast, reserved, and cloud-metadata
 * ranges.
 */
export function isPublicUnicastAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPublicIpv4(ip);
  if (family === 6) return isPublicIpv6(ip);
  return false;
}

function isPublicIpv4(ip: string): boolean {
  const octets = ip.split('.').map((o) => Number.parseInt(o, 10));
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) {
    return false;
  }
  const [a, b] = octets;

  // 0.0.0.0/8 — "this network" / unspecified.
  if (a === 0) return false;
  // 10.0.0.0/8 — private.
  if (a === 10) return false;
  // 127.0.0.0/8 — loopback.
  if (a === 127) return false;
  // 169.254.0.0/16 — link-local (incl. 169.254.169.254 cloud metadata).
  if (a === 169 && b === 254) return false;
  // 172.16.0.0/12 — private.
  if (a === 172 && b >= 16 && b <= 31) return false;
  // 192.168.0.0/16 — private.
  if (a === 192 && b === 168) return false;
  // 100.64.0.0/10 — CGNAT (RFC 6598).
  if (a === 100 && b >= 64 && b <= 127) return false;
  // 192.0.0.0/24 — IETF protocol assignments.
  if (a === 192 && b === 0 && octets[2] === 0) return false;
  // 198.18.0.0/15 — benchmarking.
  if (a === 198 && (b === 18 || b === 19)) return false;
  // 224.0.0.0/4 — multicast; 240.0.0.0/4 — reserved / broadcast.
  if (a >= 224) return false;

  return true;
}

/**
 * Extract the embedded IPv4 address from a fully-expanded (8-hextet) IPv6
 * literal when it is an IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible
 * (`::a.b.c.d`), NAT64 (`64:ff9b::a.b.c.d`, RFC 6052) or 6to4
 * (`2002:aabb:ccdd::`, RFC 3056) address, in EITHER notation:
 *
 *   ::ffff:127.0.0.1  → expandIpv6 → 0:0:0:0:0:ffff:7f00:1
 *   ::ffff:7f00:1     → expandIpv6 → 0:0:0:0:0:ffff:7f00:1   (same form)
 *
 * Both collapse to the same hextet sequence, so working off the expanded form
 * normalises the two notations and closes the hex-form SSRF bypass. Returns
 * the dotted-quad string (e.g. `"127.0.0.1"`) or `null` when the address is
 * not an embedded-v4 form.
 *
 * Only the well-known prefixes `::ffff:0:0/96` (mapped), `::/96`
 * (compatible), `64:ff9b::/96` (NAT64) and `2002::/16` (6to4) carry an
 * embedded v4 address; any other prefix is a native IPv6 address whose
 * hextets are NOT a v4 address. A NAT64 gateway or a 6to4 relay forwards to
 * the embedded address, so `64:ff9b::a00:1` IS 10.0.0.1 as far as SSRF goes —
 * and a DNS64-synthesised `64:ff9b::` record of a public IPv4-only host stays
 * reachable.
 */
function extractEmbeddedIpv4(expanded: string): string | null {
  const parts = expanded.split(':');
  if (parts.length !== 8) return null;

  const prefix = parts.slice(0, 6).join(':');
  const isMapped = prefix === '0:0:0:0:0:ffff';
  const isCompatible = prefix === '0:0:0:0:0:0';
  const isNat64 = prefix === '64:ff9b:0:0:0:0';
  const is6to4 = parts[0] === '2002';
  if (!isMapped && !isCompatible && !isNat64 && !is6to4) return null;

  // 6to4 carries the v4 address right after its /16; the others in the last
  // 32 bits.
  const offset = is6to4 ? 1 : 6;
  const high = Number.parseInt(parts[offset], 16);
  const low = Number.parseInt(parts[offset + 1], 16);
  if (!Number.isFinite(high) || !Number.isFinite(low)) return null;
  if (high < 0 || high > 0xffff || low < 0 || low > 0xffff) return null;

  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

function isPublicIpv6(ip: string): boolean {
  const expanded = expandIpv6(ip);

  // Unspecified (::) and loopback (::1).
  if (expanded === '0:0:0:0:0:0:0:0' || expanded === '0:0:0:0:0:0:0:1') return false;

  // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d), NAT64 and 6to4
  // — re-check the embedded v4 address so `::ffff:169.254.169.254` (or
  // `64:ff9b::a9fe:a9fe`, which a NAT64 gateway forwards there) cannot slip
  // through.
  //
  // CRITICAL: this must catch BOTH notations of the embedded address:
  //   - dot-decimal  ::ffff:127.0.0.1
  //   - pure hex     ::ffff:7f00:1   (== 127.0.0.1)
  // Matching only the dot-decimal text form lets the hex form bypass every
  // IPv4 range check, enabling loopback/RFC1918 SSRF.
  // We therefore work off the fully-expanded 8-hextet form, which normalises
  // both notations identically (expandIpv6 collapses `::ffff:7f00:1` and
  // `::ffff:127.0.0.1` to the same `0:0:0:0:0:ffff:7f00:1`).
  const embeddedIpv4 = extractEmbeddedIpv4(expanded);
  if (embeddedIpv4 !== null) return isPublicIpv4(embeddedIpv4);

  const hextets = expanded
    .split(':')
    .map((h) => (/^[0-9a-f]{1,4}$/.test(h) ? parseInt(h, 16) : NaN));
  if (hextets.length !== 8 || hextets.some((h) => Number.isNaN(h))) return false;
  const [first, second] = hextets;

  // An ALLOWLIST, not a blocklist (ANT-2026-K1WCPR4R): 2000::/3 is the only
  // block IANA has allocated for global unicast, so everything outside it is
  // refused without having to be named — link-local fe80::/10, site-local
  // fec0::/10, unique-local fc00::/7 (incl. cloud instance-metadata addresses
  // such as fd00:ec2::254), multicast
  // ff00::/8, local-use NAT64 64:ff9b:1::/48, discard-only 100::/64 and
  // whatever is still reserved.
  if (first < 0x2000 || first > 0x3fff) return false;
  // 2001::/23 — IETF protocol assignments (Teredo, benchmarking, ORCHID).
  if (first === 0x2001 && second < 0x0200) return false;
  // 2001:db8::/32 and 3fff::/20 — documentation.
  if (first === 0x2001 && second === 0x0db8) return false;
  if (first === 0x3fff && second < 0x1000) return false;

  return true;
}

/**
 * The checks that need no network: a parseable https URL without userinfo,
 * whose host — when it is an IP literal — is public. Run on the main thread
 * before a worker is started (a URL that can be refused costs no thread) and
 * again in the worker, which trusts nothing it is handed.
 *
 * `host` is the URL's host name, lower-cased and without a trailing dot: the
 * key under which fetches are counted per host.
 */
export function checkFetchTarget(
  targetUrl: string,
  allowPrivateAddresses: boolean
): { kind: 'ok'; url: URL; host: string } | { kind: 'blocked'; message: string } {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { kind: 'blocked', message: 'client_id is not a valid URL' };
  }

  if (parsed.protocol !== 'https:') {
    return { kind: 'blocked', message: 'CIMD client_id must use the https scheme' };
  }
  if (parsed.username || parsed.password) {
    return { kind: 'blocked', message: 'CIMD client_id must not embed credentials' };
  }

  // When the URL host is itself an IP literal, node's connector dials it
  // directly and never invokes the `lookup` hook — so validate it here.
  // (`URL.hostname` wraps IPv6 in brackets; strip them for isIP.)
  const literalHost = parsed.hostname.replace(/^\[|\]$/g, '');
  if (isIP(literalHost) && !allowPrivateAddresses && !isPublicUnicastAddress(literalHost)) {
    return { kind: 'blocked', message: `CIMD host is a non-public address (${literalHost})` };
  }

  return { kind: 'ok', url: parsed, host: parsed.hostname.toLowerCase().replace(/\.$/, '') };
}

/**
 * Every A and AAAA record of `hostname`. One family failing (a v4-only host has
 * no AAAA) is not an error as long as the other one answered.
 */
async function resolveAllAddresses(resolver: Resolver, hostname: string): Promise<LookupAddress[]> {
  const [a, aaaa] = await Promise.allSettled([
    resolver.resolve4(hostname),
    resolver.resolve6(hostname),
  ]);
  const addresses: LookupAddress[] = [];
  if (a.status === 'fulfilled') {
    addresses.push(...a.value.map((address) => ({ address, family: 4 })));
  }
  if (aaaa.status === 'fulfilled') {
    addresses.push(...aaaa.value.map((address) => ({ address, family: 6 })));
  }
  if (addresses.length === 0 && a.status === 'rejected') throw a.reason;
  return addresses;
}

/** A target refused by the address checks inside the `lookup` hook. */
class BlockedTargetError extends Error {}

/**
 * Perform the guarded HTTPS GET. Never rejects: every failure is an outcome,
 * because the result has to cross a thread boundary as plain data.
 */
export function guardedGet(job: GuardedGetJob): Promise<GuardedGetOutcome> {
  return new Promise((resolve) => {
    const target = checkFetchTarget(job.url, job.allowPrivateAddresses);
    if (target.kind === 'blocked') {
      resolve(target);
      return;
    }
    const allowPrivate = job.allowPrivateAddresses;

    let settled = false;
    let resolver: Resolver | undefined;
    const settle = (outcome: GuardedGetOutcome): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      // A query still in flight has no reader left.
      resolver?.cancel();
      resolve(outcome);
    };

    // Custom lookup: validate the resolved IP *and* hand the same IP to the
    // socket. This is the TOCTOU-safe boundary — node never re-resolves.
    //
    // We always resolve every A/AAAA record ourselves and validate the whole
    // set, then answer in the shape node's caller requested (`opts.all`
    // toggles single-address vs array). The address(es) node ultimately
    // dials are exactly the ones we validated, so there is no rebinding gap.
    const guardedLookup = ((
      hostname: string,
      opts: { all?: boolean } | undefined,
      cb: (
        err: NodeJS.ErrnoException | null,
        address: string | LookupAddress[],
        family?: number
      ) => void
    ) => {
      const wantsAll = typeof opts === 'object' && opts?.all === true;

      const handle = (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => {
        if (err) {
          cb(err, '', 0);
          return;
        }
        if (!addresses || addresses.length === 0) {
          cb(new Error('no addresses resolved'), '', 0);
          return;
        }
        for (const a of addresses) {
          if (!allowPrivate && !isPublicUnicastAddress(a.address)) {
            cb(
              new BlockedTargetError(`CIMD host resolves to a non-public address (${a.address})`),
              '',
              0
            );
            return;
          }
        }
        if (wantsAll) {
          cb(null, addresses);
        } else {
          cb(null, addresses[0].address, addresses[0].family);
        }
      };

      // IP literal: validate directly, no DNS round-trip.
      const literalFamily = isIP(hostname);
      if (literalFamily) {
        handle(null, [{ address: hostname, family: literalFamily }]);
        return;
      }
      // Local fixtures may be named in /etc/hosts, which only getaddrinfo(3)
      // reads. The escape hatch that allows them is off in production.
      if (allowPrivate) {
        dnsLookup(hostname, { all: true }, (err, addresses) =>
          handle(err, addresses as LookupAddress[])
        );
        return;
      }
      // A name the caller chose never reaches dns.lookup(): that is a blocking
      // getaddrinfo(3) on the libuv thread pool, which the whole process
      // shares and runs only a few of at a time, and nothing can cancel it. A
      // name server that never answers would hold those threads past every
      // deadline and queue all other lookups behind it (ANT-2026-MY1V8XOQ).
      // c-ares queries run on this thread's event loop, each with its own
      // timeout, and `settle` cancels them.
      resolver = new Resolver({
        timeout: Math.min(DNS_QUERY_TIMEOUT_MS, job.timeoutMs),
        tries: DNS_QUERY_TRIES,
      });
      resolveAllAddresses(resolver, hostname).then(
        (addresses) => handle(null, addresses),
        (err: NodeJS.ErrnoException) => handle(err, [])
      );
    }) as unknown as typeof dnsLookup;

    // A deadline for the whole fetch, from name resolution to the last body
    // byte — not `req.setTimeout()`, which is a socket IDLE timer: every byte
    // from the host restarts it, so a host dripping a byte or a 1xx response
    // at a time would never trip it (ANT-2026-UE3G2DW3).
    const deadline = setTimeout(() => {
      req.destroy();
      settle({ kind: 'failed', message: 'CIMD fetch timed out' });
    }, job.timeoutMs);

    const req = httpsRequest(
      target.url,
      {
        method: 'GET',
        // One connection per fetch, closed with it: nothing pooled for a
        // later fetch, and the request's 'close' marks the end of this one.
        agent: false,
        lookup: guardedLookup,
        ciphers: FETCH_CIPHERS,
        headers: {
          accept: 'application/json',
          'user-agent': 'qauth-cimd-resolver',
        },
      },
      (res) => {
        const status = res.statusCode ?? 0;

        // Never follow redirects — a 3xx Location could point at an internal
        // address and bypass the IP guard.
        if (status >= 300 && status < 400) {
          res.destroy();
          settle({
            kind: 'blocked',
            message: `CIMD fetch returned redirect (${status}); not followed`,
          });
          return;
        }

        const headers: Record<string, string> = {};
        for (const name of RETURNED_HEADERS) {
          const value = res.headers[name];
          if (value === undefined) continue;
          headers[name] = Array.isArray(value) ? value.join(', ') : value;
        }

        let received = 0;
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => {
          received += chunk.length;
          if (received > job.maxBytes) {
            res.destroy();
            settle({ kind: 'failed', message: 'CIMD document exceeds maximum allowed size' });
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          settle({
            kind: 'response',
            status,
            body: Buffer.concat(chunks).toString('utf8'),
            headers,
          });
        });
        res.on('error', (err) => settle({ kind: 'failed', message: err.message }));
      }
    );

    // 1xx responses never reach the response callback, so the byte cap does
    // not see them; a host could stream them until the deadline.
    let interimResponses = 0;
    req.on('information', () => {
      interimResponses += 1;
      if (interimResponses > MAX_INTERIM_RESPONSES) {
        req.destroy();
        settle({ kind: 'failed', message: 'CIMD fetch received too many interim responses' });
      }
    });
    req.on('error', (err) => {
      settle({
        kind: err instanceof BlockedTargetError ? 'blocked' : 'failed',
        message: err.message,
      });
    });
    // Whatever else happened, the fetch is over once the request has closed.
    // Without this an unsolicited `101`, which Node answers by dropping the
    // socket and reports with nothing but 'close', left the fetch pending.
    req.on('close', () => {
      settle({ kind: 'failed', message: 'CIMD fetch closed without a response' });
    });
    req.end();
  });
}

/** True when `data` is the `workerData` of a thread started for a fetch. */
function isFetchWorkerData(data: unknown): data is { tag: string; job: GuardedGetJob } {
  if (typeof data !== 'object' || data === null) return false;
  const { tag, job } = data as { tag?: unknown; job?: unknown };
  return tag === GUARDED_GET_WORKER_TAG && typeof job === 'object' && job !== null;
}

// The worker itself: fetch once, report, and let the main thread end the
// thread.
if (!isMainThread && parentPort !== null && isFetchWorkerData(workerData)) {
  const port = parentPort;
  // Linux keeps a nice value per thread, so this lowers only this worker:
  // were a host to keep it busy inside OpenSSL past its deadline, the thread
  // that serves requests still gets the CPU first. Elsewhere it would renice
  // the whole server, so it is not done there.
  if (platform() === 'linux') {
    try {
      setPriority(19);
    } catch {
      // Not permitted: the worker still runs, at the default priority.
    }
  }
  void guardedGet(workerData.job).then((outcome) => port.postMessage(outcome));
}
