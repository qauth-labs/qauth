import type { LookupAddress } from 'node:dns';
import { lookup as dnsLookup } from 'node:dns';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';

/**
 * SSRF-safe HTTPS fetcher (CIMD §6 / OWASP API7 / OWASP A?:2025 SSRF).
 *
 * A `client_id` in CIMD is a fully attacker-controlled URL that the
 * authorization server fetches on demand. Without hardening this is a
 * textbook SSRF primitive: an attacker registers
 * `client_id=https://169.254.169.254/latest/meta-data/...` (or a name that
 * resolves to a loopback / RFC 1918 address) and the AS happily proxies the
 * request into the deployment's private network or cloud metadata service.
 *
 * Defenses layered here (defense-in-depth):
 *   1. **Scheme allowlist** — https only. http/file/gopher/data rejected.
 *   2. **No credentials / non-default surprises** — userinfo (`user:pass@`)
 *      in the URL is rejected.
 *   3. **DNS-pinned IP validation that is TOCTOU-safe.** We do NOT resolve
 *      the host, validate, and then let the HTTP client resolve again
 *      (classic DNS-rebinding window). Instead we hand `node:https` a custom
 *      `lookup` callback. The IP that callback returns is the exact IP the
 *      socket connects to, and we validate it inside the callback — so the
 *      address that is checked and the address that is dialed are guaranteed
 *      identical. Every A/AAAA record is checked; if any is non-public the
 *      whole connection is refused.
 *   4. **No redirect following.** A 3xx is surfaced as an error, never
 *      transparently followed — otherwise the upstream could 302 us to
 *      `http://169.254.169.254` and bypass every check above.
 *   5. **Response size + time bounds.** A slow-loris or multi-GB body can't
 *      exhaust the server.
 *
 * The blocklist covers the ranges CIMD §6 and the SSRF literature call out:
 * loopback, link-local (incl. the 169.254.169.254 cloud-metadata address and
 * its IPv6 fd00:ec2 equivalent), private/RFC1918, CGNAT, IPv4-mapped IPv6,
 * unique-local IPv6, and unspecified addresses.
 */

export interface SsrfSafeFetchOptions {
  /** Per-request timeout in milliseconds. */
  timeoutMs: number;
  /** Maximum response body size in bytes. */
  maxBytes: number;
  /**
   * Escape hatch for local dev/integration fixtures only. When true the
   * private/loopback/link-local IP checks are skipped. MUST be false in
   * production — it removes the core SSRF guard.
   */
  allowPrivateAddresses?: boolean;
}

export interface SsrfSafeFetchResult {
  status: number;
  body: string;
  /** Lower-cased header map (single value per header; last wins). */
  headers: Record<string, string>;
}

/**
 * Reason a fetch was refused. `ssrf_blocked` specifically flags a target
 * that resolved to a disallowed address so callers can audit-log it
 * distinctly from a generic network failure.
 */
export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfBlockedError';
    Object.setPrototypeOf(this, SsrfBlockedError.prototype);
  }
}

export class SsrfFetchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfFetchError';
    Object.setPrototypeOf(this, SsrfFetchError.prototype);
  }
}

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
 * literal when it is an IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible
 * (`::a.b.c.d`) address, in EITHER notation:
 *
 *   ::ffff:127.0.0.1  → expandIpv6 → 0:0:0:0:0:ffff:7f00:1
 *   ::ffff:7f00:1     → expandIpv6 → 0:0:0:0:0:ffff:7f00:1   (same form)
 *
 * Both collapse to the same hextet sequence, so working off the expanded form
 * normalises the two notations and closes the hex-form SSRF bypass. Returns
 * the dotted-quad string (e.g. `"127.0.0.1"`) or `null` when the address is
 * not an embedded-v4 form.
 *
 * Only the well-known prefixes `::ffff:0:0/96` (mapped) and `::/96`
 * (compatible) carry an embedded v4 address; any other prefix is a native
 * IPv6 address whose trailing hextets are NOT a v4 address.
 */
function extractEmbeddedIpv4(expanded: string): string | null {
  const parts = expanded.split(':');
  if (parts.length !== 8) return null;

  const prefix = parts.slice(0, 6).join(':');
  const isMapped = prefix === '0:0:0:0:0:ffff';
  const isCompatible = prefix === '0:0:0:0:0:0';
  if (!isMapped && !isCompatible) return null;

  const high = Number.parseInt(parts[6], 16);
  const low = Number.parseInt(parts[7], 16);
  if (!Number.isFinite(high) || !Number.isFinite(low)) return null;
  if (high < 0 || high > 0xffff || low < 0 || low > 0xffff) return null;

  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

function isPublicIpv6(ip: string): boolean {
  const expanded = expandIpv6(ip);

  // Unspecified (::) and loopback (::1).
  if (expanded === '0:0:0:0:0:0:0:0' || expanded === '0:0:0:0:0:0:0:1') return false;

  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) — re-check
  // the embedded v4 address so `::ffff:169.254.169.254` cannot slip through.
  //
  // CRITICAL: this must catch BOTH notations of the embedded address:
  //   - dot-decimal  ::ffff:127.0.0.1
  //   - pure hex     ::ffff:7f00:1   (== 127.0.0.1)
  // Matching only the dot-decimal text form lets the hex form bypass every
  // check below (its `firstHextet` is 0), enabling loopback/RFC1918 SSRF.
  // We therefore work off the fully-expanded 8-hextet form, which normalises
  // both notations identically (expandIpv6 collapses `::ffff:7f00:1` and
  // `::ffff:127.0.0.1` to the same `0:0:0:0:0:ffff:7f00:1`).
  const embeddedIpv4 = extractEmbeddedIpv4(expanded);
  if (embeddedIpv4 !== null) return isPublicIpv4(embeddedIpv4);

  const firstHextet = Number.parseInt(expanded.split(':')[0] || '0', 16);
  // fe80::/10 — link-local. (fe80–febf)
  if (firstHextet >= 0xfe80 && firstHextet <= 0xfebf) return false;
  // fc00::/7 — unique-local (fc00–fdff), incl. AWS fd00:ec2 metadata.
  if (firstHextet >= 0xfc00 && firstHextet <= 0xfdff) return false;
  // ff00::/8 — multicast.
  if (firstHextet >= 0xff00) return false;

  return true;
}

/**
 * Perform an SSRF-guarded HTTPS GET. Resolves with status/headers/body on a
 * completed (non-redirect) response; rejects with {@link SsrfBlockedError}
 * for a disallowed target or {@link SsrfFetchError} for any other failure.
 */
export function ssrfSafeGet(
  targetUrl: string,
  options: SsrfSafeFetchOptions
): Promise<SsrfSafeFetchResult> {
  return new Promise((resolve, reject) => {
    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      reject(new SsrfBlockedError('client_id is not a valid URL'));
      return;
    }

    if (parsed.protocol !== 'https:') {
      reject(new SsrfBlockedError('CIMD client_id must use the https scheme'));
      return;
    }
    if (parsed.username || parsed.password) {
      reject(new SsrfBlockedError('CIMD client_id must not embed credentials'));
      return;
    }

    const allowPrivate = options.allowPrivateAddresses === true;

    // When the URL host is itself an IP literal, node's connector dials it
    // directly and never invokes the `lookup` hook below — so validate it
    // here. (`URL.hostname` wraps IPv6 in brackets; strip them for isIP.)
    const literalHost = parsed.hostname.replace(/^\[|\]$/g, '');
    if (isIP(literalHost) && !allowPrivate && !isPublicUnicastAddress(literalHost)) {
      reject(new SsrfBlockedError(`CIMD host is a non-public address (${literalHost})`));
      return;
    }

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
              new SsrfBlockedError(`CIMD host resolves to a non-public address (${a.address})`),
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
      dnsLookup(hostname, { all: true }, (err, addresses) =>
        handle(err, addresses as LookupAddress[])
      );
    }) as unknown as typeof dnsLookup;

    const req = httpsRequest(
      parsed,
      {
        method: 'GET',
        lookup: guardedLookup,
        headers: {
          accept: 'application/json',
          'user-agent': 'qauth-cimd-resolver',
        },
        // `all: true` is required so our lookup callback receives every record.
        // Node passes lookup options through from here.
      },
      (res) => {
        const status = res.statusCode ?? 0;

        // Never follow redirects — a 3xx Location could point at an internal
        // address and bypass the IP guard.
        if (status >= 300 && status < 400) {
          res.destroy();
          reject(new SsrfBlockedError(`CIMD fetch returned redirect (${status}); not followed`));
          return;
        }

        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (v === undefined) continue;
          headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
        }

        let received = 0;
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => {
          received += chunk.length;
          if (received > options.maxBytes) {
            res.destroy();
            reject(new SsrfFetchError('CIMD document exceeds maximum allowed size'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          resolve({ status, body: Buffer.concat(chunks).toString('utf8'), headers });
        });
        res.on('error', (err) => reject(new SsrfFetchError(err.message)));
      }
    );

    req.setTimeout(options.timeoutMs, () => {
      req.destroy();
      reject(new SsrfFetchError('CIMD fetch timed out'));
    });
    req.on('error', (err) => {
      if (err instanceof SsrfBlockedError) {
        reject(err);
        return;
      }
      reject(new SsrfFetchError(err.message));
    });
    req.end();
  });
}
