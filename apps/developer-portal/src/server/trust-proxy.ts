import { isIP } from 'node:net';

/** An IPv4-mapped address as canonical IPv6 writes it (`::ffff:7f00:1`). */
const IPV4_MAPPED_HEX = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/;

/**
 * One `PORTAL_TRUST_PROXY` entry in the form srvx compares against the peer
 * address, or `undefined` when the entry is not a single IP address.
 *
 * IPv4 stays as is. IPv6 is written in canonical form, the form Node reports a
 * socket's peer in, and an IPv4-mapped address (`::ffff:192.0.2.5` or
 * `::ffff:c000:205`) becomes plain IPv4, because srvx matches a mapped peer
 * against its IPv4 form. A zone id (`fe80::1%eth0`) is not accepted.
 */
function normalizeProxyAddress(entry: string): string | undefined {
  const family = isIP(entry);
  if (family === 4) return entry;
  if (family !== 6) return undefined;
  let canonical: string;
  try {
    canonical = new URL(`http://[${entry}]/`).hostname.slice(1, -1);
  } catch {
    return undefined;
  }
  const mapped = IPV4_MAPPED_HEX.exec(canonical);
  if (!mapped) return canonical;
  const high = parseInt(mapped[1], 16);
  const low = parseInt(mapped[2], 16);
  return [high >> 8, high & 255, low >> 8, low & 255].join('.');
}

/**
 * Parse `PORTAL_TRUST_PROXY` into srvx's `trustProxy` option: the proxies in
 * front of the portal that may report the client address (`X-Forwarded-For`)
 * and the public protocol and host (`X-Forwarded-Proto`, `X-Forwarded-Host`).
 *
 * - unset, empty or `false` (default) → `false`: no proxy is trusted. The
 *   client address is the TCP peer and the request URL is the one received.
 * - a comma-separated list of IP addresses → that list, normalized.
 *
 * The rules follow the auth-server's `TRUST_PROXY` (`parseTrustProxy` in
 * `libs/server/config`): `true` is rejected, because it trusts every hop, and
 * so is a hop count, which cannot tell a proxy from a direct client. Unlike
 * `TRUST_PROXY`, every entry must be a single address: srvx compares the list
 * with the peer address exactly, so a CIDR range or a named range such as
 * `uniquelocal` would never match. List each proxy's address.
 *
 * @throws Error naming the problem; `node-entry.ts` then stops before listening.
 */
export function parsePortalTrustProxy(raw: string | undefined): false | string[] {
  const value = raw?.trim() ?? '';
  if (value === '' || value === 'false') return false;
  if (value === 'true') {
    throw new Error(
      'PORTAL_TRUST_PROXY=true would trust every X-Forwarded-For hop, letting any caller pick its own client address. List the proxy addresses (e.g. 10.0.4.12) instead.'
    );
  }
  if (/^\d+$/.test(value)) {
    throw new Error(
      'PORTAL_TRUST_PROXY takes the proxy addresses (e.g. 10.0.4.12), not a hop count: a count cannot tell a proxy from a direct client.'
    );
  }
  const addresses: string[] = [];
  const invalid: string[] = [];
  for (const entry of value.split(',').map((part) => part.trim())) {
    if (entry.length === 0) continue;
    const address = normalizeProxyAddress(entry);
    if (address === undefined) invalid.push(entry);
    else addresses.push(address);
  }
  if (invalid.length > 0) {
    throw new Error(
      `PORTAL_TRUST_PROXY entries must be single IP addresses (no CIDR ranges or named ranges); invalid: ${invalid.join(', ')}`
    );
  }
  return addresses.length > 0 ? addresses : false;
}
