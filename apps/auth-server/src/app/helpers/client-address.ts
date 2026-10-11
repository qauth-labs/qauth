import { BlockList, isIPv6 } from 'node:net';

import { normalizeIP } from '@fastify/rate-limit';

/**
 * Prefix length that groups IPv6 clients into one rate-limit / lockout key.
 * A /64 is the smallest allocation a single subscriber or host normally gets.
 */
export const CLIENT_IPV6_PREFIX_LENGTH = 64;

/**
 * The RFC 6052 well-known prefix 64:ff9b::/96. An address inside it embeds one
 * IPv4 client, so it is keyed per address rather than per /64.
 */
const TRANSLATED_IPV4 = new BlockList();
TRANSLATED_IPV4.addSubnet('64:ff9b::', 96, 'ipv6');

/** Key used when a request carries no client address at all. */
export const UNKNOWN_CLIENT_ADDRESS = 'unknown';

/** The parts of a Fastify request the key is derived from. */
export interface ClientAddressSource {
  readonly ip?: string;
  readonly socket?: { readonly remoteAddress?: string };
}

/**
 * The client key every per-IP rate limit and the `ip:` failed-login lockout
 * identifier use.
 *
 * Rate-limit and lockout keys use the client's /64 for IPv6 so one allocation
 * shares one bucket. An IPv4 address is used as is, an IPv4-mapped IPv6
 * address (`::ffff:192.0.2.1`) keys as its IPv4 form, zone ids are dropped,
 * and every textual form of one IPv6 address yields the same key. An address
 * in the well-known translation prefix 64:ff9b::/96 stands for one IPv4
 * client and is keyed per address.
 *
 * The address comes from `request.ip` (which honours TRUST_PROXY), falling
 * back to the socket peer. This is a bucket key only: audit events and
 * session / device records keep the exact `request.ip`.
 *
 * Typed structurally so it can be passed straight to `keyGenerator`.
 */
export function clientAddressKey(request: ClientAddressSource): string {
  const address = request.ip || request.socket?.remoteAddress;
  if (!address) return UNKNOWN_CLIENT_ADDRESS;
  try {
    const bare = address.split('%')[0];
    const prefixLength =
      isIPv6(bare) && TRANSLATED_IPV4.check(bare, 'ipv6') ? 128 : CLIENT_IPV6_PREFIX_LENGTH;
    return normalizeIP(address, prefixLength);
  } catch {
    // Unparseable input keys as itself rather than failing the request.
    return address.toLowerCase();
  }
}
