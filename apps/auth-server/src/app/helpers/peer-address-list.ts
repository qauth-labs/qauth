import { BlockList, isIP } from 'node:net';

import { normalizeIP } from '@fastify/rate-limit';

/**
 * A list of peer addresses the operator set, such as `CEREMONY_APP_PEERS`
 * (#982), matched against a request's address.
 */
export interface PeerAddressList {
  /**
   * Whether `address` is listed. An IPv4 client, written as IPv4 or as
   * IPv4-mapped IPv6 (`::ffff:192.0.2.1`), is matched against the IPv4
   * entries only, and any other IPv6 client against the IPv6 entries only. A
   * zone id is dropped. No address, or a value that is not an IP address, is
   * never listed.
   */
  has(address: string | undefined): boolean;
}

/** The IPv4-mapped IPv6 prefix ::ffff:0:0/96: an address in it is one IPv4 client. */
const IPV4_MAPPED = new BlockList();
IPV4_MAPPED.addSubnet('::ffff:0:0', 96, 'ipv6');

/** An address without its zone id (`fe80::1%eth0` → `fe80::1`). */
function withoutZone(address: string): string {
  return address.split('%')[0];
}

/** The IPv4 client an address stands for: itself, or the one an IPv4-mapped IPv6 address embeds. */
function ipv4Of(address: string, family: number): string | undefined {
  if (family === 4) return address;
  return IPV4_MAPPED.check(address, 'ipv6') ? normalizeIP(address, 128) : undefined;
}

/**
 * Build a {@link PeerAddressList} from IP addresses and CIDR ranges, as the
 * configuration schema accepts them (`parseCeremonyAppPeers`).
 *
 * The two families are kept apart. Node's `BlockList` matches an IPv6 range
 * that covers ::ffff:0:0/96, such as `::/64`, against every IPv4 client, so
 * an IPv6 entry would list IPv4 callers the operator never named. Here an
 * IPv4-mapped entry (`::ffff:10.0.4.12`, or a range of /96 or longer inside
 * the mapped prefix) is an IPv4 entry, and every other IPv6 entry matches
 * IPv6 clients only.
 *
 * @throws {Error} on an entry that is not an address or a range, or carries a
 *   zone id, which the schema refuses first
 */
export function createPeerAddressList(entries: readonly string[]): PeerAddressList {
  const ipv4 = new BlockList();
  const ipv6 = new BlockList();
  for (const entry of entries) {
    const [address, prefix] = entry.split('/');
    const family = isIP(address);
    if (family === 0 || address.includes('%')) {
      throw new Error(`not an IP address or CIDR range: ${entry}`);
    }
    const bits = prefix === undefined ? (family === 4 ? 32 : 128) : Number(prefix);
    const mapped = ipv4Of(address, family);
    if (mapped !== undefined && (family === 4 || bits >= 96)) {
      ipv4.addSubnet(mapped, family === 4 ? bits : bits - 96, 'ipv4');
    } else {
      ipv6.addSubnet(address, bits, 'ipv6');
    }
  }
  const empty = entries.length === 0;
  return {
    has(address) {
      if (empty || !address) return false;
      const bare = withoutZone(address);
      const family = isIP(bare);
      if (family === 0) return false;
      const client = ipv4Of(bare, family);
      return client === undefined ? ipv6.check(bare, 'ipv6') : ipv4.check(client, 'ipv4');
    },
  };
}
