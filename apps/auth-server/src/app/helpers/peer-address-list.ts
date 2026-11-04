import { BlockList, isIP } from 'node:net';

/**
 * A list of peer addresses the operator set, such as `CEREMONY_APP_PEERS`
 * (#982), matched against a request's address.
 */
export interface PeerAddressList {
  /**
   * Whether `address` is listed. An IPv4-mapped IPv6 address
   * (`::ffff:192.0.2.1`) matches its IPv4 entry, and a zone id is dropped.
   * No address, or a value that is not an IP address, is never listed.
   */
  has(address: string | undefined): boolean;
}

/** An address without its zone id (`fe80::1%eth0` → `fe80::1`). */
function withoutZone(address: string): string {
  return address.split('%')[0];
}

/**
 * Build a {@link PeerAddressList} from IP addresses and CIDR ranges, as the
 * configuration schema accepts them (`parseCeremonyAppPeers`).
 *
 * @throws {Error} on an entry that is neither, which the schema refuses first
 */
export function createPeerAddressList(entries: readonly string[]): PeerAddressList {
  const list = new BlockList();
  for (const entry of entries) {
    const [rawAddress, prefix] = entry.split('/');
    const address = withoutZone(rawAddress);
    const family = isIP(address);
    if (family === 0) throw new Error(`not an IP address or CIDR range: ${entry}`);
    const type = family === 6 ? 'ipv6' : 'ipv4';
    if (prefix === undefined) list.addAddress(address, type);
    else list.addSubnet(address, Number(prefix), type);
  }
  const empty = entries.length === 0;
  return {
    has(address) {
      if (empty || !address) return false;
      const bare = withoutZone(address);
      const family = isIP(bare);
      if (family === 0) return false;
      return list.check(bare, family === 6 ? 'ipv6' : 'ipv4');
    },
  };
}
