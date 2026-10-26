import { isIP } from 'node:net';

/**
 * Which kind of address an IP literal is, as far as the egress client cares.
 * Only `public` is dialled. Every other kind names why an address is refused,
 * so a log line can say more than "blocked".
 *
 * - `unspecified`: `0.0.0.0/8`, `::`.
 * - `loopback`: `127.0.0.0/8`, `::1`.
 * - `private`: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918).
 * - `shared`: `100.64.0.0/10`, the shared address space of carrier-grade NAT
 *   (RFC 6598).
 * - `link-local`: `169.254.0.0/16`, which holds the cloud metadata address
 *   `169.254.169.254`, and `fe80::/10`.
 * - `unique-local`: `fc00::/7`, which holds cloud metadata addresses such as
 *   `fd00:ec2::254`.
 * - `multicast`: `224.0.0.0/4`, `ff00::/8`.
 * - `documentation`: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
 *   (RFC 5737), `2001:db8::/32` (RFC 3849) and `3fff::/20` (RFC 9637).
 * - `reserved`: every other special-purpose block of the IANA registries
 *   (RFC 6890): `192.0.0.0/24`, `192.88.99.0/24`, `198.18.0.0/15`,
 *   `240.0.0.0/4` with the broadcast address, `2001::/23`, and all of IPv6
 *   outside `2000::/3`.
 * - `invalid`: not an IP literal, or an IPv6 literal with a zone id.
 */
export type AddressKind =
  | 'public'
  | 'unspecified'
  | 'loopback'
  | 'private'
  | 'shared'
  | 'link-local'
  | 'unique-local'
  | 'multicast'
  | 'documentation'
  | 'reserved'
  | 'invalid';

/** A CIDR block of the tables below, as bytes. */
interface AddressRange {
  readonly prefix: readonly number[];
  readonly bits: number;
  readonly kind: Exclude<AddressKind, 'public' | 'invalid'>;
}

/** IPv4 blocks that are never dialled (RFC 6890 and the IANA IPv4 registries). */
const IPV4_BLOCKED: readonly AddressRange[] = [
  { prefix: [0, 0, 0, 0], bits: 8, kind: 'unspecified' },
  { prefix: [10, 0, 0, 0], bits: 8, kind: 'private' },
  { prefix: [100, 64, 0, 0], bits: 10, kind: 'shared' },
  { prefix: [127, 0, 0, 0], bits: 8, kind: 'loopback' },
  { prefix: [169, 254, 0, 0], bits: 16, kind: 'link-local' },
  { prefix: [172, 16, 0, 0], bits: 12, kind: 'private' },
  // IETF protocol assignments.
  { prefix: [192, 0, 0, 0], bits: 24, kind: 'reserved' },
  { prefix: [192, 0, 2, 0], bits: 24, kind: 'documentation' },
  // The deprecated 6to4 relay anycast block (RFC 7526).
  { prefix: [192, 88, 99, 0], bits: 24, kind: 'reserved' },
  { prefix: [192, 168, 0, 0], bits: 16, kind: 'private' },
  // Benchmarking (RFC 2544).
  { prefix: [198, 18, 0, 0], bits: 15, kind: 'reserved' },
  { prefix: [198, 51, 100, 0], bits: 24, kind: 'documentation' },
  { prefix: [203, 0, 113, 0], bits: 24, kind: 'documentation' },
  { prefix: [224, 0, 0, 0], bits: 4, kind: 'multicast' },
  // Reserved for future use, and the limited broadcast address.
  { prefix: [240, 0, 0, 0], bits: 4, kind: 'reserved' },
];

/**
 * IPv6 blocks named for the log. The check itself is an allowlist: an address
 * outside `2000::/3`, the only block IANA allocates for global unicast, is
 * `reserved` even when no entry here names it.
 */
const IPV6_BLOCKED: readonly AddressRange[] = [
  { prefix: [0xfe, 0x80], bits: 10, kind: 'link-local' },
  { prefix: [0xfc], bits: 7, kind: 'unique-local' },
  { prefix: [0xff], bits: 8, kind: 'multicast' },
  { prefix: [0x20, 0x01, 0x0d, 0xb8], bits: 32, kind: 'documentation' },
  { prefix: [0x3f, 0xff], bits: 20, kind: 'documentation' },
  // IETF protocol assignments: Teredo, benchmarking, ORCHID and others.
  { prefix: [0x20, 0x01], bits: 23, kind: 'reserved' },
];

/** `::ffff:0:0/96`, IPv4-mapped. */
const IPV4_MAPPED_PREFIX = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
/** `64:ff9b::/96`, the NAT64 well-known prefix (RFC 6052). */
const NAT64_PREFIX = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
/** `2002::/16`, 6to4 (RFC 3056). */
const SIX_TO_FOUR_PREFIX = [0x20, 0x02];

/** True when the first `bits` bits of `bytes` equal those of `prefix`. */
export function inRange(
  bytes: readonly number[],
  prefix: readonly number[],
  bits: number
): boolean {
  const whole = Math.floor(bits / 8);
  for (let i = 0; i < whole; i += 1) {
    if (bytes[i] !== prefix[i]) return false;
  }
  const rest = bits % 8;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return ((bytes[whole] ?? 0) & mask) === ((prefix[whole] ?? 0) & mask);
}

function startsWith(bytes: readonly number[], prefix: readonly number[]): boolean {
  return inRange(bytes, prefix, prefix.length * 8);
}

/** The four bytes of a dotted-quad IPv4 literal, or `null`. */
export function parseIpv4(text: string): number[] | null {
  if (isIP(text) !== 4) return null;
  return text.split('.').map((octet) => Number.parseInt(octet, 10));
}

/**
 * The sixteen bytes of an IPv6 literal, in any of its text forms: `::`
 * compression and a dotted-quad tail (`::ffff:127.0.0.1`) included. `null` for
 * anything else, and for a literal with a zone id (`fe80::1%eth0`): a zone is
 * only meaningful on a local link.
 */
export function parseIpv6(text: string): number[] | null {
  if (text.includes('%') || isIP(text) !== 6) return null;

  let body = text.toLowerCase();
  const tail: number[] = [];
  const lastColon = body.lastIndexOf(':');
  const last = body.slice(lastColon + 1);
  if (last.includes('.')) {
    const v4 = parseIpv4(last);
    if (v4 === null) return null;
    tail.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
    // Keep the colon when it is half of a `::` right before the dotted quad.
    body = body.slice(0, body[lastColon - 1] === ':' ? lastColon + 1 : lastColon);
  }

  const groups = (part: string): number[] =>
    part === '' ? [] : part.split(':').map((group) => Number.parseInt(group, 16));
  const halves = body.split('::');
  const head = groups(halves[0]);
  const back = halves.length === 2 ? groups(halves[1]) : [];
  const fill = 8 - tail.length - head.length - back.length;
  if (halves.length > 2 || fill < 0 || (halves.length === 1 && fill !== 0)) return null;
  const hextets = [...head, ...Array<number>(fill).fill(0), ...back, ...tail];
  if (hextets.length !== 8 || hextets.some((h) => !(h >= 0 && h <= 0xffff))) return null;

  return hextets.flatMap((h) => [h >> 8, h & 0xff]);
}

function ipv4Kind(bytes: readonly number[]): AddressKind {
  for (const range of IPV4_BLOCKED) {
    if (inRange(bytes, range.prefix, range.bits)) return range.kind;
  }
  return 'public';
}

/**
 * The IPv4 address an IPv6 form carries, or `null`. A dual-stack socket dials
 * a mapped address over IPv4, and a NAT64 gateway and a 6to4 relay forward to
 * the embedded one, so each of them reaches that IPv4 address.
 */
function embeddedIpv4(bytes: readonly number[]): readonly number[] | null {
  if (startsWith(bytes, IPV4_MAPPED_PREFIX) || startsWith(bytes, NAT64_PREFIX)) {
    return bytes.slice(12, 16);
  }
  if (startsWith(bytes, SIX_TO_FOUR_PREFIX)) return bytes.slice(2, 6);
  return null;
}

/**
 * The IPv4 address of an IPv4-mapped IPv6 address (`::ffff:0:0/96`), or
 * `null`. A dual-stack socket dials a mapped address as that IPv4 address.
 */
export function mappedIpv4(bytes: readonly number[]): readonly number[] | null {
  return startsWith(bytes, IPV4_MAPPED_PREFIX) ? bytes.slice(12, 16) : null;
}

function ipv6Kind(bytes: readonly number[]): AddressKind {
  if (bytes.every((b) => b === 0)) return 'unspecified';
  if (bytes.slice(0, 15).every((b) => b === 0) && bytes[15] === 1) return 'loopback';

  // Judge an IPv6 form that carries an IPv4 address by that address, so
  // `::ffff:169.254.169.254` and `64:ff9b::a9fe:a9fe` are the metadata address
  // and a DNS64 record of a public host stays reachable.
  const v4 = embeddedIpv4(bytes);
  if (v4 !== null) return ipv4Kind(v4);

  for (const range of IPV6_BLOCKED) {
    if (inRange(bytes, range.prefix, range.bits)) return range.kind;
  }
  // Outside 2000::/3: IPv4-compatible `::/96`, local-use NAT64
  // `64:ff9b:1::/48`, discard-only `100::/64`, site-local `fec0::/10` and
  // whatever is still unallocated.
  if (!inRange(bytes, [0x20], 3)) return 'reserved';
  return 'public';
}

/**
 * The {@link AddressKind} of an IP literal, IPv4 or IPv6 in any text form.
 * Anything that is not an IP literal is `invalid`.
 */
export function addressKind(ip: string): AddressKind {
  const v4 = parseIpv4(ip);
  if (v4 !== null) return ipv4Kind(v4);
  const v6 = parseIpv6(ip);
  if (v6 !== null) return ipv6Kind(v6);
  return 'invalid';
}

/**
 * True when `ip` is a public unicast address the egress client may dial: not
 * loopback, private, shared, link-local (the cloud metadata address included),
 * unique-local, multicast, unspecified, reserved or documentation, and not an
 * IPv6 form that carries such an IPv4 address (mapped, NAT64, 6to4).
 */
export function isPublicUnicastAddress(ip: string): boolean {
  return addressKind(ip) === 'public';
}

/** The cloud metadata address over IPv4, `169.254.169.254`. */
const METADATA_IPV4 = [169, 254, 169, 254];
/** The cloud metadata address over IPv6, `fd00:ec2::254`. */
const METADATA_IPV6 = [0xfd, 0, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54];

/**
 * True when `ip` is the cloud metadata address, `169.254.169.254` or
 * `fd00:ec2::254`, in any text form, an IPv6 form that carries the IPv4 one
 * included. No allowlist entry makes it reachable.
 */
export function isCloudMetadataAddress(ip: string): boolean {
  const same = (a: readonly number[], b: readonly number[]) =>
    a.length === b.length && a.every((byte, i) => byte === b[i]);
  const v4 = parseIpv4(ip);
  if (v4 !== null) return same(v4, METADATA_IPV4);
  const v6 = parseIpv6(ip);
  if (v6 === null) return false;
  const embedded = embeddedIpv4(v6);
  return same(v6, METADATA_IPV6) || (embedded !== null && same(embedded, METADATA_IPV4));
}
