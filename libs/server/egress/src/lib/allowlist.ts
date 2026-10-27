import { closeSync, fstatSync, openSync, readFileSync, type Stats } from 'node:fs';
import { isIP } from 'node:net';

import {
  type AddressKind,
  addressKind,
  inRange,
  mappedIpv4,
  parseIpv4,
  parseIpv6,
} from './address';

/**
 * The deployment-level egress allowlist (ADR-019 Decision 8): the hosts and
 * address ranges an operator lets the egress client reach although they are
 * not public, each for the realms it names.
 *
 * An entry applies only to a destination the operator or a realm admin set
 * (`source` `operator` or `admin`), for a realm the entry names. A destination
 * that a client, an end user or a remote document supplies never uses it.
 *
 * The list is a file the operator writes, named by `EGRESS_ALLOWLIST_PATH`
 * and read once at boot. It is not in the database, and no API reads or edits
 * it, so a realm admin cannot widen it.
 *
 * @example
 * ```json
 * {
 *   "entries": [
 *     { "host": "idp.corp.example", "realms": ["master"] },
 *     { "cidr": "10.20.0.0/16", "realms": ["master", "acme"], "note": "partner VPN" }
 *   ]
 * }
 * ```
 */
export interface EgressAllowlist {
  readonly entries: readonly EgressAllowlistEntry[];
}

/** One allowlist entry: a host or a range, and the realms it applies to. */
export interface EgressAllowlistEntry {
  /**
   * A host name, matched exactly and case-insensitively against the URL's
   * host. The private (RFC 1918), shared (RFC 6598) and unique-local addresses
   * it resolves to may then be dialled. Its DNS may be someone else's, so a
   * host entry never opens loopback, link-local or another special range; a
   * `cidr` entry that names one does.
   */
  readonly host?: string;
  /**
   * An IPv4 or IPv6 range, such as `10.20.0.0/16`, matched against every
   * address the URL's host is or resolves to.
   */
  readonly cidr?: string;
  /** The realms, by name, whose operator- and admin-set destinations it applies to. */
  readonly realms: readonly string[];
  /** The operator's own words about the entry. Not read. */
  readonly note?: string;
}

/** An allowlist file or value that cannot be used. The message names what is wrong. */
export class EgressAllowlistError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EgressAllowlistError';
  }
}

/**
 * Decides whether a non-public `address` of `hostname` may be dialled for one
 * call. The client consults it only for an address that is not public, and
 * never for one no entry opens.
 */
export type AddressPermit = (hostname: string, address: string) => boolean;

/** A range, as bytes. */
interface CompiledRange {
  readonly family: 4 | 6;
  readonly bytes: readonly number[];
  readonly bits: number;
}

/**
 * The kinds of address a `host` entry opens: the private networks an operator
 * reaches an internal service on. Anything else needs a `cidr` entry.
 */
const HOST_ENTRY_KINDS: ReadonlySet<AddressKind> = new Set<AddressKind>([
  'private',
  'shared',
  'unique-local',
]);

/** An entry in the form the client matches with. */
interface CompiledEntry {
  readonly host: string | undefined;
  readonly range: CompiledRange | undefined;
  readonly realms: ReadonlySet<string>;
}

/**
 * Where an allowlist {@link parseEgressAllowlist} made keeps its compiled
 * entries: a non-enumerable property under a registry symbol, so that a copy
 * of this library loaded twice (a test runner that resets its module
 * registry) still reads a list the other copy parsed.
 */
const COMPILED = Symbol.for('@qauth-labs/server-egress/allowlist');

/** The compiled entries of a parsed allowlist, or `undefined` for anything else. */
function compiledEntries(allowlist: unknown): readonly CompiledEntry[] | undefined {
  if (typeof allowlist !== 'object' || allowlist === null) return undefined;
  const entries: unknown = Reflect.get(allowlist, COMPILED);
  return Array.isArray(entries) ? (entries as readonly CompiledEntry[]) : undefined;
}

const MAX_ENTRIES = 1000;
/** The widest IPv4 range an entry may open. */
const MIN_IPV4_PREFIX = 8;
/** The widest IPv6 range an entry may open. */
const MIN_IPV6_PREFIX = 32;

/**
 * IPv6 ranges whose addresses reach other addresses only through translation.
 * An entry may not overlap one: it would open whatever the translator reaches,
 * and an IPv4-mapped address is judged by its IPv4 address anyway.
 */
const TRANSLATION_RANGES: readonly { name: string; prefix: readonly number[]; bits: number }[] = [
  {
    name: 'IPv4-mapped ::ffff:0:0/96',
    prefix: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
    bits: 96,
  },
  {
    name: 'NAT64 64:ff9b::/96',
    prefix: [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0],
    bits: 96,
  },
  { name: 'local-use NAT64 64:ff9b:1::/48', prefix: [0, 0x64, 0xff, 0x9b, 0, 1], bits: 48 },
  { name: '6to4 2002::/16', prefix: [0x20, 0x02], bits: 16 },
  { name: 'Teredo 2001::/32', prefix: [0x20, 0x01, 0, 0], bits: 32 },
];
const MAX_REALMS_PER_ENTRY = 100;
/** The `realms.name` column's length. */
const MAX_REALM_NAME_LENGTH = 255;
const MAX_NOTE_LENGTH = 1000;
const ENTRY_KEYS: ReadonlySet<string> = new Set(['host', 'cidr', 'realms', 'note']);

/**
 * A host name as URLs carry it after parsing: lower-case ASCII labels of
 * letters, digits, `-` and `_`, at most 63 characters each and 253 in all. An
 * internationalised name is written in its `xn--` form.
 */
const HOST_NAME =
  /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseHost(value: unknown, at: string): string {
  if (typeof value !== 'string') {
    throw new EgressAllowlistError(`${at}.host must be a string`);
  }
  if (value.includes('*')) {
    throw new EgressAllowlistError(`${at}.host must name one host; a wildcard is not allowed`);
  }
  const host = value.toLowerCase().replace(/\.$/, '');
  const literal = isIP(host.replace(/^\[|\]$/g, ''));
  if (literal !== 0) {
    const address = host.replace(/^\[|\]$/g, '');
    throw new EgressAllowlistError(
      `${at}.host must be a host name; write an address as a range in "cidr", such as "${address}/${literal === 4 ? 32 : 128}"`
    );
  }
  if (!HOST_NAME.test(host)) {
    throw new EgressAllowlistError(`${at}.host is not a valid host name`);
  }
  return host;
}

function parseCidr(value: unknown, at: string): CompiledRange {
  if (typeof value !== 'string') {
    throw new EgressAllowlistError(`${at}.cidr must be a string`);
  }
  const slash = value.indexOf('/');
  if (slash === -1) {
    throw new EgressAllowlistError(
      `${at}.cidr must carry a prefix length, such as "10.20.0.0/16" or "${value}/32"`
    );
  }
  const address = value.slice(0, slash);
  const length = value.slice(slash + 1);
  const v4 = parseIpv4(address);
  const v6 = v4 === null ? parseIpv6(address) : null;
  if (v4 === null && v6 === null) {
    throw new EgressAllowlistError(`${at}.cidr does not start with an IPv4 or IPv6 address`);
  }
  const family = v4 === null ? 6 : 4;
  const bytes = v4 ?? (v6 as number[]);
  const maxBits = family === 4 ? 32 : 128;
  if (!/^\d{1,3}$/.test(length) || Number(length) > maxBits) {
    throw new EgressAllowlistError(`${at}.cidr must end in a prefix length from 0 to ${maxBits}`);
  }
  const bits = Number(length);
  // Bits below the prefix length would be ignored, and an entry that does not
  // say what it matches is a mistake waiting to happen.
  const network = bytes.map((byte, i) => {
    const keep = Math.max(0, Math.min(8, bits - i * 8));
    return byte & ((0xff << (8 - keep)) & 0xff);
  });
  if (network.some((byte, i) => byte !== bytes[i])) {
    throw new EgressAllowlistError(
      `${at}.cidr has address bits set below its prefix length; write the range's first address`
    );
  }
  const minBits = family === 4 ? MIN_IPV4_PREFIX : MIN_IPV6_PREFIX;
  if (bits < minBits) {
    throw new EgressAllowlistError(
      `${at}.cidr is wider than /${minBits}; list the narrower ranges the deployment reaches`
    );
  }
  if (family === 6) {
    const translated = TRANSLATION_RANGES.find((range) =>
      inRange(network, range.prefix, Math.min(bits, range.bits))
    );
    if (translated !== undefined) {
      throw new EgressAllowlistError(
        `${at}.cidr overlaps ${translated.name}, whose addresses reach others only through translation; list the range they reach instead`
      );
    }
  }
  return { family, bytes: network, bits };
}

function parseRealms(value: unknown, at: string): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new EgressAllowlistError(`${at}.realms must list at least one realm name`);
  }
  if (value.length > MAX_REALMS_PER_ENTRY) {
    throw new EgressAllowlistError(`${at}.realms lists more than ${MAX_REALMS_PER_ENTRY} realms`);
  }
  return value.map((realm, i) => {
    if (
      typeof realm !== 'string' ||
      realm === '' ||
      realm.length > MAX_REALM_NAME_LENGTH ||
      realm.trim() !== realm ||
      // eslint-disable-next-line no-control-regex
      /[\u0000-\u001f\u007f]/.test(realm)
    ) {
      throw new EgressAllowlistError(`${at}.realms[${i}] must be a realm name`);
    }
    return realm;
  });
}

/**
 * Validate an allowlist, as the JSON of its file. Every mistake refuses the
 * whole list, naming where it is: an unknown member, an entry with both or
 * neither of `host` and `cidr`, a wildcard, a range with bits set below its
 * prefix length, a range wider than /8 (IPv4) or /32 (IPv6), an IPv6 range
 * that overlaps a translation range (IPv4-mapped, NAT64, 6to4, Teredo), an
 * entry without realms.
 *
 * @param what - names the list in error messages, such as the variable and the file
 * @throws EgressAllowlistError
 */
export function parseEgressAllowlist(
  value: unknown,
  what = 'the egress allowlist'
): EgressAllowlist {
  if (!isRecord(value)) {
    throw new EgressAllowlistError(`${what}: must be a JSON object with an "entries" list`);
  }
  for (const key of Object.keys(value)) {
    if (key !== 'entries') {
      throw new EgressAllowlistError(`${what}: unknown member "${key}"`);
    }
  }
  const raw = value['entries'];
  if (!Array.isArray(raw)) {
    throw new EgressAllowlistError(`${what}: "entries" must be a list`);
  }
  if (raw.length > MAX_ENTRIES) {
    throw new EgressAllowlistError(`${what}: more than ${MAX_ENTRIES} entries`);
  }

  const entries: EgressAllowlistEntry[] = [];
  const compiledList: CompiledEntry[] = [];
  raw.forEach((item: unknown, index) => {
    const at = `${what}: entries[${index}]`;
    if (!isRecord(item)) {
      throw new EgressAllowlistError(`${at} must be an object`);
    }
    for (const key of Object.keys(item)) {
      if (!ENTRY_KEYS.has(key)) {
        throw new EgressAllowlistError(`${at} has an unknown member "${key}"`);
      }
    }
    const hasHost = item['host'] !== undefined;
    const hasCidr = item['cidr'] !== undefined;
    if (hasHost && hasCidr) {
      throw new EgressAllowlistError(`${at} names both a "host" and a "cidr"; split it in two`);
    }
    if (!hasHost && !hasCidr) {
      throw new EgressAllowlistError(`${at} must name a "host" or a "cidr"`);
    }
    const note = item['note'];
    if (note !== undefined && (typeof note !== 'string' || note.length > MAX_NOTE_LENGTH)) {
      throw new EgressAllowlistError(
        `${at}.note must be a string of at most ${MAX_NOTE_LENGTH} characters`
      );
    }
    const realms = parseRealms(item['realms'], at);
    const host = hasHost ? parseHost(item['host'], at) : undefined;
    const range = hasCidr ? parseCidr(item['cidr'], at) : undefined;

    entries.push(
      Object.freeze({
        ...(host === undefined ? {} : { host }),
        ...(hasCidr ? { cidr: item['cidr'] as string } : {}),
        realms: Object.freeze([...realms]),
        ...(note === undefined ? {} : { note }),
      })
    );
    compiledList.push(Object.freeze({ host, range, realms: new Set(realms) }));
  });

  const allowlist: EgressAllowlist = { entries: Object.freeze(entries) };
  Object.defineProperty(allowlist, COMPILED, { value: Object.freeze(compiledList) });
  return Object.freeze(allowlist);
}

/** The allowlist of a deployment that names none: every non-public address is refused. */
export const EMPTY_EGRESS_ALLOWLIST: EgressAllowlist = parseEgressAllowlist({ entries: [] });

/**
 * Read the allowlist file at `path` (`EGRESS_ALLOWLIST_PATH`). Called once, at
 * boot; a file that cannot be read or does not validate fails the boot.
 *
 * The file is opened once: `inspect` gets the status of that open descriptor
 * before it is read, so a check of the file's owner and mode applies to the
 * very file read, not to whatever the path names a moment later. An error it
 * throws fails the load.
 *
 * @throws EgressAllowlistError naming the variable, the file and the mistake
 */
export function loadEgressAllowlist(
  path: string,
  inspect?: (stats: Stats, what: string) => void
): EgressAllowlist {
  const what = `EGRESS_ALLOWLIST_PATH (${path})`;
  const unreadable = (err: unknown) => {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    return new EgressAllowlistError(`${what}: the file cannot be read${code ? ` (${code})` : ''}`);
  };
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch (err) {
    throw unreadable(err);
  }
  let text: string;
  try {
    let stats: Stats;
    try {
      stats = fstatSync(fd);
    } catch (err) {
      throw unreadable(err);
    }
    inspect?.(stats, what);
    try {
      text = readFileSync(fd, 'utf8');
    } catch (err) {
      throw unreadable(err);
    }
  } finally {
    closeSync(fd);
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new EgressAllowlistError(`${what}: the file is not valid JSON`);
  }
  return parseEgressAllowlist(json, what);
}

/** Whether `allowlist` came from {@link parseEgressAllowlist}. */
export function isEgressAllowlist(allowlist: unknown): allowlist is EgressAllowlist {
  return compiledEntries(allowlist) !== undefined;
}

/** Whether an IP literal lies in `range`, an IPv4-mapped one judged as its IPv4 address too. */
function rangeHolds(range: CompiledRange, address: string): boolean {
  const v4 = parseIpv4(address);
  if (v4 !== null) return range.family === 4 && inRange(v4, range.bytes, range.bits);
  const v6 = parseIpv6(address);
  if (v6 === null) return false;
  if (range.family === 6) return inRange(v6, range.bytes, range.bits);
  const mapped = mappedIpv4(v6);
  return mapped !== null && inRange(mapped, range.bytes, range.bits);
}

/**
 * What the allowlist lets one call for `realm` reach: the hosts and ranges of
 * the entries that name the realm. `undefined` when none does, so the call
 * reaches public addresses only.
 */
export function allowlistPermit(
  allowlist: EgressAllowlist,
  realm: string
): AddressPermit | undefined {
  const entries = (compiledEntries(allowlist) ?? []).filter((entry) => entry.realms.has(realm));
  if (entries.length === 0) return undefined;
  return (hostname, address) =>
    entries.some(
      (entry) =>
        (entry.host !== undefined &&
          entry.host === hostname &&
          HOST_ENTRY_KINDS.has(addressKind(address))) ||
        (entry.range !== undefined && rangeHolds(entry.range, address))
    );
}
