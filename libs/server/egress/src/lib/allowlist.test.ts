import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import {
  allowlistPermit,
  EgressAllowlistError,
  isEgressAllowlist,
  loadEgressAllowlist,
  parseEgressAllowlist,
} from './allowlist';

/*
 * The deployment allowlist file (`EGRESS_ALLOWLIST_PATH`, issue #481): what it
 * accepts, what it refuses and what one realm's entries let a call reach. The
 * client applies it only to `operator` and `admin` destinations; that part is
 * in `egress-client.test.ts`.
 */

const parse = (entries: unknown) => parseEgressAllowlist({ entries });

/** The message an invalid allowlist is refused with. */
function refusal(value: unknown): string {
  try {
    parseEgressAllowlist(value);
  } catch (err) {
    expect(err).toBeInstanceOf(EgressAllowlistError);
    return (err as Error).message;
  }
  throw new Error('the allowlist was accepted');
}

describe('parseEgressAllowlist', () => {
  it('accepts host and range entries and keeps them as written', () => {
    const allowlist = parse([
      { host: 'IdP.Corp.Example.', realms: ['master'] },
      { cidr: '10.20.0.0/16', realms: ['master', 'acme'], note: 'partner VPN' },
      { cidr: 'fd12:3456::/32', realms: ['acme'] },
    ]);
    expect(allowlist.entries).toEqual([
      { host: 'idp.corp.example', realms: ['master'] },
      { cidr: '10.20.0.0/16', realms: ['master', 'acme'], note: 'partner VPN' },
      { cidr: 'fd12:3456::/32', realms: ['acme'] },
    ]);
    expect(Object.isFrozen(allowlist)).toBe(true);
    expect(Object.isFrozen(allowlist.entries[0])).toBe(true);
    expect(isEgressAllowlist(allowlist)).toBe(true);
  });

  it('accepts an empty list', () => {
    expect(parse([]).entries).toEqual([]);
  });

  it.each([
    ['not an object', [], 'must be a JSON object'],
    ['an unknown top-level member', { entries: [], extra: 1 }, 'unknown member "extra"'],
    ['entries that are not a list', { entries: {} }, '"entries" must be a list'],
    ['an entry that is not an object', { entries: ['10.0.0.0/8'] }, 'entries[0] must be an object'],
    [
      'an unknown entry member',
      { entries: [{ host: 'a.example', realms: ['r'], ports: [443] }] },
      'unknown member "ports"',
    ],
    [
      'both host and cidr',
      { entries: [{ host: 'a.example', cidr: '10.0.0.0/8', realms: ['r'] }] },
      'both',
    ],
    ['neither host nor cidr', { entries: [{ realms: ['r'] }] }, 'must name a "host" or a "cidr"'],
    ['no realms', { entries: [{ host: 'a.example' }] }, 'realms must list at least one'],
    ['an empty realm list', { entries: [{ host: 'a.example', realms: [] }] }, 'at least one'],
    ['an empty realm name', { entries: [{ host: 'a.example', realms: [''] }] }, 'realms[0]'],
    ['a padded realm name', { entries: [{ host: 'a.example', realms: [' master'] }] }, 'realms[0]'],
    [
      'a realm that is not a string',
      { entries: [{ host: 'a.example', realms: [7] }] },
      'realms[0]',
    ],
    ['a wildcard host', { entries: [{ host: '*.corp.example', realms: ['r'] }] }, 'wildcard'],
    ['an IP literal as host', { entries: [{ host: '10.0.0.7', realms: ['r'] }] }, '"10.0.0.7/32"'],
    ['an IPv6 literal as host', { entries: [{ host: '[fd00::1]', realms: ['r'] }] }, 'range'],
    [
      'a host with a path',
      { entries: [{ host: 'a.example/x', realms: ['r'] }] },
      'not a valid host',
    ],
    [
      'a host with a port',
      { entries: [{ host: 'a.example:8443', realms: ['r'] }] },
      'not a valid host',
    ],
    [
      'a range without a prefix length',
      { entries: [{ cidr: '10.0.0.7', realms: ['r'] }] },
      'prefix length',
    ],
    ['a range past /32', { entries: [{ cidr: '10.0.0.0/33', realms: ['r'] }] }, 'from 0 to 32'],
    ['a range past /128', { entries: [{ cidr: 'fd00::/129', realms: ['r'] }] }, 'from 0 to 128'],
    [
      'a range that is not an address',
      { entries: [{ cidr: 'corp/8', realms: ['r'] }] },
      'IPv4 or IPv6',
    ],
    ['a short IPv4 form', { entries: [{ cidr: '10.1/16', realms: ['r'] }] }, 'IPv4 or IPv6'],
    [
      'host bits below the prefix',
      { entries: [{ cidr: '10.0.0.7/24', realms: ['r'] }] },
      'first address',
    ],
    [
      'IPv6 host bits below the prefix',
      { entries: [{ cidr: 'fd00::1/64', realms: ['r'] }] },
      'first address',
    ],
    ['a zone id', { entries: [{ cidr: 'fe80::%eth0/64', realms: ['r'] }] }, 'IPv4 or IPv6'],
    ['an IPv4 range wider than /8', { entries: [{ cidr: '10.0.0.0/7', realms: ['r'] }] }, '/8'],
    ['every IPv4 address', { entries: [{ cidr: '0.0.0.0/0', realms: ['r'] }] }, '/8'],
    ['an IPv6 range wider than /32', { entries: [{ cidr: 'fd00::/8', realms: ['r'] }] }, '/32'],
    [
      'the IPv4-mapped range',
      { entries: [{ cidr: '::ffff:0:0/96', realms: ['r'] }] },
      'IPv4-mapped',
    ],
    [
      'a range inside the IPv4-mapped range',
      { entries: [{ cidr: '::ffff:a00:0/104', realms: ['r'] }] },
      'IPv4-mapped',
    ],
    ['the NAT64 range', { entries: [{ cidr: '64:ff9b::/96', realms: ['r'] }] }, 'NAT64'],
    [
      'a range that holds the NAT64 range',
      { entries: [{ cidr: '64:ff9b::/32', realms: ['r'] }] },
      'NAT64',
    ],
    [
      'the local-use NAT64 range',
      { entries: [{ cidr: '64:ff9b:1::/48', realms: ['r'] }] },
      'NAT64',
    ],
    ['a 6to4 range', { entries: [{ cidr: '2002:a00::/32', realms: ['r'] }] }, '6to4'],
    ['the Teredo range', { entries: [{ cidr: '2001::/32', realms: ['r'] }] }, 'Teredo'],
    ['a range inside Teredo', { entries: [{ cidr: '2001:0:a00::/48', realms: ['r'] }] }, 'Teredo'],
    [
      'a note that is not a string',
      { entries: [{ host: 'a.example', realms: ['r'], note: 1 }] },
      'note',
    ],
  ])('refuses %s', (_label, value, message) => {
    expect(refusal(value)).toContain(message);
  });

  it('names where the mistake is', () => {
    expect(() =>
      parseEgressAllowlist(
        {
          entries: [
            { host: 'a.example', realms: ['r'] },
            { cidr: '10.0.0.1/8', realms: ['r'] },
          ],
        },
        'EGRESS_ALLOWLIST_PATH (/etc/qauth/egress.json)'
      )
    ).toThrow('EGRESS_ALLOWLIST_PATH (/etc/qauth/egress.json): entries[1].cidr');
  });

  it('is not fooled by an object of the same shape', () => {
    expect(isEgressAllowlist({ entries: [] })).toBe(false);
  });
});

describe('loadEgressAllowlist', () => {
  const dir = mkdtempSync(join(tmpdir(), 'egress-allowlist-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('reads and validates the file', () => {
    const path = join(dir, 'ok.json');
    writeFileSync(path, JSON.stringify({ entries: [{ cidr: '10.0.0.0/8', realms: ['master'] }] }));
    expect(loadEgressAllowlist(path).entries).toEqual([{ cidr: '10.0.0.0/8', realms: ['master'] }]);
  });

  it('refuses a file that is missing, naming the variable and the path', () => {
    const path = join(dir, 'missing.json');
    expect(() => loadEgressAllowlist(path)).toThrow(
      `EGRESS_ALLOWLIST_PATH (${path}): the file cannot be read (ENOENT)`
    );
  });

  it('refuses a file that is not JSON', () => {
    const path = join(dir, 'broken.json');
    writeFileSync(path, '{ entries: ');
    expect(() => loadEgressAllowlist(path)).toThrow('the file is not valid JSON');
  });

  it('refuses a file whose entries do not validate', () => {
    const path = join(dir, 'invalid.json');
    writeFileSync(path, JSON.stringify({ entries: [{ host: '*.corp', realms: ['master'] }] }));
    expect(() => loadEgressAllowlist(path)).toThrow(EgressAllowlistError);
  });
});

describe('allowlistPermit', () => {
  const allowlist = parse([
    { host: 'idp.corp.example', realms: ['master'] },
    { cidr: '10.20.0.0/16', realms: ['acme'] },
    { cidr: 'fd12:3456::/32', realms: ['acme'] },
    { cidr: '192.168.1.0/24', realms: ['master', 'acme'] },
  ]);

  it('answers undefined for a realm no entry names', () => {
    expect(allowlistPermit(allowlist, 'other')).toBeUndefined();
    // Realm names are compared exactly.
    expect(allowlistPermit(allowlist, 'Master')).toBeUndefined();
  });

  it('opens only the entries of the realm', () => {
    const master = allowlistPermit(allowlist, 'master');
    const acme = allowlistPermit(allowlist, 'acme');
    expect(master?.('idp.corp.example', '10.99.0.1')).toBe(true);
    expect(acme?.('idp.corp.example', '10.99.0.1')).toBe(false);
    // A host entry opens private networks only; its DNS may be someone else's.
    expect(master?.('idp.corp.example', '100.64.0.1')).toBe(true);
    expect(master?.('idp.corp.example', 'fd12::1')).toBe(true);
    expect(master?.('idp.corp.example', '127.0.0.1')).toBe(false);
    expect(master?.('idp.corp.example', '169.254.170.2')).toBe(false);
    expect(master?.('idp.corp.example', '198.18.0.1')).toBe(false);
    expect(acme?.('any.example', '10.20.255.255')).toBe(true);
    expect(master?.('any.example', '10.20.255.255')).toBe(false);
    expect(master?.('any.example', '192.168.1.200')).toBe(true);
    expect(acme?.('any.example', '192.168.1.200')).toBe(true);
  });

  it('matches range edges by bits', () => {
    const acme = allowlistPermit(allowlist, 'acme');
    expect(acme?.('h', '10.20.0.0')).toBe(true);
    expect(acme?.('h', '10.19.255.255')).toBe(false);
    expect(acme?.('h', '10.21.0.0')).toBe(false);
    expect(acme?.('h', 'fd12:3456:ffff::1')).toBe(true);
    expect(acme?.('h', 'fd12:3457::1')).toBe(false);
  });

  it('judges an IPv4-mapped IPv6 address by its IPv4 address, and nothing else that embeds one', () => {
    const acme = allowlistPermit(allowlist, 'acme');
    expect(acme?.('h', '::ffff:10.20.0.7')).toBe(true);
    expect(acme?.('h', '::ffff:a14:7')).toBe(true);
    // A NAT64 or 6to4 address is the gateway's, not the range's.
    expect(acme?.('h', '64:ff9b::a14:7')).toBe(false);
    expect(acme?.('h', '2002:a14:7::')).toBe(false);
  });

  it('never matches an IPv4 range with an IPv6 address or the reverse', () => {
    const permit = allowlistPermit(
      parse([
        { cidr: '10.0.0.0/8', realms: ['r'] },
        { cidr: 'a00::/32', realms: ['v6'] },
      ]),
      'r'
    );
    expect(permit?.('h', '10.0.0.1')).toBe(true);
    // The same leading bytes in an IPv6 address are not the IPv4 range.
    expect(permit?.('h', 'a00::1')).toBe(false);
    expect(
      allowlistPermit(parse([{ cidr: 'a00::/32', realms: ['r'] }]), 'r')?.('h', '10.0.0.1')
    ).toBe(false);
  });
});
