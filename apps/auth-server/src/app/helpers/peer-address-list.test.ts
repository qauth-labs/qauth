import { describe, expect, it } from 'vitest';

import { createPeerAddressList } from './peer-address-list';

describe('createPeerAddressList', () => {
  const list = createPeerAddressList(['198.51.100.7', '10.0.4.0/28', '2001:db8:1:2::/64']);

  it('lists an address entry and the addresses of a range entry', () => {
    expect(list.has('198.51.100.7')).toBe(true);
    expect(list.has('10.0.4.1')).toBe(true);
    expect(list.has('10.0.4.15')).toBe(true);
    expect(list.has('2001:db8:1:2::abcd')).toBe(true);
  });

  it('lists nothing outside the entries', () => {
    expect(list.has('198.51.100.8')).toBe(false);
    expect(list.has('10.0.4.16')).toBe(false);
    expect(list.has('2001:db8:1:3::1')).toBe(false);
  });

  it('matches an IPv4-mapped IPv6 address to its IPv4 entry, and drops a zone id', () => {
    expect(list.has('::ffff:198.51.100.7')).toBe(true);
    expect(list.has('::ffff:10.0.4.2')).toBe(true);
    expect(list.has('2001:db8:1:2::1%eth0')).toBe(true);
  });

  it('never lists a missing address or a value that is not one', () => {
    expect(list.has(undefined)).toBe(false);
    expect(list.has('')).toBe(false);
    expect(list.has('unknown')).toBe(false);
  });

  it('lists no address when it has no entry', () => {
    const empty = createPeerAddressList([]);
    expect(empty.has('198.51.100.7')).toBe(false);
    expect(empty.has('127.0.0.1')).toBe(false);
  });

  it('never matches an IPv4 client against an IPv6 range that covers the mapped prefix', () => {
    for (const range of ['::/0', '::/64', '::ffff:0:0/80']) {
      const v6 = createPeerAddressList([range]);
      expect(v6.has('203.0.113.9'), range).toBe(false);
      expect(v6.has('::ffff:203.0.113.9'), range).toBe(false);
    }
    expect(createPeerAddressList(['::/0']).has('2001:db8::1')).toBe(true);
  });

  it('reads an IPv4-mapped entry as its IPv4 address or range', () => {
    const mapped = createPeerAddressList(['::ffff:198.51.100.9', '::ffff:10.0.4.0/120']);
    expect(mapped.has('198.51.100.9')).toBe(true);
    expect(mapped.has('::ffff:198.51.100.9')).toBe(true);
    expect(mapped.has('10.0.4.200')).toBe(true);
    expect(mapped.has('10.0.5.1')).toBe(false);
  });

  it('refuses an entry that is not an address or a range, or carries a zone id', () => {
    expect(() => createPeerAddressList(['uniquelocal'])).toThrow(/uniquelocal/);
    expect(() => createPeerAddressList(['fe80::1%eth0'])).toThrow(/fe80::1%eth0/);
  });
});
