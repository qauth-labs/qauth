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

  it('refuses an entry that is not an address or a range', () => {
    expect(() => createPeerAddressList(['uniquelocal'])).toThrow(/uniquelocal/);
  });
});
