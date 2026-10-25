import { describe, expect, it } from 'vitest';

import { hostFamily } from './host-family';

describe('hostFamily', () => {
  it.each([
    ['a.stall.test', 'stall.test'],
    ['b.c.stall.test', 'stall.test'],
    ['stall.test', 'stall.test'],
    ['www.example.com', 'example.com'],
    ['api.example.co.uk', 'example.co.uk'],
  ])('counts the name %s under its registrable domain %s', (hostname, family) => {
    expect(hostFamily(hostname, 0)).toBe(family);
  });

  it('keeps the owners of a private-section suffix apart', () => {
    expect(hostFamily('alice.eu.org', 0)).toBe('alice.eu.org');
    expect(hostFamily('docs.alice.eu.org', 0)).toBe('alice.eu.org');
    expect(hostFamily('bob.eu.org', 0)).toBe('bob.eu.org');
  });

  it('counts a name that is a public suffix as its own family', () => {
    expect(hostFamily('co.uk', 0)).toBe('co.uk');
    expect(hostFamily('localhost', 0)).toBe('localhost');
  });

  it('counts an IPv4 literal as its own family', () => {
    expect(hostFamily('93.184.215.14', 4)).toBe('93.184.215.14');
    expect(hostFamily('93.184.215.15', 4)).toBe('93.184.215.15');
  });

  it('counts an IPv6 literal under its /64', () => {
    expect(hostFamily('2606:4700:4700::1111', 6)).toBe('2606:4700:4700:0::/64');
    expect(hostFamily('2606:4700:4700:0:ffff::1', 6)).toBe('2606:4700:4700:0::/64');
    expect(hostFamily('2606:4700:4700:1::1', 6)).toBe('2606:4700:4700:1::/64');
  });
});
