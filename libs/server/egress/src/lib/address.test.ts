import { describe, expect, it } from 'vitest';

import {
  type AddressKind,
  addressKind,
  isCloudMetadataAddress,
  isPublicUnicastAddress,
} from './address';

/*
 * The address table of the egress client: every literal below is dialled
 * only when its kind is `public`.
 */

const TABLE: readonly [string, AddressKind, string][] = [
  // IPv4
  ['8.8.8.8', 'public', 'public IPv4'],
  ['93.184.215.14', 'public', 'public IPv4'],
  ['192.0.1.255', 'public', 'just below 192.0.2.0/24'],
  ['198.51.99.1', 'public', 'just below 198.51.100.0/24'],
  ['100.63.255.255', 'public', 'just below CGNAT'],
  ['100.128.0.0', 'public', 'just above CGNAT'],
  ['172.15.255.255', 'public', 'just below 172.16.0.0/12'],
  ['172.32.0.0', 'public', 'just above 172.16.0.0/12'],
  ['223.255.255.255', 'public', 'just below multicast'],
  ['0.0.0.0', 'unspecified', 'unspecified'],
  ['0.1.2.3', 'unspecified', '"this network"'],
  ['127.0.0.1', 'loopback', 'loopback'],
  ['127.255.255.254', 'loopback', 'loopback /8'],
  ['10.0.0.1', 'private', 'RFC 1918 10/8'],
  ['172.16.0.1', 'private', 'RFC 1918 172.16/12'],
  ['172.31.255.255', 'private', 'RFC 1918 172.16/12, top'],
  ['192.168.1.1', 'private', 'RFC 1918 192.168/16'],
  ['100.64.0.1', 'shared', 'CGNAT (RFC 6598)'],
  ['100.127.255.255', 'shared', 'CGNAT, top'],
  ['169.254.169.254', 'link-local', 'cloud metadata'],
  ['169.254.0.1', 'link-local', 'link-local'],
  ['224.0.0.1', 'multicast', 'multicast'],
  ['239.255.255.250', 'multicast', 'SSDP multicast'],
  ['240.0.0.1', 'reserved', 'reserved 240/4'],
  ['255.255.255.255', 'reserved', 'limited broadcast'],
  ['192.0.0.8', 'reserved', 'IETF protocol assignments'],
  ['192.88.99.1', 'reserved', '6to4 relay anycast'],
  ['198.18.0.1', 'reserved', 'benchmarking'],
  ['198.19.255.255', 'reserved', 'benchmarking, top'],
  ['192.0.2.1', 'documentation', 'TEST-NET-1'],
  ['198.51.100.7', 'documentation', 'TEST-NET-2'],
  ['203.0.113.10', 'documentation', 'TEST-NET-3'],

  // IPv6
  ['2606:4700:4700::1111', 'public', 'public IPv6'],
  ['2a00:1450:4001:80b::200e', 'public', 'public IPv6'],
  ['2001:200::1', 'public', 'just above 2001::/23'],
  ['3fff:1000::1', 'public', 'just above 3fff::/20'],
  ['::', 'unspecified', 'unspecified'],
  ['::1', 'loopback', 'loopback'],
  ['0:0:0:0:0:0:0:1', 'loopback', 'loopback, uncompressed'],
  ['fe80::1', 'link-local', 'link-local'],
  ['febf:ffff::1', 'link-local', 'link-local, top'],
  ['fc00::1', 'unique-local', 'unique-local'],
  ['fd00:ec2::254', 'unique-local', 'cloud metadata over IPv6'],
  ['ff02::1', 'multicast', 'multicast'],
  ['2001:db8::1', 'documentation', 'documentation'],
  ['3fff::1', 'documentation', 'documentation (RFC 9637)'],
  ['2001::1', 'reserved', 'Teredo'],
  ['2001:2::1', 'reserved', 'benchmarking'],
  ['2001:1ff::1', 'reserved', 'IETF protocol assignments, top'],
  ['fec0::1', 'reserved', 'deprecated site-local'],
  ['100::1', 'reserved', 'discard-only'],
  ['64:ff9b:1::a00:1', 'reserved', 'local-use NAT64'],
  ['4000::1', 'reserved', 'outside 2000::/3'],
  ['::8.8.8.8', 'reserved', 'IPv4-compatible (deprecated)'],
  ['::127.0.0.1', 'reserved', 'IPv4-compatible loopback'],

  // IPv4 inside IPv6: mapped
  ['::ffff:8.8.8.8', 'public', 'mapped public'],
  ['::ffff:808:808', 'public', 'mapped public, hex'],
  ['::ffff:127.0.0.1', 'loopback', 'mapped loopback'],
  ['::ffff:7f00:1', 'loopback', 'mapped loopback, hex'],
  ['::ffff:7f00:0001', 'loopback', 'mapped loopback, padded hex'],
  ['0:0:0:0:0:ffff:7f00:1', 'loopback', 'mapped loopback, uncompressed'],
  ['::FFFF:7F00:1', 'loopback', 'mapped loopback, upper case'],
  ['::ffff:169.254.169.254', 'link-local', 'mapped metadata'],
  ['::ffff:a9fe:a9fe', 'link-local', 'mapped metadata, hex'],
  ['::ffff:10.0.0.1', 'private', 'mapped RFC 1918'],
  ['::ffff:c0a8:101', 'private', 'mapped 192.168.1.1, hex'],
  ['::ffff:100.64.0.1', 'shared', 'mapped CGNAT'],
  ['::ffff:224.0.0.1', 'multicast', 'mapped multicast'],
  ['::ffff:0.0.0.0', 'unspecified', 'mapped unspecified'],

  // IPv4 inside IPv6: NAT64 (RFC 6052)
  ['64:ff9b::8.8.8.8', 'public', 'NAT64 of a public host (DNS64)'],
  ['64:ff9b::808:808', 'public', 'NAT64 of a public host, hex'],
  ['64:ff9b::7f00:1', 'loopback', 'NAT64 loopback'],
  ['64:ff9b::10.0.0.1', 'private', 'NAT64 RFC 1918'],
  ['64:ff9b::a9fe:a9fe', 'link-local', 'NAT64 metadata'],
  ['64:ff9b::6440:1', 'shared', 'NAT64 CGNAT'],

  // IPv4 inside IPv6: 6to4 (RFC 3056)
  ['2002:808:808::1', 'public', '6to4 of a public host'],
  ['2002:7f00:1::', 'loopback', '6to4 loopback'],
  ['2002:a00:1::1', 'private', '6to4 RFC 1918'],
  ['2002:a9fe:a9fe::', 'link-local', '6to4 metadata'],
  ['2002:c000:201::', 'documentation', '6to4 TEST-NET-1'],

  // Carried over from the auth server's former fetcher (ssrf-safe-fetch.ts,
  // removed in #481), whose regressions this table keeps.
  ['1.1.1.1', 'public', 'public IPv4'],
  ['2001:4860:4860::8888', 'public', 'public IPv6'],
  ['172.16.5.4', 'private', 'RFC 1918 172.16/12'],
  ['::ffff:a00:1', 'private', 'mapped 10.0.0.1, hex (ANT-2026-K1WCPR4R)'],
  ['::ffff:ac10:5', 'private', 'mapped 172.16.0.5, hex'],
  ['0000:0000:0000:0000:0000:ffff:7f00:0001', 'loopback', 'mapped loopback, unshortened'],
  ['::7f00:1', 'reserved', 'IPv4-compatible loopback, hex'],
  ['::a9fe:a9fe', 'reserved', 'IPv4-compatible metadata, hex'],
  ['::a00:1', 'reserved', 'IPv4-compatible 10.0.0.1, hex'],
  ['::ffff:0:a00:1', 'reserved', 'IPv4-translated'],
  ['feff::1', 'reserved', 'site-local, top of fec0::/10'],
  ['64:ff9b::a00:1', 'private', 'NAT64 10.0.0.1, hex'],
  ['2002:c0a8:101::1', 'private', '6to4 192.168.1.1'],

  // Not an IP literal
  ['example.com', 'invalid', 'a host name'],
  ['not-an-ip', 'invalid', 'a word'],
  ['', 'invalid', 'empty'],
  ['127.1', 'invalid', 'short IPv4 form'],
  ['0x7f.0.0.1', 'invalid', 'hex IPv4 form'],
  ['0177.0.0.1', 'invalid', 'octal IPv4 form'],
  ['fe80::1%eth0', 'invalid', 'zone id'],
  ['2001:4860::8888%1', 'invalid', 'zone id on a global address'],
  ['[::1]', 'invalid', 'bracketed'],
];

describe('addressKind', () => {
  it.each(TABLE)('%s is %s (%s)', (ip, kind) => {
    expect(addressKind(ip)).toBe(kind);
  });
});

describe('isPublicUnicastAddress', () => {
  it.each(TABLE)('%s → %s (%s)', (ip, kind) => {
    expect(isPublicUnicastAddress(ip)).toBe(kind === 'public');
  });
});

describe('isCloudMetadataAddress', () => {
  it.each([
    '169.254.169.254',
    'fd00:ec2::254',
    'FD00:EC2:0:0:0:0:0:254',
    '::ffff:169.254.169.254',
    '::ffff:a9fe:a9fe',
    '64:ff9b::a9fe:a9fe',
    '2002:a9fe:a9fe::',
    '169.254.170.2',
    '169.254.170.0',
    '169.254.170.255',
    '::ffff:169.254.170.2',
    '100.100.100.200',
    '::ffff:100.100.100.200',
    '64:ff9b::6464:64c8',
    'fd00:ec2::253',
    'fd00:ec2::1',
    'fd00:ec2:ffff:ffff:ffff:ffff:ffff:ffff',
  ])('%s is a metadata endpoint', (ip) => {
    expect(isCloudMetadataAddress(ip)).toBe(true);
  });

  it.each([
    '169.254.169.253',
    '169.254.0.1',
    '169.254.171.0',
    '169.254.169.255',
    '100.100.100.199',
    '100.100.100.201',
    'fd00:ec3::254',
    'fd00:ec1:ffff::1',
    '10.0.0.1',
    '::1',
    'example.com',
    '',
  ])('%s is not', (ip) => {
    expect(isCloudMetadataAddress(ip)).toBe(false);
  });
});
