import { describe, expect, it } from 'vitest';

import { ceremonyAppPeerProblems, rateLimitEnvSchema } from './rate-limit';

/**
 * CEREMONY_APP_PEERS (#982) names the ceremony app server's addresses, whose
 * step reads count per interaction instead of per address. It takes the
 * addresses and CIDR ranges TRUST_PROXY takes, and nothing broader.
 */
describe('rateLimitEnvSchema CEREMONY_APP_PEERS', () => {
  const peers = (raw: string | undefined) =>
    rateLimitEnvSchema.parse(raw === undefined ? {} : { CEREMONY_APP_PEERS: raw })
      .CEREMONY_APP_PEERS;

  it('lists no address by default', () => {
    expect(peers(undefined)).toEqual([]);
    expect(peers('')).toEqual([]);
    expect(peers(' , ')).toEqual([]);
  });

  it('accepts addresses and CIDR ranges of either family', () => {
    expect(peers('10.0.4.12, 10.0.5.0/28,2001:db8::7, 2001:db8:1::/64')).toEqual([
      '10.0.4.12',
      '10.0.5.0/28',
      '2001:db8::7',
      '2001:db8:1::/64',
    ]);
  });

  it('refuses a named range, which lists every private address rather than one server', () => {
    expect(() => peers('uniquelocal')).toThrow(/CEREMONY_APP_PEERS.*invalid: uniquelocal/);
    expect(() => peers('10.0.4.12,loopback')).toThrow(/invalid: loopback/);
  });

  it('refuses malformed entries and names them', () => {
    expect(() => peers('true')).toThrow(/invalid: true/);
    expect(() => peers('10.0.4.0/33')).toThrow(/invalid: 10\.0\.4\.0\/33/);
    expect(() => peers('ceremony.internal')).toThrow(/invalid: ceremony\.internal/);
  });
});

describe('rateLimitEnvSchema CEREMONY_APP_PEER_RATE_LIMIT', () => {
  const cap = (raw: string | undefined) =>
    rateLimitEnvSchema.parse(raw === undefined ? {} : { CEREMONY_APP_PEER_RATE_LIMIT: raw })
      .CEREMONY_APP_PEER_RATE_LIMIT;

  it('has no default', () => {
    expect(cap(undefined)).toBeUndefined();
  });

  it('takes a positive whole number of reads per minute', () => {
    expect(cap('600')).toBe(600);
    expect(() => cap('0')).toThrow();
    expect(() => cap('1.5')).toThrow();
  });
});

describe('ceremonyAppPeerProblems', () => {
  it('accepts both set, or neither', () => {
    expect(ceremonyAppPeerProblems({ CEREMONY_APP_PEERS: [] })).toEqual([]);
    expect(
      ceremonyAppPeerProblems({
        CEREMONY_APP_PEERS: ['10.0.4.12'],
        CEREMONY_APP_PEER_RATE_LIMIT: 600,
      })
    ).toEqual([]);
  });

  it('refuses a list without its cap, naming both settings', () => {
    const problems = ceremonyAppPeerProblems({ CEREMONY_APP_PEERS: ['10.0.4.12'] });
    expect(problems).toHaveLength(1);
    expect(problems[0].variable).toBe('CEREMONY_APP_PEER_RATE_LIMIT');
    expect(problems[0].message).toMatch(/CEREMONY_APP_PEERS/);
    expect(problems[0].message).toMatch(/CEREMONY_APP_PEER_RATE_LIMIT/);
  });

  it('refuses a cap without its list, an empty list counted as unset', () => {
    const problems = ceremonyAppPeerProblems({
      CEREMONY_APP_PEERS: [],
      CEREMONY_APP_PEER_RATE_LIMIT: 600,
    });
    expect(problems.map((problem) => problem.variable)).toEqual(['CEREMONY_APP_PEERS']);
    expect(problems[0].message).toMatch(/CEREMONY_APP_PEERS and CEREMONY_APP_PEER_RATE_LIMIT/);
  });
});
