import { describe, expect, it } from 'vitest';

import { baseEnvSchema } from './base';

/**
 * TRUST_PROXY decides which X-Forwarded-For hops set request.ip, and every
 * per-IP limit and lockout keys on request.ip. Unset must mean "no proxy";
 * `true` must never be accepted, because it lets any caller pick its own IP.
 */
describe('baseEnvSchema TRUST_PROXY', () => {
  const trustProxy = (raw: string | undefined) =>
    baseEnvSchema.parse(raw === undefined ? {} : { TRUST_PROXY: raw }).TRUST_PROXY;

  it('defaults to trusting no proxy', () => {
    expect(trustProxy(undefined)).toBe(false);
    expect(trustProxy('')).toBe(false);
    expect(trustProxy('false')).toBe(false);
  });

  it('rejects true (trust every hop)', () => {
    expect(() => trustProxy('true')).toThrow(/TRUST_PROXY=true/);
  });

  it('rejects a hop count, which cannot tell a proxy from a direct client', () => {
    expect(() => trustProxy('1')).toThrow(/not a hop count/);
    expect(() => trustProxy('0')).toThrow(/not a hop count/);
  });

  it('accepts addresses, CIDR ranges and the proxy-addr named ranges', () => {
    expect(trustProxy('10.0.0.5, 172.16.0.0/12, ::1, fd00::/8, loopback, uniquelocal')).toEqual([
      '10.0.0.5',
      '172.16.0.0/12',
      '::1',
      'fd00::/8',
      'loopback',
      'uniquelocal',
    ]);
  });

  it('rejects malformed entries', () => {
    expect(() => trustProxy('10.0.0.0/33')).toThrow(/invalid: 10.0.0.0\/33/);
    expect(() => trustProxy('proxy.internal')).toThrow(/invalid: proxy.internal/);
    expect(() => trustProxy('10.0.0.1/8/1')).toThrow(/invalid/);
    expect(() => trustProxy('*')).toThrow(/invalid/);
  });
});
