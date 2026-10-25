import { describe, expect, it } from 'vitest';

import { realmRateLimitKey, resolveRealmRateLimitMax } from './realm-rate-limit';

const CONFIG = { lenientMax: 300, strictMax: 30 } as const;

const REALM_A = '0190e3c4-0000-7000-8000-00000000000a';
const REALM_B = '0190e3c4-0000-7000-8000-00000000000b';

describe('resolveRealmRateLimitMax', () => {
  it('returns the strict cap when the realm ceiling is production', () => {
    expect(resolveRealmRateLimitMax({ maxEnvironmentLaxity: 'production' }, CONFIG)).toBe(
      CONFIG.strictMax
    );
  });

  it('returns the lenient cap when the realm ceiling is development', () => {
    expect(resolveRealmRateLimitMax({ maxEnvironmentLaxity: 'development' }, CONFIG)).toBe(
      CONFIG.lenientMax
    );
  });

  it('gives staging the lenient tier, as development', () => {
    // ADR-008 §5: staging shares the lenient tier (load testing), production is strict.
    expect(resolveRealmRateLimitMax({ maxEnvironmentLaxity: 'staging' }, CONFIG)).toBe(
      CONFIG.lenientMax
    );
  });

  it('fails safe to the strict cap when the realm ceiling is unset or invalid', () => {
    expect(resolveRealmRateLimitMax({ maxEnvironmentLaxity: null }, CONFIG)).toBe(CONFIG.strictMax);
    expect(resolveRealmRateLimitMax({ maxEnvironmentLaxity: 'lenient' }, CONFIG)).toBe(
      CONFIG.strictMax
    );
  });

  it('fails safe to the strict cap when the request has no realm', () => {
    expect(resolveRealmRateLimitMax(null, CONFIG)).toBe(CONFIG.strictMax);
    expect(resolveRealmRateLimitMax(undefined, CONFIG)).toBe(CONFIG.strictMax);
  });

  it('reads each realm’s own ceiling', () => {
    const development = { maxEnvironmentLaxity: 'development' };
    const production = { maxEnvironmentLaxity: 'production' };

    expect(resolveRealmRateLimitMax(development, CONFIG)).toBe(CONFIG.lenientMax);
    expect(resolveRealmRateLimitMax(production, CONFIG)).toBe(CONFIG.strictMax);
    expect(resolveRealmRateLimitMax(development, CONFIG)).toBe(CONFIG.lenientMax);
  });
});

describe('realmRateLimitKey', () => {
  it('puts the realm id before the client address key', () => {
    expect(realmRateLimitKey({ ip: '203.0.113.7', realm: { id: REALM_A } })).toBe(
      `${REALM_A}:203.0.113.7`
    );
  });

  it('gives the same address a different key in each realm', () => {
    const inA = realmRateLimitKey({ ip: '203.0.113.7', realm: { id: REALM_A } });
    const inB = realmRateLimitKey({ ip: '203.0.113.7', realm: { id: REALM_B } });

    expect(inA).not.toBe(inB);
  });

  it('keys an IPv6 client by its /64 within the realm, as clientAddressKey does', () => {
    expect(realmRateLimitKey({ ip: '2001:db8:1:2::1', realm: { id: REALM_A } })).toBe(
      realmRateLimitKey({ ip: '2001:db8:1:2:ffff::9', realm: { id: REALM_A } })
    );
  });

  it('keys a request with no realm by its address alone', () => {
    expect(realmRateLimitKey({ ip: '203.0.113.7', realm: null })).toBe('203.0.113.7');
    expect(realmRateLimitKey({ ip: '203.0.113.7' })).toBe('203.0.113.7');
    expect(realmRateLimitKey({})).toBe('unknown');
  });
});
