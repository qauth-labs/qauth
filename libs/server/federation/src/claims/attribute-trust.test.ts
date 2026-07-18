import { describe, expect, it } from 'vitest';

import { rankAttributeSource, selectTrustedAttribute } from './attribute-trust';

const NOW = 1_700_000_000_000;

function row(source: string, attrValue = `${source}@example.com`, expiresAt?: number | null) {
  return { source, attrValue, expiresAt };
}

describe('rankAttributeSource (ADR-002 trust order)', () => {
  it('ranks wallet > oidc_* > self_reported > unknown', () => {
    expect(rankAttributeSource('wallet')).toBe(3);
    expect(rankAttributeSource('oidc_google')).toBe(2);
    expect(rankAttributeSource('oidc_azure')).toBe(2);
    expect(rankAttributeSource('self_reported')).toBe(1);
    expect(rankAttributeSource('carrier_pigeon')).toBe(0);
  });

  it('the oidc_ family is a prefix match, not an allowlist', () => {
    expect(rankAttributeSource('oidc_anything_future')).toBe(2);
    // 'oidc' without the underscore is NOT the family.
    expect(rankAttributeSource('oidc')).toBe(0);
  });
});

describe('selectTrustedAttribute', () => {
  it('walks the full trust chain as higher sources disappear', () => {
    const wallet = row('wallet');
    const oidc = row('oidc_google');
    const self = row('self_reported');

    expect(selectTrustedAttribute([self, oidc, wallet], NOW)).toBe(wallet);
    expect(selectTrustedAttribute([self, oidc], NOW)).toBe(oidc);
    expect(selectTrustedAttribute([self], NOW)).toBe(self);
    expect(selectTrustedAttribute([], NOW)).toBeUndefined();
  });

  it('breaks intra-rank ties lexicographically by source ascending', () => {
    const azure = row('oidc_azure');
    const google = row('oidc_google');
    // Input order must not matter.
    expect(selectTrustedAttribute([google, azure], NOW)).toBe(azure);
    expect(selectTrustedAttribute([azure, google], NOW)).toBe(azure);
  });

  it('an unknown source loses to self_reported but wins when it is the only row', () => {
    const unknown = row('carrier_pigeon');
    const self = row('self_reported');
    expect(selectTrustedAttribute([unknown, self], NOW)).toBe(self);
    expect(selectTrustedAttribute([unknown], NOW)).toBe(unknown);
  });

  it('excludes rows expiring exactly at now (boundary) and earlier', () => {
    expect(selectTrustedAttribute([row('wallet', 'w@x.co', NOW)], NOW)).toBeUndefined();
    expect(selectTrustedAttribute([row('wallet', 'w@x.co', NOW - 1)], NOW)).toBeUndefined();
    expect(selectTrustedAttribute([row('wallet', 'w@x.co', NOW + 1)], NOW)?.attrValue).toBe(
      'w@x.co'
    );
  });

  it('null or absent expiresAt never expires', () => {
    expect(selectTrustedAttribute([row('self_reported', 's@x.co', null)], NOW)).toBeDefined();
    expect(
      selectTrustedAttribute([{ source: 'self_reported', attrValue: 's@x.co' }], NOW)
    ).toBeDefined();
  });

  it('falls through to the next rank when the top-ranked row is expired', () => {
    const expiredWallet = row('wallet', 'w@x.co', NOW - 1);
    const self = row('self_reported');
    expect(selectTrustedAttribute([expiredWallet, self], NOW)).toBe(self);
  });

  it('does not mutate the input array', () => {
    const rows = [row('self_reported'), row('wallet')];
    const snapshot = [...rows];
    selectTrustedAttribute(rows, NOW);
    expect(rows).toEqual(snapshot);
  });
});
