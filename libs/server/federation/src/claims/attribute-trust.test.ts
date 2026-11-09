import { describe, expect, it } from 'vitest';

import {
  isUpstreamPresetProvenance,
  rankAttributeSource,
  selectTrustedAttribute,
  UPSTREAM_PRESET_PROVENANCE,
} from './attribute-trust';

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

  // #671: by how the method that wrote the row was built, never by a
  // provider's name.
  it("ranks a row of a method the loader built from a preset with oidc_*, and a plain plugin's as unknown", () => {
    expect(rankAttributeSource('example_idp', UPSTREAM_PRESET_PROVENANCE)).toBe(2);
    // A JSON round trip, as the row comes back from the database.
    expect(
      rankAttributeSource('example_idp', JSON.parse(JSON.stringify(UPSTREAM_PRESET_PROVENANCE)))
    ).toBe(2);
    expect(rankAttributeSource('example_idp')).toBe(0);
    expect(rankAttributeSource('corp_sso', null)).toBe(0);
    expect(rankAttributeSource('corp_sso', { builtFrom: 'auth-method' })).toBe(0);
    expect(rankAttributeSource('corp_sso', ['upstream-oidc-preset'])).toBe(0);
    // The provenance never changes the rank of QAuth's own sources.
    expect(rankAttributeSource('wallet', UPSTREAM_PRESET_PROVENANCE)).toBe(3);
    expect(rankAttributeSource('self_reported', UPSTREAM_PRESET_PROVENANCE)).toBe(1);
  });

  it('reads only the provenance it wrote', () => {
    expect(isUpstreamPresetProvenance(UPSTREAM_PRESET_PROVENANCE)).toBe(true);
    expect(isUpstreamPresetProvenance({ builtFrom: 'upstream-oidc-preset', more: 1 })).toBe(true);
    expect(isUpstreamPresetProvenance('upstream-oidc-preset')).toBe(false);
    expect(isUpstreamPresetProvenance(undefined)).toBe(false);
    expect(Object.isFrozen(UPSTREAM_PRESET_PROVENANCE)).toBe(true);
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

  it("ranks each row by its own provenance: a preset-built method's beats self_reported (#671)", () => {
    const preset = { ...row('example_idp'), provenance: UPSTREAM_PRESET_PROVENANCE };
    const plain = { ...row('corp_sso'), provenance: null };
    const self = row('self_reported');
    expect(selectTrustedAttribute([self, preset], NOW)).toBe(preset);
    expect(selectTrustedAttribute([self, plain], NOW)).toBe(self);
    // Within the rank, the lexicographic tie-break holds.
    const oidc = row('oidc_corp');
    expect(selectTrustedAttribute([preset, oidc], NOW)).toBe(preset);
  });

  it('does not mutate the input array', () => {
    const rows = [row('self_reported'), row('wallet')];
    const snapshot = [...rows];
    selectTrustedAttribute(rows, NOW);
    expect(rows).toEqual(snapshot);
  });
});
