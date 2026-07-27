import { describe, expect, it, vi } from 'vitest';

// The helper reads only `ACR_VALUE_STYLE`. Mocked so the test does not trigger
// full env parsing (DATABASE_URL etc. are unset here) and so the deployment's
// vocabulary can be varied per test — same pattern as `error-handler.test.ts`.
const envMock = { ACR_VALUE_STYLE: 'eidas-uri' as string };
vi.mock('../../config/env', () => ({
  get env() {
    return envMock;
  },
}));

import { resolveAcrClaims, toStoredAssuranceLevel } from './acr-claims';

describe('resolveAcrClaims (#237, ADR-004/ADR-010)', () => {
  it('emits an acr claim for a substantial-assurance authentication', () => {
    expect(resolveAcrClaims('substantial')).toEqual({
      acr: 'http://eidas.europa.eu/LoA/substantial',
    });
  });

  it('emits an acr claim for a high-assurance authentication', () => {
    expect(resolveAcrClaims('high')).toEqual({ acr: 'http://eidas.europa.eu/LoA/high' });
  });

  it('emits NO acr claim for a password login', () => {
    // The invariant #237 and #240 both assert, and the one this whole helper
    // exists to keep: a password credential is `'low'` (ADR-003) and its ID
    // token carries no `acr` at all. An RP may gate on PRESENCE, so a "low"
    // value here would not be cosmetic — it would tell every RP that every
    // password session is assured.
    expect(resolveAcrClaims('low')).toEqual({});
  });

  it('emits no acr claim when the authorization code recorded no level', () => {
    // NULL column — the password path, the Bearer path, and every wallet login
    // whose issuer the realm assures nothing about.
    expect(resolveAcrClaims(null)).toEqual({});
    expect(resolveAcrClaims(undefined)).toEqual({});
  });

  it.each([
    ['an unknown level', 'medium'],
    ['an upper-cased level', 'HIGH'],
    ['a rendered acr value stored by mistake', 'http://eidas.europa.eu/LoA/high'],
    ['an empty string', ''],
  ])(
    'emits no acr claim for %s — an assertion QAuth cannot read is one it must not make',
    (_label, stored) => {
      expect(resolveAcrClaims(stored)).toEqual({});
    }
  );

  it('renders in the deployment vocabulary, resolved at issuance rather than at mint time', () => {
    envMock.ACR_VALUE_STYLE = 'loa-name';
    try {
      expect(resolveAcrClaims('high')).toEqual({ acr: 'high' });
      // The absence rule is vocabulary-independent.
      expect(resolveAcrClaims('low')).toEqual({});
    } finally {
      envMock.ACR_VALUE_STYLE = 'eidas-uri';
    }
  });

  it('falls back to the default vocabulary rather than throwing on a bad style', () => {
    // This runs on the token path; a configuration value that slipped past
    // validation must not turn a valid issuance into a 500.
    envMock.ACR_VALUE_STYLE = 'eidas-saml';
    try {
      expect(resolveAcrClaims('high')).toEqual({ acr: 'http://eidas.europa.eu/LoA/high' });
    } finally {
      envMock.ACR_VALUE_STYLE = 'eidas-uri';
    }
  });
});

describe('toStoredAssuranceLevel (#237)', () => {
  it.each(['substantial', 'high'] as const)('stores %s verbatim', (level) => {
    expect(toStoredAssuranceLevel(level)).toBe(level);
  });

  it.each([
    ['low', 'low'],
    ['undefined', undefined],
    ['null', null],
    ['an unknown level', 'medium'],
    ['a boolean', true],
    ['an object', { level: 'high' }],
  ])('stores NULL for %s so "no assurance" has one representation', (_label, level) => {
    expect(toStoredAssuranceLevel(level)).toBeNull();
  });

  it('never stores low — NULL is the only unassured value the column may hold', () => {
    // The database CHECK constraint enforces the same rule; this keeps the
    // application from ever attempting the write.
    expect(toStoredAssuranceLevel('low')).not.toBe('low');
  });
});
