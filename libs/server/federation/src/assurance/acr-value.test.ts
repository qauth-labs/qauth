import { describe, expect, it } from 'vitest';

import type { AssuranceLevel } from '../providers/credential-provider.interface';
import {
  type AcrValueStyle,
  DEFAULT_ACR_VALUE_STYLE,
  EIDAS_LOA_ACR_VALUES,
  LOA_NAME_ACR_VALUES,
  parseAcrValueStyle,
  resolveAcrValue,
  supportedAcrValues,
} from './acr-value';

describe('resolveAcrValue (ADR-010 eIDAS LoA → acr mapping, #237)', () => {
  it('emits NO acr value for low assurance — the invariant password logins rest on', () => {
    // ADR-003/ADR-004 and #240 all assert this: a password login is `'low'` and
    // must carry no `acr` claim at all. Emitting `.../LoA/low` would assert an
    // eIDAS level QAuth never established, and every RP gating on "is acr
    // present" would then read every session as assured.
    expect(resolveAcrValue('low')).toBeUndefined();
    expect(resolveAcrValue('low', 'eidas-uri')).toBeUndefined();
    expect(resolveAcrValue('low', 'loa-name')).toBeUndefined();
  });

  it('emits no acr value when no level was established at all', () => {
    expect(resolveAcrValue(undefined)).toBeUndefined();
    expect(resolveAcrValue(null)).toBeUndefined();
  });

  it('emits the eIDAS LoA URI by default', () => {
    expect(resolveAcrValue('substantial')).toBe('http://eidas.europa.eu/LoA/substantial');
    expect(resolveAcrValue('high')).toBe('http://eidas.europa.eu/LoA/high');
  });

  it('emits the bare LoA name under the loa-name style', () => {
    expect(resolveAcrValue('substantial', 'loa-name')).toBe('substantial');
    expect(resolveAcrValue('high', 'loa-name')).toBe('high');
  });

  it('keeps the eIDAS URIs on http: — they are identifiers, not locations', () => {
    // Rewriting these to https: produces a different string that no
    // eIDAS-aware RP recognises. Pinned so a well-meaning "fix the http URL"
    // sweep has to argue with a test.
    expect(EIDAS_LOA_ACR_VALUES.substantial.startsWith('http://')).toBe(true);
    expect(EIDAS_LOA_ACR_VALUES.high.startsWith('http://')).toBe(true);
  });

  it('defaults to the URI form, which is what OIDC Core §2 asks an acr value to be', () => {
    expect(DEFAULT_ACR_VALUE_STYLE).toBe('eidas-uri');
    expect(resolveAcrValue('high')).toBe(EIDAS_LOA_ACR_VALUES.high);
  });

  it('falls back to the default style rather than throwing on an unknown style', () => {
    // This runs on the token-issuance path. A configuration value that slipped
    // past validation must not turn a valid issuance into a 500.
    const bogus = 'eidas-saml' as AcrValueStyle;

    expect(resolveAcrValue('high', bogus)).toBe(EIDAS_LOA_ACR_VALUES.high);
  });

  it.each([
    ['an unknown level string', 'medium'],
    ['an upper-cased level', 'HIGH'],
    ['a boolean', true],
    ['a number', 3],
    ['an object', { level: 'high' }],
  ] as const)('emits no acr value for %s smuggled past the type', (_label, value) => {
    // An ALLOWLIST of the two bearing levels, not a `!== 'low'` check: a cast
    // anywhere upstream must not be able to conjure an assurance claim.
    expect(resolveAcrValue(value as unknown as AssuranceLevel)).toBeUndefined();
  });
});

describe('parseAcrValueStyle (#237)', () => {
  it('accepts the two documented vocabularies', () => {
    expect(parseAcrValueStyle('eidas-uri')).toBe('eidas-uri');
    expect(parseAcrValueStyle('loa-name')).toBe('loa-name');
  });

  it.each([
    ['an unknown name', 'eidas-saml'],
    ['a blank string', ''],
    ['undefined', undefined],
    ['null', null],
    ['a number', 1],
  ] as const)('refuses %s rather than guessing a vocabulary', (_label, value) => {
    expect(parseAcrValueStyle(value)).toBeUndefined();
  });
});

describe('supportedAcrValues (#237)', () => {
  it('lists exactly the two values that can be emitted, ascending', () => {
    expect(supportedAcrValues('eidas-uri')).toEqual([
      EIDAS_LOA_ACR_VALUES.substantial,
      EIDAS_LOA_ACR_VALUES.high,
    ]);
    expect(supportedAcrValues('loa-name')).toEqual([
      LOA_NAME_ACR_VALUES.substantial,
      LOA_NAME_ACR_VALUES.high,
    ]);
  });

  it('never advertises a value for low assurance', () => {
    for (const style of ['eidas-uri', 'loa-name'] as const) {
      expect(supportedAcrValues(style)).not.toContain('low');
      expect(supportedAcrValues(style)).not.toContain('http://eidas.europa.eu/LoA/low');
    }
  });
});
