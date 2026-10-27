import { describe, expect, it } from 'vitest';

import {
  isSecurityEffect,
  SECURITY_EFFECT_DESCRIPTIONS,
  SECURITY_EFFECTS,
  type SecurityEffect,
} from './security-effects';

describe('the security effect tags (#508)', () => {
  it('are the eleven tags of ADR-019 Decision 7 and #508, in order', () => {
    expect(SECURITY_EFFECTS).toEqual([
      'credential-path',
      'token-content',
      'issue-for-other',
      'administration',
      'import',
      'federation-operator',
      'key-custody',
      'realm-lifecycle',
      'authority-tree-power',
      'posture-loosening',
      'bulk-revocation',
    ]);
  });

  it('is a closed list that cannot be extended at run time', () => {
    expect(Object.isFrozen(SECURITY_EFFECTS)).toBe(true);
    expect(() => (SECURITY_EFFECTS as unknown as string[]).push('anything')).toThrow(TypeError);
    expect(Object.isFrozen(SECURITY_EFFECT_DESCRIPTIONS)).toBe(true);
  });

  it('are kebab-case, as the API conventions require of x-qauth-effects', () => {
    for (const effect of SECURITY_EFFECTS) {
      expect(effect).toMatch(/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/);
    }
  });

  it('describe each tag in exactly one line, and nothing else', () => {
    expect(Object.keys(SECURITY_EFFECT_DESCRIPTIONS)).toEqual([...SECURITY_EFFECTS]);
    for (const description of Object.values(SECURITY_EFFECT_DESCRIPTIONS)) {
      expect(description).toMatch(/^[A-Z][^\n]*\.$/);
    }
  });

  it.each(SECURITY_EFFECTS)('knows %s', (effect) => {
    expect(isSecurityEffect(effect)).toBe(true);
  });

  it.each([
    'Credential-Path',
    'credential-path ',
    'credential_path',
    'security',
    '',
    'toString',
    '__proto__',
    'constructor',
  ])('does not know %j', (value) => {
    expect(isSecurityEffect(value)).toBe(false);
  });

  it('refuses a value that is not a string', () => {
    for (const value of [undefined, null, 1, ['credential-path'], { effect: 'import' }]) {
      expect(isSecurityEffect(value)).toBe(false);
    }
  });

  it('narrows the type', () => {
    const value: unknown = 'key-custody';
    if (isSecurityEffect(value)) {
      const effect: SecurityEffect = value;
      expect(effect).toBe('key-custody');
    }
  });
});
