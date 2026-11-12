import { describe, expect, it } from 'vitest';

import {
  isOperatorVerified,
  OPERATOR_VERIFIED_BY_PATTERN,
  operatorVerifiedBy,
  parseOperatorVerifiedBy,
} from './operator-verification';

const ACCOUNT = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';

describe("an operator's verification of an account (#1052)", () => {
  it('stores the admin account, in lower case, and the operating-system user of the CLI', () => {
    expect(operatorVerifiedBy({ method: 'operator', accountId: ACCOUNT.toUpperCase() })).toBe(
      `operator:${ACCOUNT}`
    );
    expect(operatorVerifiedBy({ method: 'operator_cli', osUser: 'root' })).toBe(
      'operator_cli:root'
    );
    expect(operatorVerifiedBy({ method: 'operator_cli', osUser: null })).toBe('operator_cli');
  });

  it('reads back what it stores, and nothing else', () => {
    expect(parseOperatorVerifiedBy(`operator:${ACCOUNT}`)).toEqual({
      method: 'operator',
      accountId: ACCOUNT,
    });
    expect(parseOperatorVerifiedBy('operator_cli:deploy user')).toEqual({
      method: 'operator_cli',
      osUser: 'deploy user',
    });
    expect(parseOperatorVerifiedBy('operator_cli')).toEqual({
      method: 'operator_cli',
      osUser: null,
    });
    for (const value of [
      'operator',
      'operator:',
      'operator:not-a-uuid',
      `operator:${ACCOUNT.toUpperCase()}`,
      'operator_cli:',
      'operator_cli:a\nb',
      `operator_cli:${'x'.repeat(256)}`,
      'admin:root',
      '',
    ]) {
      expect(parseOperatorVerifiedBy(value), value).toBeNull();
      expect(OPERATOR_VERIFIED_BY_PATTERN.test(value), value).toBe(false);
    }
  });

  it('refuses to form what the column refuses', () => {
    expect(() => operatorVerifiedBy({ method: 'operator', accountId: 'root' })).toThrow(TypeError);
    expect(() => operatorVerifiedBy({ method: 'operator_cli', osUser: '' })).toThrow(TypeError);
    expect(() => operatorVerifiedBy({ method: 'operator_cli', osUser: 'a\u0000b' })).toThrow(
      TypeError
    );
    expect(() => operatorVerifiedBy({ method: 'operator_cli', osUser: 'x'.repeat(256) })).toThrow(
      TypeError
    );
  });

  it('counts an account as operator-verified only with a time', () => {
    expect(isOperatorVerified({ operatorVerifiedAt: 1_700_000_000_000 })).toBe(true);
    expect(isOperatorVerified({ operatorVerifiedAt: null })).toBe(false);
    expect(isOperatorVerified({})).toBe(false);
  });
});
