import { describe, expect, it } from 'vitest';

import { formatKekRef, parseKekRef, transitKeyPath } from './kek-ref';

describe('kekRef', () => {
  it('names the Transit key path and the version', () => {
    expect(formatKekRef(transitKeyPath(undefined, 'transit', 'qauth-kek'), 3)).toBe(
      'vault:transit/keys/qauth-kek#v3'
    );
    expect(formatKekRef(transitKeyPath('org/team-a', 'kek/transit', 'k@1'), 12)).toBe(
      'vault:org/team-a/kek/transit/keys/k@1#v12'
    );
  });

  it('reads back what it formats', () => {
    expect(parseKekRef('vault:org/team-a/transit/keys/qauth-kek#v41')).toEqual({
      keyPath: 'org/team-a/transit/keys/qauth-kek',
      version: 41,
    });
  });

  it.each([
    'transit/keys/qauth-kek#v1',
    'vault:transit/keys/qauth-kek',
    'vault:#v1',
    'vault:transit/keys/qauth-kek#v0',
    'vault:transit/keys/qauth-kek#v01',
    'vault:transit/keys/qauth-kek#v1x',
    'vault:transit/keys/qauth-kek#v99999999999',
    'vault:transit/keys/qauth-kek#v2147483648',
  ])('reads %s as no Vault kekRef', (kekRef) => {
    expect(parseKekRef(kekRef)).toBeUndefined();
  });

  it('refuses a version that is not a positive integer', () => {
    expect(() => formatKekRef('transit/keys/k', 0)).toThrow(RangeError);
    expect(() => formatKekRef('transit/keys/k', 1.5)).toThrow(RangeError);
  });
});
