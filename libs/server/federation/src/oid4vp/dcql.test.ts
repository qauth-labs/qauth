import { describe, expect, it } from 'vitest';

import {
  assertValidDcqlQuery,
  type DcqlQuery,
  MAX_DCQL_CREDENTIAL_QUERIES,
  parseStoredDcqlQuery,
} from './dcql';

function query(ids: readonly string[]): DcqlQuery {
  return { credentials: ids.map((id) => ({ id, format: 'dc+sd-jwt' as const })) };
}

describe('assertValidDcqlQuery', () => {
  it('accepts a conformant query', () => {
    expect(() => assertValidDcqlQuery(query(['pid', 'employee_badge', 'a-b_C9']))).not.toThrow();
  });

  it('rejects an empty query', () => {
    expect(() => assertValidDcqlQuery(query([]))).toThrow(/at least one Credential Query/);
  });

  it('rejects duplicate Credential Query ids (they key the vp_token map)', () => {
    expect(() => assertValidDcqlQuery(query(['pid', 'pid']))).toThrow(/duplicated/);
  });

  it.each(['with space', 'dots.not.allowed', 'slash/', '', 'ünicode'])(
    "rejects the non-conformant id '%s' (§6.1)",
    (id) => {
      expect(() => assertValidDcqlQuery(query([id]))).toThrow(/not conformant/);
    }
  );

  it('rejects a query above the self-imposed Credential Query bound', () => {
    const ids = Array.from({ length: MAX_DCQL_CREDENTIAL_QUERIES + 1 }, (_, i) => `q${i}`);

    expect(() => assertValidDcqlQuery(query(ids))).toThrow(/at most/);
  });
});

describe('parseStoredDcqlQuery', () => {
  it('round-trips a persisted query', () => {
    const stored = JSON.parse(JSON.stringify(query(['pid']))) as unknown;

    expect(parseStoredDcqlQuery(stored)).toEqual(query(['pid']));
  });

  it.each([
    ['a JSON array', []],
    ['null', null],
    ['a string', 'pid'],
    ['an object without credentials', { foo: 1 }],
    ['credentials that is not an array', { credentials: {} }],
    ['a non-object Credential Query', { credentials: ['pid'] }],
    ['a Credential Query without a string id', { credentials: [{ format: 'dc+sd-jwt' }] }],
    ['a Credential Query without a string format', { credentials: [{ id: 'pid' }] }],
  ])('refuses %s rather than failing deep inside response correlation', (_label, value) => {
    expect(() => parseStoredDcqlQuery(value)).toThrow();
  });
});
