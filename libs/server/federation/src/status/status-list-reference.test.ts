import { describe, expect, it } from 'vitest';

import { parseStatusListReference } from './status-list-reference';

const uri = 'https://issuer.example/statuslists/1';

describe('parseStatusListReference (#297)', () => {
  it('extracts idx and uri from a well-formed status claim', () => {
    expect(parseStatusListReference({ status_list: { idx: 42, uri } })).toEqual({ idx: 42, uri });
  });

  it('accepts index zero', () => {
    // `0` is falsy and is the single most likely index to be dropped by a
    // truthiness check somewhere in the chain.
    expect(parseStatusListReference({ status_list: { idx: 0, uri } })).toEqual({ idx: 0, uri });
  });

  it('keeps the uri VERBATIM so the token `sub` comparison stays byte-exact', () => {
    // Trailing slash, mixed-case path, query string: draft-14 §6 compares this
    // value to `sub` unchanged, so canonicalizing here would break real tokens.
    const raw = 'https://Issuer.example/Status/List/?v=2';
    expect(parseStatusListReference({ status_list: { idx: 1, uri: raw } })?.uri).toBe(raw);
  });

  it('trims surrounding whitespace exactly once, so fetch and `sub` agree', () => {
    expect(parseStatusListReference({ status_list: { idx: 1, uri: `  ${uri}\n` } })?.uri).toBe(uri);
  });

  it('ignores other status mechanisms alongside status_list', () => {
    const parsed = parseStatusListReference({
      status_list: { idx: 3, uri },
      other_mechanism: { whatever: true },
    });
    expect(parsed).toEqual({ idx: 3, uri });
  });

  it.each([
    ['a non-object status claim', 'not-an-object'],
    ['null', null],
    ['an array', [{ idx: 0, uri }]],
    ['no status_list member', { some_other: { idx: 0, uri } }],
    ['a non-object status_list', { status_list: 'nope' }],
    ['an array status_list', { status_list: [{ idx: 0, uri }] }],
    ['a missing idx', { status_list: { uri } }],
    ['a string idx', { status_list: { idx: '1', uri } }],
    ['a negative idx', { status_list: { idx: -1, uri } }],
    ['a fractional idx', { status_list: { idx: 1.5, uri } }],
    ['a non-safe-integer idx', { status_list: { idx: 2 ** 53, uri } }],
    ['NaN idx', { status_list: { idx: Number.NaN, uri } }],
    ['a missing uri', { status_list: { idx: 0 } }],
    ['a non-string uri', { status_list: { idx: 0, uri: 5 } }],
    ['a blank uri', { status_list: { idx: 0, uri: '   ' } }],
    ['an over-long uri', { status_list: { idx: 0, uri: `https://a.example/${'x'.repeat(3000)}` } }],
  ])('returns undefined for %s', (_label, status) => {
    expect(parseStatusListReference(status)).toBeUndefined();
  });

  it.each([
    ['undefined', undefined],
    ['a symbol', Symbol('x')],
    ['a function', (): void => undefined],
  ])('returns undefined rather than throwing for %s', (_label, value) => {
    expect(() => parseStatusListReference(value)).not.toThrow();
    expect(parseStatusListReference(value)).toBeUndefined();
  });
});
