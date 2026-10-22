import { describe, expect, it } from 'vitest';

import { canonicalizeJson } from './canonical-json';

/**
 * RFC 8785 conformance for the canonicalizer the admin audit log hashes with
 * (issue #448). The vectors are the RFC's own: §3.2.2 for serialization,
 * §3.2.3 for member order, Appendix B for numbers.
 */
describe('canonicalizeJson', () => {
  it('serializes the RFC 8785 §3.2.2 example', () => {
    const input = String.raw`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}`;
    const expected = String.raw`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`;

    expect(canonicalizeJson(JSON.parse(input))).toBe(expected);
  });

  it('sorts members by UTF-16 code units (RFC 8785 §3.2.3)', () => {
    const input = String.raw`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`;
    const expected =
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis",' +
      '"\u20ac":"Euro Sign","\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}';

    expect(canonicalizeJson(JSON.parse(input))).toBe(expected);
  });

  it.each([
    [0, '0'],
    [-0, '0'],
    [1, '1'],
    [-1.5, '-1.5'],
    [0.000001, '0.000001'],
    [1e-7, '1e-7'],
    [1e21, '1e+21'],
    [5e-324, '5e-324'],
    [1.7976931348623157e308, '1.7976931348623157e+308'],
    [9007199254740992, '9007199254740992'],
    [295147905179352830000, '295147905179352830000'],
  ])('serializes the number %s as %s (RFC 8785 Appendix B)', (value, expected) => {
    expect(canonicalizeJson(value)).toBe(expected);
  });

  it('writes no whitespace and keeps array order', () => {
    expect(canonicalizeJson({ b: [3, 1, { d: 1, c: [] }], a: {} })).toBe(
      '{"a":{},"b":[3,1,{"c":[],"d":1}]}'
    );
  });

  it('gives the same text whatever the member order of the input', () => {
    expect(canonicalizeJson({ a: 1, b: { x: true, y: null } })).toBe(
      canonicalizeJson({ b: { y: null, x: true }, a: 1 })
    );
  });

  it('leaves out a member whose value is undefined, as JSON.stringify does', () => {
    expect(canonicalizeJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it('keeps a member named __proto__', () => {
    expect(canonicalizeJson(JSON.parse('{"__proto__":{"a":1},"b":2}'))).toBe(
      '{"__proto__":{"a":1},"b":2}'
    );
  });

  it('accepts an object without a prototype', () => {
    const value = Object.assign(Object.create(null) as Record<string, unknown>, { a: 1 });
    expect(canonicalizeJson(value)).toBe('{"a":1}');
  });

  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['undefined', undefined],
    ['a bigint', 1n],
    ['a function', () => 1],
    ['a symbol', Symbol('s')],
    ['a Date', new Date(0)],
    ['a Buffer', Buffer.from('a')],
    ['a Map', new Map()],
    ['undefined inside an array', [1, undefined]],
    // eslint-disable-next-line no-sparse-arrays
    ['a hole in an array', [1, , 3]],
    ['an array with no elements set', new Array(2)],
    ['a lone high surrogate', '\ud800'],
    ['a lone low surrogate', 'a\udc00b'],
    ['a lone surrogate in a member name', { '\ud800': 1 }],
    ['a nested non-JSON value', { a: [{ b: new Date(0) }] }],
  ])('refuses %s', (_label, value) => {
    expect(() => canonicalizeJson(value)).toThrow(TypeError);
  });
});
