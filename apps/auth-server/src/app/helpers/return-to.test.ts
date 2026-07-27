import { describe, expect, it } from 'vitest';

import { isSafeReturnTo, resolveReturnTo } from './return-to';

/**
 * The `return_to` open-redirect guard.
 *
 * Everything this accepts is somewhere the server will send a user who has just
 * authenticated — via `reply.redirect()` on the no-JavaScript paths and via
 * `window.location.assign()` on the wallet-login poll — so the interesting half
 * of this suite is the rejections.
 */

/** The origin a browser would be resolving a `Location` header against. */
const BASE = 'https://auth.example.com';

/**
 * Characters the WHATWG URL parser removes from a URL BEFORE parsing it. They
 * are spelled out here because that is exactly what a guard reading the raw
 * string cannot see: each one hides a protocol-relative value behind an
 * apparently single leading `/`.
 */
const DISCARDED_BY_THE_URL_PARSER: ReadonlyArray<[string, string]> = [
  ['tab', '\t'],
  ['line feed', '\n'],
  ['carriage return', '\r'],
];

describe('isSafeReturnTo — accepted values', () => {
  it.each([
    '/',
    '/oauth/authorize?client_id=abc&scope=openid',
    `/ui/resume/${'A'.repeat(43)}`,
    '/ui/consent?client_id=abc',
    '/deep/multi/segment/path',
    '/path#fragment',
    // A cross-origin URL inside the QUERY is not a cross-origin destination:
    // the browser still lands here, and this server re-validates it.
    '/oauth/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcb',
  ])('accepts the same-origin relative path %j', (value) => {
    expect(isSafeReturnTo(value)).toBe(true);
    expect(resolveReturnTo(value)).toBe(value);
  });
});

describe('isSafeReturnTo — rejected values', () => {
  it.each([
    'https://evil.example/steal',
    'http://evil.example',
    '//evil.example',
    '//evil.example/steal',
    '/\\evil.example',
    '/\\evil.example/steal',
    '\\\\evil.example',
    'javascript:alert(1)',
    'relative/path',
    '',
  ])('rejects %j and falls back to "/"', (value) => {
    expect(isSafeReturnTo(value)).toBe(false);
    expect(resolveReturnTo(value)).toBe('/');
  });

  it.each([undefined, null, 42, {}, [], true])('rejects the non-string %j', (value) => {
    expect(isSafeReturnTo(value)).toBe(false);
    expect(resolveReturnTo(value)).toBe('/');
  });
});

/**
 * The bypass the two prefix checks above exist to stop, spelled a third way.
 *
 * Each case is asserted twice on purpose: first that a browser really does
 * resolve it cross-origin (Node's URL implementation is the same algorithm), so
 * the test cannot rot into asserting a rejection nobody needs, and then that the
 * guard refuses it.
 */
describe('isSafeReturnTo — characters the URL parser discards before parsing', () => {
  it.each(DISCARDED_BY_THE_URL_PARSER)('rejects a %s between the slashes', (_name, character) => {
    const protocolRelative = `/${character}/example.invalid`;
    const backslashSpelling = `/${character}\\example.invalid`;

    expect(new URL(protocolRelative, BASE).origin).toBe('https://example.invalid');
    expect(new URL(backslashSpelling, BASE).origin).toBe('https://example.invalid');

    expect(isSafeReturnTo(protocolRelative)).toBe(false);
    expect(isSafeReturnTo(backslashSpelling)).toBe(false);
    expect(resolveReturnTo(protocolRelative)).toBe('/');
    expect(resolveReturnTo(backslashSpelling)).toBe('/');
  });

  it.each(DISCARDED_BY_THE_URL_PARSER)(
    'rejects a leading %s that would be trimmed away',
    (_name, character) => {
      expect(isSafeReturnTo(`${character}//example.invalid`)).toBe(false);
      expect(isSafeReturnTo(`${character}/ui/consent`)).toBe(false);
    }
  );

  it('rejects the whole C0-plus-space class, not only the three stripped characters', () => {
    for (let code = 0x00; code <= 0x20; code += 1) {
      const character = String.fromCharCode(code);
      expect(isSafeReturnTo(`/${character}/example.invalid`)).toBe(false);
      expect(isSafeReturnTo(`/ui/consent${character}`)).toBe(false);
    }
    expect(isSafeReturnTo('/ui/consent?a=b c')).toBe(false);
  });
});
