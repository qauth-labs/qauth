import { describe, expect, it } from 'vitest';

import { DpopProofError } from './dpop-error';
import { dpopRequestUrl, hasPlainPath, normalizeHtu } from './htu';

/** The `htu` comparison form (RFC 9449 §4.3 step 9, RFC 3986 §6.2.2 and §6.2.3). */
describe('normalizeHtu', () => {
  it.each([
    ['https://server.example.com/token', 'https://server.example.com/token'],
    ['HTTPS://SERVER.Example.COM/token', 'https://server.example.com/token'],
    ['https://server.example.com:443/token', 'https://server.example.com/token'],
    ['http://server.example.com:80/token', 'http://server.example.com/token'],
    ['https://server.example.com:8443/token', 'https://server.example.com:8443/token'],
    ['https://server.example.com', 'https://server.example.com/'],
    ['https://server.example.com/a/./b/../token', 'https://server.example.com/a/token'],
    ['https://server.example.com/%7Euser/%74oken', 'https://server.example.com/~user/token'],
    ['https://server.example.com/a%2fb', 'https://server.example.com/a%2Fb'],
    ['https://server.example.com/token?x=1#frag', 'https://server.example.com/token'],
  ])('%s compares as %s', (input, expected) => {
    expect(normalizeHtu(input)).toBe(expected);
  });

  it('keeps the case of the path, which is significant', () => {
    expect(normalizeHtu('https://server.example.com/Token')).not.toBe(
      normalizeHtu('https://server.example.com/token')
    );
  });

  it.each([
    'token',
    '/token',
    'ftp://server.example.com/token',
    'urn:example:token',
    'https://user:pass@server.example.com/token',
    'https://user@server.example.com/token',
    'https://',
  ])('refuses %s', (input) => {
    expect(normalizeHtu(input)).toBeUndefined();
  });
});

describe('hasPlainPath', () => {
  it.each([
    'https://server.example.com/token',
    'https://server.example.com',
    'https://server.example.com/a.b/..c/%2e%2e%2e/token',
    'https://server.example.com/token?next=/../admin#/./x',
  ])('accepts %s', (url) => {
    expect(hasPlainPath(url)).toBe(true);
  });

  it.each([
    'https://server.example.com/a/../token',
    'https://server.example.com/a/..',
    'https://server.example.com/./token',
    'https://server.example.com/a/%2E%2e/token',
    'https://server.example.com/a/.%2e/token',
    'https://server.example.com/a/%2e/token',
    'https://server.example.com/a\\token',
    'https://server.example.com\\..\\token',
    '/token',
  ])('refuses %s', (url) => {
    expect(hasPlainPath(url)).toBe(false);
  });
});

describe('dpopRequestUrl', () => {
  it("joins the server's own origin and the request path, without the query", () => {
    expect(dpopRequestUrl('https://auth.example.com', '/oauth/token?x=1#f')).toBe(
      'https://auth.example.com/oauth/token'
    );
    expect(dpopRequestUrl('https://Auth.Example.com:443/realms/acme', '/oauth/token')).toBe(
      'https://auth.example.com/oauth/token'
    );
  });

  it.each([
    ['an absolute-form target', 'https://attacker.example/oauth/token'],
    ['a scheme-relative target', '//attacker.example/oauth/token'],
    ['an asterisk-form target', '*'],
    ['an empty target', ''],
  ])('refuses %s with htu, so the client never chooses the origin', (_label, target) => {
    let error: unknown;
    try {
      dpopRequestUrl('https://auth.example.com', target);
    } catch (thrown) {
      error = thrown;
    }
    expect(error).toBeInstanceOf(DpopProofError);
    expect((error as DpopProofError).reason).toBe('htu');
  });

  it('throws when the origin is not an http(s) URL', () => {
    expect(() => dpopRequestUrl('auth.example.com', '/token')).toThrow(TypeError);
    expect(() => dpopRequestUrl('ftp://auth.example.com', '/token')).toThrow(TypeError);
  });
});
