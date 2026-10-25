import { describe, expect, it } from 'vitest';

import { normalizeHtu } from './htu';

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
