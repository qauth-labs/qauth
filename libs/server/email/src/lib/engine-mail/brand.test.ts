import { describe, expect, it } from 'vitest';

import { DEFAULT_MAIL_BRAND, isSameOriginPath, resolveMailBrand } from './brand';
import { isMailBaseUrl, isMailPass, mailLink, mailPassUrl } from './links';

describe('resolveMailBrand (#637)', () => {
  it('keeps every member in shape', () => {
    expect(
      resolveMailBrand({
        name: 'Acme',
        logo: { path: '/assets/logo.png', width: 100, height: 30 },
        colors: { primary: '#123456', background: '#abcdef' },
        footer: 'Acme Inc.',
      })
    ).toEqual({
      name: 'Acme',
      logo: { path: '/assets/logo.png', width: 100, height: 30 },
      colors: { primary: '#123456', background: '#abcdef' },
      footer: 'Acme Inc.',
    });
  });

  it('falls back to the defaults for a realm that set nothing', () => {
    expect(resolveMailBrand(undefined)).toEqual(DEFAULT_MAIL_BRAND);
    expect(resolveMailBrand(null)).toEqual(DEFAULT_MAIL_BRAND);
    expect(resolveMailBrand({})).toEqual(DEFAULT_MAIL_BRAND);
  });

  it.each([
    '//evil.example/logo.png',
    'https://evil.example/logo.png',
    '/\\evil.example/logo.png',
    '/assets/../../logo.png',
    '/assets/%2e%2e/logo.png',
    '/logo.png?x=1',
    '/logo.png#x',
    'logo.png',
    '',
  ])('drops a logo at %s, which could leave the realm origin', (path) => {
    expect(isSameOriginPath(path)).toBe(false);
    expect(resolveMailBrand({ logo: { path, width: 10, height: 10 } }).logo).toBeUndefined();
  });

  it('drops a logo of an impossible size', () => {
    expect(
      resolveMailBrand({ logo: { path: '/l.png', width: 0, height: 10 } }).logo
    ).toBeUndefined();
    expect(
      resolveMailBrand({ logo: { path: '/l.png', width: 10, height: 4096 } }).logo
    ).toBeUndefined();
  });

  it('keeps only colours of the stored form', () => {
    const brand = resolveMailBrand({
      colors: { primary: 'red', background: '#ABCDEF' },
    });
    expect(brand.colors).toEqual(DEFAULT_MAIL_BRAND.colors);
  });

  it('strips control and bidirectional characters from the strings', () => {
    const brand = resolveMailBrand({ name: 'Ac‮me\u0000 Inc', footer: '⁦x⁩' });
    expect(brand.name).toBe('Ac me Inc');
    expect(brand.footer).toBe('x');
  });

  it('drops a string too long or not a string', () => {
    expect(resolveMailBrand({ name: 'x'.repeat(65) }).name).toBe(DEFAULT_MAIL_BRAND.name);
    expect(resolveMailBrand({ name: 42 }).name).toBe(DEFAULT_MAIL_BRAND.name);
    expect(resolveMailBrand({ footer: 'x'.repeat(281) }).footer).toBeUndefined();
  });
});

describe('the mail links (#637)', () => {
  it('builds the pass link on the realm issuer', () => {
    const pass = 'p'.repeat(43);
    expect(mailPassUrl('https://auth.example', pass)).toBe(
      `https://auth.example/auth/pass?pass=${pass}`
    );
    expect(mailPassUrl('https://auth.example/realms/a', pass)).toBe(
      `https://auth.example/realms/a/auth/pass?pass=${pass}`
    );
  });

  it('refuses a pass out of shape', () => {
    expect(isMailPass('p'.repeat(42))).toBe(false);
    expect(isMailPass('p'.repeat(42) + '=')).toBe(false);
    expect(() => mailPassUrl('https://auth.example', 'p'.repeat(44))).toThrow();
  });

  it('refuses a path that would leave the issuer', () => {
    expect(() => mailLink('https://auth.example', '//evil.example')).toThrow();
    expect(() => mailLink('https://auth.example', 'evil')).toThrow();
  });

  it('takes only an issuer as the base', () => {
    expect(isMailBaseUrl('https://auth.example')).toBe(true);
    expect(isMailBaseUrl('http://localhost:3000')).toBe(true);
    expect(isMailBaseUrl('https://auth.example/')).toBe(false);
    expect(isMailBaseUrl('ftp://auth.example')).toBe(false);
    expect(isMailBaseUrl('not a url')).toBe(false);
  });
});
