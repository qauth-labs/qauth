import { describe, expect, it } from 'vitest';

import { QAUTH_MAIL_LOGO_IMAGE } from '../templates/qauth-logo';
import { DEFAULT_MAIL_BRAND, isSameOriginPath, mailImagesOf, resolveMailBrand } from './brand';
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
    expect(resolveMailBrand({ name: 'Acme', logo: { path, width: 10, height: 10 } }).logo).toBe(
      undefined
    );
    // Under QAuth's name, QAuth's logo stands in.
    expect(resolveMailBrand({ logo: { path, width: 10, height: 10 } }).logo).toBe(
      DEFAULT_MAIL_BRAND.logo
    );
  });

  it('drops a logo of an impossible size', () => {
    expect(
      resolveMailBrand({ name: 'Acme', logo: { path: '/l.png', width: 0, height: 10 } }).logo
    ).toBeUndefined();
    expect(
      resolveMailBrand({ name: 'Acme', logo: { path: '/l.png', width: 10, height: 4096 } }).logo
    ).toBeUndefined();
  });

  it('gives QAuth’s logo to QAuth’s name only', () => {
    expect(DEFAULT_MAIL_BRAND.logo).toMatchObject({ width: 97, height: 40 });
    expect(mailImagesOf(DEFAULT_MAIL_BRAND)).toEqual([QAUTH_MAIL_LOGO_IMAGE]);
    expect(resolveMailBrand({ colors: { primary: '#123456' } }).logo).toBe(DEFAULT_MAIL_BRAND.logo);
    const acme = resolveMailBrand({ name: 'Acme' });
    expect(acme.logo).toBeUndefined();
    expect(mailImagesOf(acme)).toEqual([]);
  });

  it('carries QAuth’s logo as a PNG of three pixels to a point', () => {
    const png = QAUTH_MAIL_LOGO_IMAGE.content;
    expect(png.subarray(0, 8)).toEqual(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    // The IHDR chunk: width, then height, big-endian, after the signature and chunk header.
    expect(png.readUInt32BE(16)).toBe(290);
    expect(png.readUInt32BE(20)).toBe(120);
    expect(QAUTH_MAIL_LOGO_IMAGE.contentId).toMatch(/^[a-z0-9.-]+@[a-z0-9.-]+$/);
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
