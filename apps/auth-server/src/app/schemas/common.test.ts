import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { createClientRequestSchema, updateClientRequestSchema } from './clients';
import { exactUrl, hasInteriorTabOrNewline } from './common';

/**
 * `exactUrl()` replaces `z.url()` for every URL QAuth compares as a string.
 * Since Zod 4.5, `z.url()` deletes tabs and line breaks from the value it
 * returns. These tests pin that QAuth still receives the value as sent.
 */
describe('exactUrl', () => {
  it('returns a valid URL unchanged, with no parser normalisation', () => {
    for (const value of [
      'https://app.example.com/cb',
      'http://127.0.0.1:8080/cb?x=%20y',
      'com.example.app:/oauth/callback',
      'https://APP.example.com/a/../b',
    ]) {
      expect(exactUrl().parse(value)).toBe(value);
    }
  });

  it('trims leading and trailing whitespace, line breaks included, as z.url() always has', () => {
    expect(exactUrl().parse(' https://app.example.com/cb\r\n')).toBe('https://app.example.com/cb');
    expect(exactUrl().parse('\thttps://app.example.com/cb')).toBe('https://app.example.com/cb');
  });

  it('rejects a tab, LF or CR inside the value instead of deleting it', () => {
    for (const value of [
      'https://app.example.com/c\tb',
      'https://app.exa\nmple.com/cb',
      'https://app.example.com/cb\r?x=1',
      'ht\ttps://app.example.com/cb',
    ]) {
      expect(exactUrl().safeParse(value).success).toBe(false);
    }
  });

  it('still rejects what z.url() rejects', () => {
    for (const value of ['not a url', '', '/relative/path', 'https://']) {
      expect(exactUrl().safeParse(value).success).toBe(false);
    }
  });

  it('is still documented as `format: "uri"`', () => {
    expect(z.toJSONSchema(exactUrl())).toMatchObject({ type: 'string', format: 'uri' });
  });
});

describe('hasInteriorTabOrNewline', () => {
  it('ignores the leading and trailing whitespace that z.url() trims', () => {
    expect(hasInteriorTabOrNewline('\thttps://app.example.com/cb\r\n')).toBe(false);
    expect(hasInteriorTabOrNewline('https://app.example.com/c\tb')).toBe(true);
  });
});

describe('client-management redirectUris use exactUrl', () => {
  const tabbed = 'https://app.example.com/c\tb';

  it('POST /api/clients refuses a redirect URI with a tab inside instead of storing it stripped', () => {
    expect(createClientRequestSchema.safeParse({ name: 'x', redirectUris: [tabbed] }).success).toBe(
      false
    );
    expect(
      createClientRequestSchema.parse({ name: 'x', redirectUris: ['https://app.example.com/cb'] })
        .redirectUris
    ).toEqual(['https://app.example.com/cb']);
  });

  it('PATCH /api/clients/:id refuses it too', () => {
    expect(updateClientRequestSchema.safeParse({ redirectUris: [tabbed] }).success).toBe(false);
  });
});
