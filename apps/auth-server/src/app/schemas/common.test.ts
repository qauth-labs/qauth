import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { createClientRequestSchema, updateClientRequestSchema } from './clients';
import { boundedArray, exactUrl, hasInteriorTabOrNewline } from './common';
import {
  authorizeQuerySchema,
  dynamicClientRegistrationRequestSchema,
  TOKEN_EXCHANGE_GRANT_TYPE,
  tokenExchangeBodySchema,
} from './oauth';

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

/**
 * `z.array(element).max(n)` does not bound the work: Zod parses every element
 * first and runs the array's own checks afterwards, and each failing element is
 * a separate issue. A 1 MB body of two-byte elements made ~490 000 of them,
 * seconds of event-loop time on an unauthenticated route and a 93 MB answer.
 */
describe('boundedArray', () => {
  const element = vi.fn((value: string) => value.length > 0);
  const schema = boundedArray(z.array(z.string().refine(element)), 3);

  it('accepts an array up to the bound and still validates its elements', () => {
    expect(schema.parse(['a', 'b', 'c'])).toEqual(['a', 'b', 'c']);
    expect(schema.safeParse(['a', '']).error?.issues).toMatchObject([{ path: [1] }]);
    expect(schema.safeParse('a').error?.issues).toMatchObject([{ code: 'invalid_type' }]);
  });

  it('refuses an oversized array with ONE too_big issue, before looking at any element', () => {
    element.mockClear();
    const result = schema.safeParse(Array(10_000).fill('a'));

    expect(result.error?.issues).toEqual([
      expect.objectContaining({ code: 'too_big', origin: 'array', maximum: 3, path: [] }),
    ]);
    expect(element).not.toHaveBeenCalled();
  });

  it('publishes the same JSON Schema as the plain array', () => {
    const plain = z.array(z.string()).max(3);
    expect(z.toJSONSchema(boundedArray(z.array(z.string()), 3), { io: 'input' })).toEqual(
      z.toJSONSchema(plain, { io: 'input' })
    );
  });
});

describe('request schemas — the caller does not choose the number of issues', () => {
  const tokenExchange = {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: 't',
    subject_token_type: 't',
  };
  const cases: ReadonlyArray<readonly [string, z.ZodType, string, Record<string, unknown>]> = [
    ...['redirect_uris', 'grant_types', 'response_types', 'contacts'].map(
      (field) =>
        ['POST /oauth/register', dynamicClientRegistrationRequestSchema, field, {}] as const
    ),
    ...['redirectUris', 'scopes', 'grantTypes', 'responseTypes'].flatMap(
      (field) =>
        [
          ['POST /api/clients', createClientRequestSchema, field, { name: 'n' }],
          ['PATCH /api/clients/:id', updateClientRequestSchema, field, {}],
        ] as const
    ),
    ['POST /oauth/token', tokenExchangeBodySchema, 'resource', tokenExchange],
    ['POST /oauth/token', tokenExchangeBodySchema, 'audience', tokenExchange],
    ['/oauth/authorize', authorizeQuerySchema, 'resource', {}],
  ];

  it.each(cases)('%s %#: an oversized array is refused whole', (...args) => {
    const [, schema, field, rest] = args;
    const result = schema.safeParse({ ...rest, [field]: Array(10_000).fill(1) });

    expect(result.success).toBe(false);
    // Serialised, so issues nested inside an `invalid_union` count as well.
    expect(JSON.stringify(result.error?.issues).length).toBeLessThan(4096);
  });

  it('parses no URL in an oversized list of redirect URIs', () => {
    const canParse = vi.spyOn(URL, 'canParse');
    try {
      const redirectUris = Array(1000).fill('https://app.example.com/cb');
      expect(createClientRequestSchema.safeParse({ name: 'n', redirectUris }).success).toBe(false);
      expect(updateClientRequestSchema.safeParse({ redirectUris }).success).toBe(false);
      expect(canParse).not.toHaveBeenCalled();
    } finally {
      canParse.mockRestore();
    }
  });
});
