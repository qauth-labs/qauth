import { InvalidClientError, InvalidScopeError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

import {
  authenticateClient,
  extractClientCredentials,
  type OAuthClientLike,
  resolveAudience,
  validateScopes,
} from './client-auth';

function requestWith(authHeader: string | undefined): FastifyRequest {
  return {
    headers: authHeader === undefined ? {} : { authorization: authHeader },
  } as unknown as FastifyRequest;
}

describe('extractClientCredentials', () => {
  it('extracts client_secret_post credentials from the body', () => {
    const creds = extractClientCredentials(requestWith(undefined), 'cid', 'csecret');
    expect(creds).toEqual({
      clientId: 'cid',
      clientSecret: 'csecret',
      method: 'client_secret_post',
    });
  });

  it('decodes client_secret_basic credentials from the Authorization header', () => {
    const basic = Buffer.from('cid:csecret', 'utf8').toString('base64');
    const creds = extractClientCredentials(requestWith(`Basic ${basic}`), undefined, undefined);
    expect(creds).toEqual({
      clientId: 'cid',
      clientSecret: 'csecret',
      method: 'client_secret_basic',
    });
  });

  it('URL-decodes Basic credentials (RFC 6749 §2.3.1 form-urlencoding)', () => {
    // `+` represents a space in application/x-www-form-urlencoded.
    const raw = 'user+name:p%40ss%3Aword';
    const basic = Buffer.from(raw, 'utf8').toString('base64');
    const creds = extractClientCredentials(requestWith(`Basic ${basic}`), undefined, undefined);
    expect(creds.clientId).toBe('user name');
    expect(creds.clientSecret).toBe('p@ss:word');
  });

  it('throws InvalidClientError for malformed base64 in Basic header', () => {
    expect(() =>
      extractClientCredentials(requestWith('Basic !!!not-base64!!!'), undefined, undefined)
    ).toThrow(InvalidClientError);
  });

  it('throws InvalidClientError when Basic payload has no colon separator', () => {
    const basic = Buffer.from('no-colon', 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${basic}`), undefined, undefined)
    ).toThrow(InvalidClientError);
  });

  it('throws InvalidClientError when Basic credentials have empty clientId or secret', () => {
    const emptyId = Buffer.from(':secret', 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${emptyId}`), undefined, undefined)
    ).toThrow(InvalidClientError);

    const emptySecret = Buffer.from('cid:', 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${emptySecret}`), undefined, undefined)
    ).toThrow(InvalidClientError);
  });

  it('rejects requests that mix Basic and body client_secret (RFC 6749 §2.3)', () => {
    const basic = Buffer.from('cid:csecret', 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${basic}`), undefined, 'body-secret')
    ).toThrow(InvalidClientError);
  });

  it('rejects requests where Basic clientId disagrees with body client_id', () => {
    const basic = Buffer.from('cid-a:csecret', 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${basic}`), 'cid-b', undefined)
    ).toThrow(InvalidClientError);
  });

  it('accepts Basic when body client_id matches and no body secret is present', () => {
    const basic = Buffer.from('cid-a:csecret', 'utf8').toString('base64');
    const creds = extractClientCredentials(requestWith(`Basic ${basic}`), 'cid-a', undefined);
    expect(creds.method).toBe('client_secret_basic');
    expect(creds.clientId).toBe('cid-a');
  });

  it('throws InvalidClientError when no credentials are supplied', () => {
    expect(() => extractClientCredentials(requestWith(undefined), undefined, undefined)).toThrow(
      InvalidClientError
    );
  });

  it('does not throw URIError on malformed percent-encoding (I-e regression)', () => {
    // Base64-encode a string that will decode fine but contains an invalid
    // percent sequence — decodeURIComponent would throw URIError if not caught.
    const raw = 'foo%ZZ:bar';
    const basic = Buffer.from(raw, 'utf8').toString('base64');
    expect(() =>
      extractClientCredentials(requestWith(`Basic ${basic}`), undefined, undefined)
    ).toThrow(InvalidClientError);
  });
});

describe('authenticateClient', () => {
  function makeFastifyStub(
    client: OAuthClientLike | null,
    passwordValid: boolean
  ): FastifyInstance {
    return {
      repositories: {
        oauthClients: {
          findByClientId: vi.fn().mockResolvedValue(client),
        },
      },
      passwordHasher: {
        verifyPassword: vi.fn().mockResolvedValue(passwordValid),
      },
    } as unknown as FastifyInstance;
  }

  const baseClient: OAuthClientLike = {
    id: 'cuid',
    clientId: 'cid',
    clientSecretHash: 'hash',
    enabled: true,
    grantTypes: ['client_credentials'],
    scopes: [],
    audience: null,
  };

  it('returns the client when credentials are valid', async () => {
    const fastify = makeFastifyStub(baseClient, true);
    const out = await authenticateClient(fastify, 'realm', {
      clientId: 'cid',
      clientSecret: 'secret',
      method: 'client_secret_post',
    });
    expect(out).toBe(baseClient);
  });

  it('throws InvalidClientError for unknown client', async () => {
    const fastify = makeFastifyStub(null, true);
    await expect(
      authenticateClient(fastify, 'realm', {
        clientId: 'missing',
        clientSecret: 'secret',
        method: 'client_secret_post',
      })
    ).rejects.toThrow(InvalidClientError);
  });

  it('throws InvalidClientError for disabled client', async () => {
    const fastify = makeFastifyStub({ ...baseClient, enabled: false }, true);
    await expect(
      authenticateClient(fastify, 'realm', {
        clientId: 'cid',
        clientSecret: 'secret',
        method: 'client_secret_post',
      })
    ).rejects.toThrow(InvalidClientError);
    // Must not reach password verification for a disabled client.
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
  });

  it('throws InvalidClientError for wrong secret', async () => {
    const fastify = makeFastifyStub(baseClient, false);
    await expect(
      authenticateClient(fastify, 'realm', {
        clientId: 'cid',
        clientSecret: 'wrong',
        method: 'client_secret_post',
      })
    ).rejects.toThrow(InvalidClientError);
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledWith('hash', 'wrong');
  });
});

describe('validateScopes', () => {
  it('returns an empty array when requested scope is missing or blank', () => {
    expect(validateScopes(undefined, ['read'])).toEqual([]);
    expect(validateScopes('', ['read'])).toEqual([]);
    expect(validateScopes('   ', ['read'])).toEqual([]);
  });

  it('returns the requested scopes when all are in the allowlist', () => {
    expect(validateScopes('read write', ['read', 'write', 'delete'])).toEqual(['read', 'write']);
  });

  it('throws InvalidScopeError when any requested scope is outside the allowlist', () => {
    expect(() => validateScopes('read admin', ['read'])).toThrow(InvalidScopeError);
  });

  it('denies every requested scope when the allowlist is empty', () => {
    expect(() => validateScopes('read', [])).toThrow(InvalidScopeError);
  });

  it('collapses runs of whitespace between scopes', () => {
    expect(validateScopes('read    write', ['read', 'write'])).toEqual(['read', 'write']);
  });
});

describe('resolveAudience', () => {
  const base: OAuthClientLike = {
    id: 'x',
    clientId: 'cid',
    clientSecretHash: '',
    enabled: true,
    grantTypes: [],
    scopes: [],
    audience: null,
  };

  it('falls back to clientId when audience is null', () => {
    expect(resolveAudience(base)).toBe('cid');
  });

  it('falls back to clientId when audience is an empty array', () => {
    expect(resolveAudience({ ...base, audience: [] })).toBe('cid');
  });

  it('collapses a single-item array to a bare string', () => {
    expect(resolveAudience({ ...base, audience: ['https://api.example.com'] })).toBe(
      'https://api.example.com'
    );
  });

  it('returns the array when multiple audiences are configured', () => {
    expect(
      resolveAudience({ ...base, audience: ['https://a.example', 'https://b.example'] })
    ).toEqual(['https://a.example', 'https://b.example']);
  });

  it('falls back to clientId when audience entries are not strings (I-g guard)', () => {
    // Drizzle's $type<string[] | null> hints the shape but raw JSONB can store
    // anything; the helper must defend against malformed rows.
    const malformed = [null as unknown as string, 42 as unknown as string];
    expect(resolveAudience({ ...base, audience: malformed })).toBe('cid');
  });

  it('falls back to clientId when audience exceeds the entry cap', () => {
    const tooMany = Array.from({ length: 25 }, (_, i) => `aud-${i}`);
    expect(resolveAudience({ ...base, audience: tooMany })).toBe('cid');
  });

  it('falls back to clientId when an audience entry is oversized', () => {
    const oversized = ['a'.repeat(257)];
    expect(resolveAudience({ ...base, audience: oversized })).toBe('cid');
  });
});
