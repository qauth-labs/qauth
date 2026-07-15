import { InvalidClientError } from '@qauth-labs/shared-errors';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

const { ENV, ssrfSafeGet } = vi.hoisted(() => ({
  ENV: {
    CIMD_ENABLED: true,
    CIMD_TRUST_POLICY: 'accept-any-https' as 'accept-any-https' | 'allowlist',
    CIMD_TRUSTED_DOMAINS: [] as string[],
    CIMD_CACHE_DEFAULT_TTL: 300,
    CIMD_CACHE_MAX_TTL: 3600,
    CIMD_MAX_DOCUMENT_BYTES: 65536,
    CIMD_FETCH_TIMEOUT_MS: 5000,
    CIMD_ALLOW_PRIVATE_ADDRESSES: false,
  },
  ssrfSafeGet: vi.fn(),
}));

vi.mock('../../config/env', () => ({ env: ENV }));

vi.mock('./ssrf-safe-fetch', async () => {
  const actual = await vi.importActual<typeof import('./ssrf-safe-fetch')>('./ssrf-safe-fetch');
  return { ...actual, ssrfSafeGet };
});

import {
  cimdDocumentSchema,
  fetchAndValidateCimdDocument,
  isCimdClientId,
  resolveCacheTtlSeconds,
  toCimdClientInsert,
} from './cimd';

const CLIENT_ID = 'https://app.example.com/oauth/client-metadata.json';

function validDoc(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CLIENT_ID,
    client_name: 'Example MCP Client',
    redirect_uris: ['https://app.example.com/callback'],
    ...overrides,
  };
}

function fastifyStub() {
  const store = new Map<string, string>();
  return {
    redis: {
      get: vi.fn(async (k: string) => store.get(k) ?? null),
      set: vi.fn(async (k: string, v: string) => {
        store.set(k, v);
        return 'OK';
      }),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  } as any;
}

function ok(body: unknown, headers: Record<string, string> = {}) {
  return { status: 200, body: JSON.stringify(body), headers };
}

beforeEach(() => {
  ssrfSafeGet.mockReset();
  ENV.CIMD_ENABLED = true;
  ENV.CIMD_TRUST_POLICY = 'accept-any-https';
  ENV.CIMD_TRUSTED_DOMAINS = [];
});

describe('isCimdClientId', () => {
  it('accepts https URLs with a path component', () => {
    expect(isCimdClientId('https://app.example.com/client.json')).toBe(true);
    expect(isCimdClientId('https://a.test/.well-known/oauth-client')).toBe(true);
  });

  it('rejects opaque ids, http, bare origins, and fragments', () => {
    expect(isCimdClientId('app-123')).toBe(false); // opaque pre-registered id
    expect(isCimdClientId('550e8400-e29b-41d4-a716-446655440000')).toBe(false); // DCR uuid
    expect(isCimdClientId('http://app.example.com/client.json')).toBe(false); // not https
    expect(isCimdClientId('https://app.example.com')).toBe(false); // bare origin, no path
    expect(isCimdClientId('https://app.example.com/')).toBe(false); // root path only
    expect(isCimdClientId('https://app.example.com/c.json#x')).toBe(false); // fragment
  });
});

describe('resolveCacheTtlSeconds', () => {
  it('honours Cache-Control max-age, clamped to the max', () => {
    expect(resolveCacheTtlSeconds({ 'cache-control': 'public, max-age=120' })).toBe(120);
    expect(resolveCacheTtlSeconds({ 'cache-control': 'max-age=999999' })).toBe(
      ENV.CIMD_CACHE_MAX_TTL
    );
  });

  it('returns 0 (do not cache) for no-store / no-cache', () => {
    expect(resolveCacheTtlSeconds({ 'cache-control': 'no-store' })).toBe(0);
    expect(resolveCacheTtlSeconds({ 'cache-control': 'private, no-cache' })).toBe(0);
  });

  it('falls back to the default TTL with no usable headers', () => {
    expect(resolveCacheTtlSeconds({})).toBe(ENV.CIMD_CACHE_DEFAULT_TTL);
  });
});

describe('fetchAndValidateCimdDocument', () => {
  it('happy path: fetches, validates, caches, and returns the document', async () => {
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue(ok(validDoc(), { 'cache-control': 'max-age=600' }));

    const doc = await fetchAndValidateCimdDocument(fastify, CLIENT_ID);

    expect(doc.client_id).toBe(CLIENT_ID);
    expect(doc.client_name).toBe('Example MCP Client');
    expect(doc.redirect_uris).toEqual(['https://app.example.com/callback']);
    expect(ssrfSafeGet).toHaveBeenCalledTimes(1);
    // Cached with the clamped max-age (600 < max 3600).
    expect((fastify.redis.set as Mock).mock.calls[0][3]).toBe(600);
  });

  it('rejects when the document client_id does not equal the URL (impersonation)', async () => {
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue(ok(validDoc({ client_id: 'https://evil.example/other.json' })));

    await expect(fetchAndValidateCimdDocument(fastify, CLIENT_ID)).rejects.toBeInstanceOf(
      InvalidClientError
    );
  });

  it('rejects a document missing required fields', async () => {
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue(ok({ client_id: CLIENT_ID })); // no client_name / redirect_uris

    await expect(fetchAndValidateCimdDocument(fastify, CLIENT_ID)).rejects.toBeInstanceOf(
      InvalidClientError
    );
  });

  it('rejects invalid JSON', async () => {
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue({ status: 200, body: '<<not json>>', headers: {} });

    await expect(fetchAndValidateCimdDocument(fastify, CLIENT_ID)).rejects.toBeInstanceOf(
      InvalidClientError
    );
  });

  it('surfaces an SSRF-blocked target as invalid_client and never caches it', async () => {
    const fastify = fastifyStub();
    const { SsrfBlockedError } = await import('./ssrf-safe-fetch');
    ssrfSafeGet.mockRejectedValue(new SsrfBlockedError('resolves to 169.254.169.254'));

    await expect(fetchAndValidateCimdDocument(fastify, CLIENT_ID)).rejects.toBeInstanceOf(
      InvalidClientError
    );
    expect(fastify.redis.set).not.toHaveBeenCalled();
  });

  it('rejects a non-200 fetch', async () => {
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue({ status: 404, body: '', headers: {} });

    await expect(fetchAndValidateCimdDocument(fastify, CLIENT_ID)).rejects.toBeInstanceOf(
      InvalidClientError
    );
  });

  it('serves a cached document without re-fetching (cache-header behaviour)', async () => {
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue(ok(validDoc(), { 'cache-control': 'max-age=600' }));

    await fetchAndValidateCimdDocument(fastify, CLIENT_ID); // populate cache
    expect(ssrfSafeGet).toHaveBeenCalledTimes(1);

    const second = await fetchAndValidateCimdDocument(fastify, CLIENT_ID);
    expect(second.client_id).toBe(CLIENT_ID);
    // No second network fetch — served from cache.
    expect(ssrfSafeGet).toHaveBeenCalledTimes(1);
  });

  it('does NOT cache when the response says no-store (re-fetches next time)', async () => {
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue(ok(validDoc(), { 'cache-control': 'no-store' }));

    await fetchAndValidateCimdDocument(fastify, CLIENT_ID);
    await fetchAndValidateCimdDocument(fastify, CLIENT_ID);

    expect(fastify.redis.set).not.toHaveBeenCalled();
    expect(ssrfSafeGet).toHaveBeenCalledTimes(2);
  });

  it('rejects when CIMD is disabled', async () => {
    ENV.CIMD_ENABLED = false;
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue(ok(validDoc()));

    await expect(fetchAndValidateCimdDocument(fastify, CLIENT_ID)).rejects.toBeInstanceOf(
      InvalidClientError
    );
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('enforces the allowlist trust policy', async () => {
    ENV.CIMD_TRUST_POLICY = 'allowlist';
    ENV.CIMD_TRUSTED_DOMAINS = ['trusted.example'];
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue(ok(validDoc()));

    // app.example.com is not allowlisted → rejected before any fetch.
    await expect(fetchAndValidateCimdDocument(fastify, CLIENT_ID)).rejects.toBeInstanceOf(
      InvalidClientError
    );
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('accepts a wildcard-allowlisted subdomain', async () => {
    ENV.CIMD_TRUST_POLICY = 'allowlist';
    ENV.CIMD_TRUSTED_DOMAINS = ['*.example.com'];
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue(ok(validDoc()));

    const doc = await fetchAndValidateCimdDocument(fastify, CLIENT_ID);
    expect(doc.client_id).toBe(CLIENT_ID);
  });

  it('recognises the is_agent indicator in the metadata document (ADR-007 §2)', async () => {
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue(ok(validDoc({ is_agent: true })));

    const doc = await fetchAndValidateCimdDocument(fastify, CLIENT_ID);
    expect(doc.is_agent).toBe(true);
  });
});

describe('toCimdClientInsert — agent classification (ADR-007 §2)', () => {
  const REALM = 'realm-1';
  const SENTINEL = '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZGlnZXN0';

  it('defaults isAgent to false when the document omits the indicator', () => {
    const doc = cimdDocumentSchema.parse(validDoc());
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.isAgent).toBe(false);
  });

  it('sets isAgent true when the document declares is_agent', () => {
    const doc = cimdDocumentSchema.parse(validDoc({ is_agent: true }));
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.isAgent).toBe(true);
  });
});

describe('toCimdClientInsert — grant/response type tolerance (RFC 7591 §2)', () => {
  const REALM = 'realm-1';
  const SENTINEL = '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZGlnZXN0';

  it('accepts unknown grant_types and keeps only the supported ones (claude.ai shape)', () => {
    // Real-world shape: claude.ai's metadata document declares jwt-bearer
    // alongside the grants QAuth implements. The document must validate and
    // the unknown grant must be dropped, not rejected.
    const doc = cimdDocumentSchema.parse(
      validDoc({
        grant_types: [
          'authorization_code',
          'refresh_token',
          'urn:ietf:params:oauth:grant-type:jwt-bearer',
        ],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      })
    );
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.grantTypes).toEqual(['authorization_code', 'refresh_token']);
    expect(insert.responseTypes).toEqual(['code']);
  });

  it('rejects a document whose declared grant_types contain nothing QAuth supports', () => {
    const doc = cimdDocumentSchema.parse(
      validDoc({ grant_types: ['urn:ietf:params:oauth:grant-type:jwt-bearer'] })
    );
    expect(() => toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL)).toThrow(InvalidClientError);
  });

  it('rejects a document whose declared response_types contain nothing QAuth supports', () => {
    const doc = cimdDocumentSchema.parse(validDoc({ response_types: ['id_token'] }));
    expect(() => toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL)).toThrow(InvalidClientError);
  });

  it('falls back to the default grants when the document declares none', () => {
    const doc = cimdDocumentSchema.parse(validDoc());
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.grantTypes).toEqual(['authorization_code', 'refresh_token']);
    expect(insert.responseTypes).toEqual(['code']);
  });

  it('accepts an unrecognised token_endpoint_auth_method (CIMD clients are forced to none)', () => {
    const doc = cimdDocumentSchema.parse(
      validDoc({ token_endpoint_auth_method: 'private_key_jwt' })
    );
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.tokenEndpointAuthMethod).toBe('none');
  });
});
