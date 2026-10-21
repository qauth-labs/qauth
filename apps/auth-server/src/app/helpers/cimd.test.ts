import { InvalidClientError } from '@qauth-labs/shared-errors';
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

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
    REDIRECT_URI_CUSTOM_SCHEMES: [] as string[],
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

  it('refuses an over-long or non-ASCII client_id BEFORE parsing it as a URL', () => {
    // `new URL()` is quadratic in the distinct non-ASCII characters of a host,
    // and this runs for any unknown client_id, including one from an HTTP
    // Basic header or a client assertion. A CIMD client_id is an ASCII URL of
    // at most 2048 characters (the document schema's own bound).
    const cjkHost = Array.from({ length: 1000 }, (_, i) => String.fromCodePoint(0x4e00 + i)).join(
      ''
    );
    const atBound = `https://app.example.com/${'a'.repeat(2048 - 'https://app.example.com/'.length)}`;
    const URLConstructor = globalThis.URL;
    const constructed = vi.fn();
    vi.stubGlobal(
      'URL',
      class extends URLConstructor {
        constructor(...args: ConstructorParameters<typeof URL>) {
          constructed();
          super(...args);
        }
      }
    );
    try {
      expect(isCimdClientId(`https://${cjkHost}/client.json`)).toBe(false);
      expect(isCimdClientId('https://bücher.example/client.json')).toBe(false);
      expect(isCimdClientId(`${atBound}a`)).toBe(false);
      expect(constructed).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
    expect(isCimdClientId(atBound)).toBe(true);
    expect(isCimdClientId('https://xn--bcher-kva.example/client.json')).toBe(true);
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

describe('toCimdClientInsert — never operator-provisioned (ANT-2026-O8U3P920)', () => {
  it('pins provisionedByOperator to false, whatever the document says', () => {
    // The document's host chose the redirect URIs, so a CIMD client never
    // receives authorization errors by automatic redirect.
    const doc = cimdDocumentSchema.parse(
      validDoc({ provisioned_by_operator: true, provisionedByOperator: true })
    );
    const insert = toCimdClientInsert('realm-1', CLIENT_ID, doc, 'sentinel');
    expect(insert.provisionedByOperator).toBe(false);
  });
});

describe('toCimdClientInsert — grant/response type tolerance (RFC 7591 §2)', () => {
  const REALM = 'realm-1';
  const SENTINEL = '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZGlnZXN0';

  it('materialises portless loopback redirect_uris verbatim (Claude Code shape, #414)', () => {
    // Claude Code's CIMD document declares its loopback callbacks without a
    // port; the ephemeral port only exists at authorization time and is
    // matched by redirectUriMatchesRegistered (RFC 8252 §7.3).
    const redirectUris = ['http://localhost/callback', 'http://127.0.0.1/callback'];
    const doc = cimdDocumentSchema.parse(validDoc({ redirect_uris: redirectUris }));
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.redirectUris).toEqual(redirectUris);
  });

  // Regression (ANT-2026-D0XJAT8S follow-up): one redirect URI registration
  // would refuse makes the whole document unusable, exactly as DCR refuses the
  // whole request — it is no longer dropped while the rest is accepted.
  it('keeps every redirect_uri when registration would accept them all', () => {
    const uris = [
      'https://app.example.com/callback',
      'http://localhost/callback',
      'http://127.0.0.1:8765/callback',
    ];
    const doc = cimdDocumentSchema.parse(validDoc({ redirect_uris: uris }));
    expect(toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL).redirectUris).toEqual(uris);
  });

  it.each([
    ['plain http to a non-loopback host', 'http://app.example.com/callback'],
    ['a fragment', 'https://app.example.com/cb#fragment'],
    ['a loopback literal registration does not accept', 'http://127.0.0.2/callback'],
    ['something that is not a URI', 'not a uri'],
    // Found while fixing the findings of scan qauth-20261015-005.
    ['a javascript: scheme', 'javascript:alert(document.domain)'],
    ['a scheme that is not a reverse domain name', 'myapp:/callback'],
  ])('refuses the whole document when one redirect_uri has %s', (_label, bad) => {
    const doc = cimdDocumentSchema.parse(
      validDoc({ redirect_uris: ['https://app.example.com/callback', bad] })
    );
    let thrown: unknown;
    try {
      toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(InvalidClientError);
    // The audit reason carries DCR's own RFC 7591 error code.
    expect((thrown as InvalidClientError).errorDescription).toMatch(
      /^CIMD document refused: invalid_redirect_uri: /
    );
  });

  describe('REDIRECT_URI_CUSTOM_SCHEMES (#774)', () => {
    const cursorCallback = 'cursor://anysphere.cursor-mcp/oauth/callback';

    afterEach(() => {
      ENV.REDIRECT_URI_CUSTOM_SCHEMES = [];
    });

    it('refuses a document listing a bare scheme when the setting is empty', () => {
      const doc = cimdDocumentSchema.parse(validDoc({ redirect_uris: [cursorCallback] }));
      expect(() => toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL)).toThrow(InvalidClientError);
    });

    it('accepts a document listing a bare scheme the deployment lists', () => {
      ENV.REDIRECT_URI_CUSTOM_SCHEMES = ['cursor'];
      const doc = cimdDocumentSchema.parse(
        validDoc({ redirect_uris: ['http://127.0.0.1/callback', cursorCallback] })
      );
      expect(toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL).redirectUris).toEqual([
        'http://127.0.0.1/callback',
        cursorCallback,
      ]);
    });

    it('still refuses a document listing a bare scheme that is not listed', () => {
      ENV.REDIRECT_URI_CUSTOM_SCHEMES = ['cursor'];
      const doc = cimdDocumentSchema.parse(
        validDoc({ redirect_uris: [cursorCallback, 'myapp:/callback'] })
      );
      let thrown: unknown;
      try {
        toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(InvalidClientError);
      expect((thrown as InvalidClientError).errorDescription).toMatch(
        /^CIMD document refused: invalid_redirect_uri: unsupported scheme: myapp:/
      );
    });
  });

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

  it('falls back to a public client when private_key_jwt is declared without a key set', () => {
    // Half-configured: the document asks for assertion authentication but
    // publishes nothing to verify an assertion against. It keeps the public,
    // PKCE-only posture it had before #384 rather than being rejected — the
    // fallback grants nothing, because the verifier requires BOTH the
    // registered method and a key set.
    const doc = cimdDocumentSchema.parse(
      validDoc({ token_endpoint_auth_method: 'private_key_jwt' })
    );
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.tokenEndpointAuthMethod).toBe('none');
    expect(insert.jwks).toBeNull();
    expect(insert.jwksUri).toBeNull();
  });

  it('accepts an unrecognised token_endpoint_auth_method and materialises a public client', () => {
    const doc = cimdDocumentSchema.parse(
      validDoc({ token_endpoint_auth_method: 'client_secret_basic' })
    );
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.tokenEndpointAuthMethod).toBe('none');
  });
});

describe('toCimdClientInsert — client JWKS (CIMD §6.2 / RFC 7591 §2, #384)', () => {
  const REALM = 'realm-1';
  const SENTINEL = '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZGlnZXN0';
  const PUBLIC_JWK = { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def', kid: 'k1' };

  it('materialises a confidential client when the document registers an inline jwks', () => {
    const doc = cimdDocumentSchema.parse(
      validDoc({
        token_endpoint_auth_method: 'private_key_jwt',
        jwks: { keys: [PUBLIC_JWK] },
      })
    );
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.tokenEndpointAuthMethod).toBe('private_key_jwt');
    expect(insert.jwks).toEqual({ keys: [PUBLIC_JWK] });
    expect(insert.jwksUri).toBeNull();
    // PKCE stays mandatory regardless of the authentication method.
    expect(insert.requirePkce).toBe(true);
  });

  it('materialises a confidential client from a jwks_uri', () => {
    const doc = cimdDocumentSchema.parse(
      validDoc({
        token_endpoint_auth_method: 'private_key_jwt',
        jwks_uri: 'https://app.example.com/jwks.json',
      })
    );
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.tokenEndpointAuthMethod).toBe('private_key_jwt');
    expect(insert.jwksUri).toBe('https://app.example.com/jwks.json');
    expect(insert.jwks).toBeNull();
  });

  it('rejects a document that sets both jwks and jwks_uri (RFC 7591 §2)', () => {
    const doc = cimdDocumentSchema.parse(
      validDoc({
        token_endpoint_auth_method: 'private_key_jwt',
        jwks: { keys: [PUBLIC_JWK] },
        jwks_uri: 'https://app.example.com/jwks.json',
      })
    );
    expect(() => toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL)).toThrow(
      expect.objectContaining({ errorDescription: expect.stringMatching(/mutually exclusive/) })
    );
  });

  it('ignores a key set the document did not ask to authenticate with', () => {
    // `jwks` without `token_endpoint_auth_method: private_key_jwt` leaves the
    // client public; persisting the keys anyway would leave them lying dormant
    // in the row for a later method flip to pick up.
    const doc = cimdDocumentSchema.parse(validDoc({ jwks: { keys: [PUBLIC_JWK] } }));
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.tokenEndpointAuthMethod).toBe('none');
    expect(insert.jwks).toBeNull();
  });

  it('rejects a document whose jwks carries a private key component', () => {
    expect(
      cimdDocumentSchema.safeParse(
        validDoc({ jwks: { keys: [{ ...PUBLIC_JWK, d: 'private-scalar' }] } })
      ).success
    ).toBe(false);
  });

  it('rejects a document whose jwks carries a symmetric key', () => {
    expect(
      cimdDocumentSchema.safeParse(validDoc({ jwks: { keys: [{ kty: 'oct', k: 'secret' }] } }))
        .success
    ).toBe(false);
  });

  it('rejects a document whose jwks is empty or oversized', () => {
    expect(cimdDocumentSchema.safeParse(validDoc({ jwks: { keys: [] } })).success).toBe(false);
    const tooMany = Array.from({ length: 21 }, (_, i) => ({ ...PUBLIC_JWK, kid: `k${i}` }));
    expect(cimdDocumentSchema.safeParse(validDoc({ jwks: { keys: tooMany } })).success).toBe(false);
  });

  it('leaves a document without any key set exactly as it behaved before #384', () => {
    const doc = cimdDocumentSchema.parse(validDoc());
    const insert = toCimdClientInsert(REALM, CLIENT_ID, doc, SENTINEL);
    expect(insert.tokenEndpointAuthMethod).toBe('none');
    expect(insert.jwks).toBeNull();
    expect(insert.jwksUri).toBeNull();
  });
});
