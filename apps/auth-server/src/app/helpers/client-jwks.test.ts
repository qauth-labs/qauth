import { InvalidClientError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { ENV, ssrfSafeGet } = vi.hoisted(() => ({
  ENV: {
    CIMD_ENABLED: true,
    CIMD_TRUST_POLICY: 'accept-any-https' as const,
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
  assertJwksMutuallyExclusive,
  fetchClientJwkSet,
  parseClientJwkSet,
  resolveClientKeySet,
} from './client-jwks';
import { SsrfBlockedError } from './ssrf-safe-fetch';

const PUBLIC_JWK = { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def', kid: 'k1' };
const JWKS_URI = 'https://client.example.com/jwks.json';

function fastifyStub() {
  const store = new Map<string, string>();
  return {
    store,
    redis: {
      get: vi.fn(async (k: string) => store.get(k) ?? null),
      set: vi.fn(async (k: string, v: string) => {
        store.set(k, v);
        return 'OK';
      }),
    },
  } as unknown as FastifyInstance;
}

beforeEach(() => {
  vi.clearAllMocks();
  ENV.CIMD_ALLOW_PRIVATE_ADDRESSES = false;
});

describe('parseClientJwkSet', () => {
  it('accepts a well-formed public key set', () => {
    expect(parseClientJwkSet({ keys: [PUBLIC_JWK] }, 'test')).toEqual({ keys: [PUBLIC_JWK] });
  });

  it.each([
    ['a private RSA/EC/OKP component', { keys: [{ ...PUBLIC_JWK, d: 'secret' }] }],
    ['a symmetric key value', { keys: [{ kty: 'oct', k: 'secret' }] }],
    ['a symmetric key type', { keys: [{ kty: 'oct' }] }],
    ['a key with no kty', { keys: [{ crv: 'P-256', x: 'a', y: 'b' }] }],
    ['an empty key list', { keys: [] }],
    ['a missing key list', {}],
    ['a non-object', 'nope'],
    ['null', null],
  ])('rejects %s', (_label, value) => {
    expect(() => parseClientJwkSet(value, 'test')).toThrow(InvalidClientError);
  });

  it('rejects a key set larger than the cap', () => {
    const keys = Array.from({ length: 21 }, (_, i) => ({ ...PUBLIC_JWK, kid: `k${i}` }));
    expect(() => parseClientJwkSet({ keys }, 'test')).toThrow(InvalidClientError);
  });
});

describe('assertJwksMutuallyExclusive (RFC 7591 §2)', () => {
  it('accepts either form alone, or neither', () => {
    expect(() => assertJwksMutuallyExclusive({ keys: [] }, null, 'x')).not.toThrow();
    expect(() => assertJwksMutuallyExclusive(null, JWKS_URI, 'x')).not.toThrow();
    expect(() => assertJwksMutuallyExclusive(null, null, 'x')).not.toThrow();
    expect(() => assertJwksMutuallyExclusive(undefined, undefined, 'x')).not.toThrow();
  });

  it('rejects both forms at once', () => {
    expect(() => assertJwksMutuallyExclusive({ keys: [] }, JWKS_URI, 'x')).toThrow(
      expect.objectContaining({ errorDescription: expect.stringMatching(/mutually exclusive/) })
    );
  });
});

describe('fetchClientJwkSet', () => {
  it('fetches through the SSRF-guarded path with private addresses disallowed', async () => {
    ssrfSafeGet.mockResolvedValue({
      status: 200,
      body: JSON.stringify({ keys: [PUBLIC_JWK] }),
      headers: {},
    });

    await expect(fetchClientJwkSet(fastifyStub(), JWKS_URI)).resolves.toEqual({
      keys: [PUBLIC_JWK],
    });
    expect(ssrfSafeGet).toHaveBeenCalledWith(JWKS_URI, {
      timeoutMs: 5000,
      maxBytes: 65536,
      allowPrivateAddresses: false,
    });
  });

  it('serves a cached key set without re-fetching', async () => {
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue({
      status: 200,
      body: JSON.stringify({ keys: [PUBLIC_JWK] }),
      headers: {},
    });

    await fetchClientJwkSet(fastify, JWKS_URI);
    await fetchClientJwkSet(fastify, JWKS_URI);

    expect(ssrfSafeGet).toHaveBeenCalledTimes(1);
  });

  it('rejects a target that resolves to a private address', async () => {
    ssrfSafeGet.mockRejectedValue(new SsrfBlockedError('resolves to a non-public address'));
    await expect(fetchClientJwkSet(fastifyStub(), JWKS_URI)).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/fetch blocked/),
    });
  });

  it('rejects a non-200 response', async () => {
    ssrfSafeGet.mockResolvedValue({ status: 500, body: '', headers: {} });
    await expect(fetchClientJwkSet(fastifyStub(), JWKS_URI)).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/returned 500/),
    });
  });

  it('rejects a document that is not JSON', async () => {
    ssrfSafeGet.mockResolvedValue({ status: 200, body: '<html>', headers: {} });
    await expect(fetchClientJwkSet(fastifyStub(), JWKS_URI)).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/not valid JSON/),
    });
  });

  it('rejects a fetched document carrying private key material', async () => {
    ssrfSafeGet.mockResolvedValue({
      status: 200,
      body: JSON.stringify({ keys: [{ ...PUBLIC_JWK, d: 'secret' }] }),
      headers: {},
    });
    await expect(fetchClientJwkSet(fastifyStub(), JWKS_URI)).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/not a valid public JWK Set/),
    });
  });

  it('does not cache a rejected document', async () => {
    const fastify = fastifyStub();
    ssrfSafeGet.mockResolvedValue({ status: 200, body: '{"keys":[]}', headers: {} });
    await expect(fetchClientJwkSet(fastify, JWKS_URI)).rejects.toThrow(InvalidClientError);
    expect(fastify.redis.set).not.toHaveBeenCalled();
  });
});

describe('resolveClientKeySet', () => {
  const base = {
    id: 'row',
    clientId: 'cid',
    clientSecretHash: 'hash',
    enabled: true,
    grantTypes: [],
    scopes: [],
    audience: null,
  };

  it('prefers the inline key set', async () => {
    await expect(
      resolveClientKeySet(fastifyStub(), { ...base, jwks: { keys: [PUBLIC_JWK] } })
    ).resolves.toEqual({ keys: [PUBLIC_JWK] });
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('rejects a client registered with both forms', async () => {
    await expect(
      resolveClientKeySet(fastifyStub(), {
        ...base,
        jwks: { keys: [PUBLIC_JWK] },
        jwksUri: JWKS_URI,
      })
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/mutually exclusive/) });
  });

  it('rejects a client registered with neither form', async () => {
    await expect(
      resolveClientKeySet(fastifyStub(), { ...base, jwks: null, jwksUri: null })
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/no registered jwks/) });
  });

  it('rejects a client whose jwksUri is an empty string', async () => {
    await expect(
      resolveClientKeySet(fastifyStub(), { ...base, jwks: null, jwksUri: '' })
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/no registered jwks/) });
  });
});
