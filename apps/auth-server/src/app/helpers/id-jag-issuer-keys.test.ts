import { generateSigningKeyPair } from '@qauth-labs/core-crypto';
import { exportJWK, type JWK } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { ENV, ssrfSafeGet } = vi.hoisted(() => ({
  ENV: {
    ID_JAG_ENABLED: true,
    ID_JAG_TRUSTED_ISSUERS: [] as string[],
    ID_JAG_FETCH_TIMEOUT_MS: 5000,
    ID_JAG_JWKS_CACHE_TTL: 300,
    ID_JAG_JWKS_REFRESH_COOLDOWN: 30,
    ID_JAG_JWKS_NEGATIVE_CACHE_TTL: 30,
    ID_JAG_MAX_DOCUMENT_BYTES: 65536,
    ID_JAG_ALLOW_PRIVATE_ADDRESSES: false,
  },
  ssrfSafeGet: vi.fn(),
}));

vi.mock('../../config/env', () => ({ env: ENV }));

vi.mock('./ssrf-safe-fetch', async () => {
  const actual = await vi.importActual<typeof import('./ssrf-safe-fetch')>('./ssrf-safe-fetch');
  return { ...actual, ssrfSafeGet };
});

import { createExpiringRedis, createFakeIdJagIssuer } from '../../testing/fake-id-jag-issuer';
import { REDIS_KEYS } from '../constants/redis-keys';
import {
  createIdJagIssuerKeyResolver,
  ID_JAG_SIGNING_ALG_VALUES_SUPPORTED,
  isSupportedIdJagAlgorithm,
  resolveTrustedIdJagIssuer,
} from './id-jag-issuer-keys';
import { SsrfBlockedError } from './ssrf-safe-fetch';

const ISSUER = 'https://idp.example.com';
const DISCOVERY_URL = `${ISSUER}/.well-known/openid-configuration`;
const JWKS_URI = 'https://idp.example.com/jwks.json';

/** A fresh Ed25519 public JWK, optionally carrying a `kid`. */
async function publicJwk(kid?: string): Promise<JWK> {
  const { publicKey } = await generateSigningKeyPair('EdDSA', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return { ...jwk, ...(kid !== undefined ? { kid } : {}) };
}

function ok(body: unknown) {
  return { status: 200, body: JSON.stringify(body), headers: {} };
}

/** `fastify` stand-in: an in-memory Redis with `EX`/`NX` on a manual clock. */
function fastifyStub() {
  const redis = createExpiringRedis();
  return {
    redis,
    fastify: {
      redis,
      log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  };
}

/** Wire the two-hop happy path: discovery document, then JWK Set. */
function wireHappyPath(keys: JWK[], overrides?: { documentIssuer?: string; jwksUri?: string }) {
  ssrfSafeGet.mockImplementation(async (url: string) => {
    if (url === DISCOVERY_URL) {
      return ok({
        issuer: overrides?.documentIssuer ?? ISSUER,
        jwks_uri: overrides?.jwksUri ?? JWKS_URI,
      });
    }
    if (url === (overrides?.jwksUri ?? JWKS_URI)) {
      return ok({ keys });
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
}

beforeEach(() => {
  ssrfSafeGet.mockReset();
  ENV.ID_JAG_ENABLED = true;
  ENV.ID_JAG_TRUSTED_ISSUERS = [ISSUER];
  ENV.ID_JAG_JWKS_CACHE_TTL = 300;
  ENV.ID_JAG_JWKS_REFRESH_COOLDOWN = 30;
  ENV.ID_JAG_JWKS_NEGATIVE_CACHE_TTL = 30;
});

describe('ID_JAG_SIGNING_ALG_VALUES_SUPPORTED', () => {
  it('contains only asymmetric algorithms and never `none` or a MAC', () => {
    expect(ID_JAG_SIGNING_ALG_VALUES_SUPPORTED).toContain('EdDSA');
    expect(ID_JAG_SIGNING_ALG_VALUES_SUPPORTED).toContain('RS256');
    expect(ID_JAG_SIGNING_ALG_VALUES_SUPPORTED).not.toContain('none');
    for (const alg of ID_JAG_SIGNING_ALG_VALUES_SUPPORTED) {
      expect(alg.startsWith('HS')).toBe(false);
    }
  });

  it('rejects `none`, MAC algorithms, and non-string values', () => {
    expect(isSupportedIdJagAlgorithm('none')).toBe(false);
    expect(isSupportedIdJagAlgorithm('HS256')).toBe(false);
    expect(isSupportedIdJagAlgorithm(undefined)).toBe(false);
    expect(isSupportedIdJagAlgorithm(256)).toBe(false);
    expect(isSupportedIdJagAlgorithm('EdDSA')).toBe(true);
  });
});

describe('resolveTrustedIdJagIssuer', () => {
  it('rejects every issuer when ID_JAG_ENABLED is false', () => {
    ENV.ID_JAG_ENABLED = false;
    expect(resolveTrustedIdJagIssuer(ISSUER)).toBeUndefined();
  });

  it('rejects every issuer when the allowlist is empty', () => {
    ENV.ID_JAG_TRUSTED_ISSUERS = [];
    expect(resolveTrustedIdJagIssuer(ISSUER)).toBeUndefined();
  });

  it('rejects an issuer that is not on the allowlist', () => {
    expect(resolveTrustedIdJagIssuer('https://evil.example.com')).toBeUndefined();
    // A near-miss must not match either — no prefix / suffix / wildcard logic.
    expect(resolveTrustedIdJagIssuer('https://idp.example.com.evil.test')).toBeUndefined();
    expect(resolveTrustedIdJagIssuer('https://sub.idp.example.com')).toBeUndefined();
  });

  it('accepts an allowlisted issuer and returns the canonical identifier', () => {
    expect(resolveTrustedIdJagIssuer(ISSUER)).toBe(ISSUER);
  });

  it('canonicalises a trailing slash on BOTH the claim and the configured entry', () => {
    expect(resolveTrustedIdJagIssuer(`${ISSUER}/`)).toBe(ISSUER);
    ENV.ID_JAG_TRUSTED_ISSUERS = [`${ISSUER}/`];
    expect(resolveTrustedIdJagIssuer(ISSUER)).toBe(ISSUER);
  });

  it('rejects a non-string, empty, or absurdly long issuer', () => {
    expect(resolveTrustedIdJagIssuer(undefined)).toBeUndefined();
    expect(resolveTrustedIdJagIssuer('')).toBeUndefined();
    expect(resolveTrustedIdJagIssuer(`https://${'a'.repeat(4000)}.example.com`)).toBeUndefined();
  });
});

describe('createIdJagIssuerKeyResolver — allowlist gating', () => {
  it('never fetches anything when the feature is disabled', async () => {
    ENV.ID_JAG_ENABLED = false;
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('never fetches anything when the allowlist is empty', async () => {
    ENV.ID_JAG_TRUSTED_ISSUERS = [];
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('never fetches anything for an issuer outside the allowlist', async () => {
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await expect(
      resolve({ issuer: 'https://evil.example.com', algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });
});

describe('createIdJagIssuerKeyResolver — key resolution', () => {
  it('resolves the single published key and reports the confirmed identifier', async () => {
    wireHappyPath([await publicJwk()]);
    const { fastify } = fastifyStub();

    const resolved = await createIdJagIssuerKeyResolver(fastify)({
      issuer: `${ISSUER}/`,
      algorithm: 'EdDSA',
    });

    expect(resolved).toBeDefined();
    // The CONFIRMED identifier is the canonical allowlist entry, not the raw claim.
    expect(resolved?.identifier).toBe(ISSUER);
    expect(ssrfSafeGet).toHaveBeenCalledWith(DISCOVERY_URL, expect.anything());
    expect(ssrfSafeGet).toHaveBeenCalledWith(JWKS_URI, expect.anything());
  });

  it('selects exactly the key named by `kid`', async () => {
    const wanted = await publicJwk('key-a');
    wireHappyPath([wanted, await publicJwk('key-b')]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' })
    ).resolves.toBeDefined();
  });

  it('resolves NOTHING for a `kid` that names no published key (no try-them-all fallback)', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({
        issuer: ISSUER,
        keyId: 'key-missing',
        algorithm: 'EdDSA',
      })
    ).resolves.toBeUndefined();
  });

  it('resolves NOTHING when no `kid` is supplied and the key set is ambiguous', async () => {
    wireHappyPath([await publicJwk('key-a'), await publicJwk('key-b')]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses a key set whose entry carries private material', async () => {
    const { privateKey } = await generateSigningKeyPair('EdDSA', { extractable: true });
    const privateJwk = await exportJWK(privateKey);
    wireHappyPath([privateJwk]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses a key whose `kty` does not match the pinned algorithm', async () => {
    // An OKP key offered for RS256 must never import — that is algorithm confusion.
    wireHappyPath([await publicJwk()]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'RS256' })
    ).resolves.toBeUndefined();
  });

  it('refuses a key its publisher marked `use: "enc"`', async () => {
    const jwk = await publicJwk();
    wireHappyPath([{ ...jwk, use: 'enc' }]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });
});

describe('createIdJagIssuerKeyResolver — document validation', () => {
  it('refuses metadata that declares a DIFFERENT issuer than the one it was fetched under', async () => {
    wireHappyPath([await publicJwk()], { documentIssuer: 'https://someone-else.example.com' });
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses a non-https `jwks_uri`', async () => {
    ssrfSafeGet.mockImplementation(async (url: string) => {
      if (url === DISCOVERY_URL) {
        return ok({ issuer: ISSUER, jwks_uri: 'http://idp.example.com/jwks.json' });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses a non-200 discovery response', async () => {
    ssrfSafeGet.mockResolvedValue({ status: 404, body: '{}', headers: {} });
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses an unparseable document', async () => {
    ssrfSafeGet.mockResolvedValue({ status: 200, body: 'not json', headers: {} });
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses an empty JWK Set', async () => {
    wireHappyPath([]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('surfaces an SSRF-blocked target as "no key" rather than an exception', async () => {
    ssrfSafeGet.mockRejectedValue(new SsrfBlockedError('host resolves to a non-public address'));
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });
});

describe('createIdJagIssuerKeyResolver — caching', () => {
  it('serves the second resolution from cache without re-fetching', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' });
    const fetchesAfterFirst = ssrfSafeGet.mock.calls.length;
    await resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' });

    expect(ssrfSafeGet.mock.calls.length).toBe(fetchesAfterFirst);
  });

  it('re-fetches when `forceRefresh` is set, so a rotated key is picked up', async () => {
    wireHappyPath([await publicJwk('old-kid')]);
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await resolve({ issuer: ISSUER, keyId: 'old-kid', algorithm: 'EdDSA' });

    // The issuer rotates: a new kid replaces the old one.
    wireHappyPath([await publicJwk('new-kid')]);
    await expect(
      resolve({ issuer: ISSUER, keyId: 'new-kid', algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
    await expect(
      resolve({ issuer: ISSUER, keyId: 'new-kid', algorithm: 'EdDSA', forceRefresh: true })
    ).resolves.toBeDefined();
  });

  it('does not write to the cache when the TTL is zero', async () => {
    ENV.ID_JAG_JWKS_CACHE_TTL = 0;
    wireHappyPath([await publicJwk()]);
    const { fastify, redis } = fastifyStub();

    await createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' });

    expect(redis.keys()).toEqual([]);
  });

  it('treats an unreachable cache as a miss rather than a failure', async () => {
    wireHappyPath([await publicJwk()]);
    const { fastify } = fastifyStub();
    fastify.redis.get.mockRejectedValue(new Error('redis down'));
    fastify.redis.set.mockRejectedValue(new Error('redis down'));

    await expect(
      createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeDefined();
  });
});

describe('createIdJagIssuerKeyResolver — refresh cooldown (#433)', () => {
  const COOLDOWN_KEY = REDIS_KEYS.ID_JAG_KEY_REFRESH(ISSUER);

  it('claims the cooldown with SET NX EX before it fetches anything', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();

    await createIdJagIssuerKeyResolver(fastify)({
      issuer: ISSUER,
      keyId: 'key-a',
      algorithm: 'EdDSA',
      forceRefresh: true,
    });

    const claim = redis.set.mock.calls.findIndex(([key]) => key === COOLDOWN_KEY);
    expect(redis.set.mock.calls[claim]).toEqual([COOLDOWN_KEY, '1', 'EX', 30, 'NX']);
    expect(redis.set.mock.invocationCallOrder[claim]).toBeLessThan(
      ssrfSafeGet.mock.invocationCallOrder[0]
    );
  });

  it('refuses a second forced refresh inside the cooldown, without a fetch', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);
    const refresh = {
      issuer: ISSUER,
      keyId: 'key-a',
      algorithm: 'EdDSA',
      forceRefresh: true,
    } as const;

    await expect(resolve(refresh)).resolves.toBeDefined();
    const fetches = ssrfSafeGet.mock.calls.length;

    redis.advance(29);
    await expect(resolve(refresh)).resolves.toBeUndefined();
    expect(ssrfSafeGet.mock.calls.length).toBe(fetches);

    redis.advance(1);
    await expect(resolve(refresh)).resolves.toBeDefined();
    expect(ssrfSafeGet.mock.calls.length).toBe(fetches * 2);
  });

  it('takes its length from ID_JAG_JWKS_REFRESH_COOLDOWN', async () => {
    ENV.ID_JAG_JWKS_REFRESH_COOLDOWN = 5;
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA', forceRefresh: true });
    expect(redis.set).toHaveBeenCalledWith(COOLDOWN_KEY, '1', 'EX', 5, 'NX');

    redis.advance(5);
    await expect(
      resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA', forceRefresh: true })
    ).resolves.toBeDefined();
  });

  it('keeps one cooldown per issuer', async () => {
    const first = await createFakeIdJagIssuer(ISSUER);
    const second = await createFakeIdJagIssuer('https://other-idp.example.com');
    ENV.ID_JAG_TRUSTED_ISSUERS = [first.issuer, second.issuer];
    ssrfSafeGet.mockImplementation((url: string) =>
      url.startsWith(`${first.issuer}/`) ? first.fetch(url) : second.fetch(url)
    );
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await resolve({ issuer: first.issuer, keyId: 'x', algorithm: 'EdDSA', forceRefresh: true });
    await resolve({ issuer: second.issuer, keyId: 'x', algorithm: 'EdDSA', forceRefresh: true });

    expect(first.totalFetches()).toBe(2);
    expect(second.totalFetches()).toBe(2);
  });

  it('refuses a forced refresh when the cooldown cannot be claimed', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();
    redis.set.mockRejectedValue(new Error('redis down'));

    await expect(
      createIdJagIssuerKeyResolver(fastify)({
        issuer: ISSUER,
        keyId: 'key-a',
        algorithm: 'EdDSA',
        forceRefresh: true,
      })
    ).resolves.toBeUndefined();
    expect(ssrfSafeGet).not.toHaveBeenCalled();
  });

  it('does not hold an ordinary cache miss to the cooldown', async () => {
    // Nothing is cached, so every resolution misses and fetches on its own.
    ENV.ID_JAG_JWKS_CACHE_TTL = 0;
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA', forceRefresh: true });
    await expect(
      resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' })
    ).resolves.toBeDefined();
    expect(ssrfSafeGet).toHaveBeenCalledTimes(4);
  });
});

describe('createIdJagIssuerKeyResolver — negative cache (#433)', () => {
  const FAILED_KEY = REDIS_KEYS.ID_JAG_FETCH_FAILED(ISSUER);

  it('remembers a failed fetch for ID_JAG_JWKS_NEGATIVE_CACHE_TTL and fetches nothing meanwhile', async () => {
    ENV.ID_JAG_JWKS_NEGATIVE_CACHE_TTL = 7;
    ssrfSafeGet.mockRejectedValue(new Error('connect ETIMEDOUT'));
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    expect(redis.set).toHaveBeenCalledWith(FAILED_KEY, '1', 'EX', 7);
    expect(ssrfSafeGet).toHaveBeenCalledTimes(1);

    redis.advance(6);
    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    expect(ssrfSafeGet).toHaveBeenCalledTimes(1);

    redis.advance(1);
    wireHappyPath([await publicJwk()]);
    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeDefined();
  });

  it('remembers a failed JWKS fetch after a good discovery fetch', async () => {
    ssrfSafeGet.mockImplementation(async (url: string) => {
      if (url === DISCOVERY_URL) return ok({ issuer: ISSUER, jwks_uri: JWKS_URI });
      return { status: 503, body: '', headers: {} };
    });
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();

    expect(ssrfSafeGet.mock.calls.map(([url]) => url)).toEqual([DISCOVERY_URL, JWKS_URI]);
  });

  it('counts a document that fails validation as a failed fetch', async () => {
    wireHappyPath([await publicJwk()], { documentIssuer: 'https://someone-else.example.com' });
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);

    await resolve({ issuer: ISSUER, algorithm: 'EdDSA' });
    await resolve({ issuer: ISSUER, algorithm: 'EdDSA' });

    expect(ssrfSafeGet).toHaveBeenCalledTimes(1);
    expect(redis.keys()).toContain(FAILED_KEY);
  });

  it('writes no failure after a successful fetch', async () => {
    wireHappyPath([await publicJwk()]);
    const { fastify, redis } = fastifyStub();

    await createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' });

    expect(redis.keys()).not.toContain(FAILED_KEY);
  });

  it('is not consulted while the documents are cached', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);
    await resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' });

    await redis.set(FAILED_KEY, '1', 'EX', 30);
    await expect(
      resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' })
    ).resolves.toBeDefined();
  });

  it('refuses a forced refresh while a failure is on record, without spending the cooldown', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify);
    await redis.set(FAILED_KEY, '1', 'EX', 30);

    await expect(
      resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA', forceRefresh: true })
    ).resolves.toBeUndefined();
    expect(ssrfSafeGet).not.toHaveBeenCalled();
    expect(redis.keys()).not.toContain(REDIS_KEYS.ID_JAG_KEY_REFRESH(ISSUER));

    redis.advance(30);
    await expect(
      resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA', forceRefresh: true })
    ).resolves.toBeDefined();
  });
});
