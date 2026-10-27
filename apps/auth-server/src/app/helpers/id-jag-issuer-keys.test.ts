import { generateSigningKeyPair } from '@qauth-labs/core-crypto';
import { exportJWK, type JWK } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { ENV, egressGet } = vi.hoisted(() => ({
  ENV: {
    ID_JAG_ENABLED: true,
    ID_JAG_TRUSTED_ISSUERS: [] as string[],
    ID_JAG_FETCH_TIMEOUT_MS: 5000,
    ID_JAG_JWKS_CACHE_TTL: 300,
    ID_JAG_JWKS_REFRESH_COOLDOWN: 30,
    ID_JAG_JWKS_NEGATIVE_CACHE_TTL: 30,
    ID_JAG_MAX_DOCUMENT_BYTES: 65536,
  },
  egressGet: vi.fn(),
}));

vi.mock('../../config/env', () => ({ env: ENV }));

vi.mock('./egress-get', () => ({ egressGet }));

import { blockedEgress } from '../../testing/egress';
import { createExpiringRedis, createFakeIdJagIssuer } from '../../testing/fake-id-jag-issuer';
import { REDIS_KEYS } from '../constants/redis-keys';
import {
  createIdJagIssuerKeyResolver,
  ID_JAG_SIGNING_ALG_VALUES_SUPPORTED,
  isSupportedIdJagAlgorithm,
  resolveTrustedIdJagIssuer,
} from './id-jag-issuer-keys';

/** The realm the assertions are presented to; the allowlist would apply to its discovery fetch. */
const REALM = 'master';

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
  egressGet.mockImplementation(async (_fastify: unknown, url: string) => {
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
  egressGet.mockReset();
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
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    expect(egressGet).not.toHaveBeenCalled();
  });

  it('never fetches anything when the allowlist is empty', async () => {
    ENV.ID_JAG_TRUSTED_ISSUERS = [];
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    expect(egressGet).not.toHaveBeenCalled();
  });

  it('never fetches anything for an issuer outside the allowlist', async () => {
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

    await expect(
      resolve({ issuer: 'https://evil.example.com', algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
    expect(egressGet).not.toHaveBeenCalled();
  });
});

describe('createIdJagIssuerKeyResolver — key resolution', () => {
  it('resolves the single published key and reports the confirmed identifier', async () => {
    wireHappyPath([await publicJwk()]);
    const { fastify } = fastifyStub();

    const resolved = await createIdJagIssuerKeyResolver(
      fastify,
      REALM
    )({
      issuer: `${ISSUER}/`,
      algorithm: 'EdDSA',
    });

    expect(resolved).toBeDefined();
    // The CONFIRMED identifier is the canonical allowlist entry, not the raw claim.
    expect(resolved?.identifier).toBe(ISSUER);
    expect(egressGet).toHaveBeenCalledWith(
      expect.anything(),
      DISCOVERY_URL,
      expect.objectContaining({ purpose: 'id-jag-discovery', source: 'operator', realm: REALM })
    );
    expect(egressGet).toHaveBeenCalledWith(
      expect.anything(),
      JWKS_URI,
      expect.objectContaining({ purpose: 'id-jag-jwks', source: 'remote_document' })
    );
  });

  it('selects exactly the key named by `kid`', async () => {
    const wanted = await publicJwk('key-a');
    wireHappyPath([wanted, await publicJwk('key-b')]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(
        fastify,
        REALM
      )({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' })
    ).resolves.toBeDefined();
  });

  it('resolves NOTHING for a `kid` that names no published key (no try-them-all fallback)', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(
        fastify,
        REALM
      )({
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
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses a key set whose entry carries private material', async () => {
    const { privateKey } = await generateSigningKeyPair('EdDSA', { extractable: true });
    const privateJwk = await exportJWK(privateKey);
    wireHappyPath([privateJwk]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses a key whose `kty` does not match the pinned algorithm', async () => {
    // An OKP key offered for RS256 must never import — that is algorithm confusion.
    wireHappyPath([await publicJwk()]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'RS256' })
    ).resolves.toBeUndefined();
  });

  it('refuses a key its publisher marked `use: "enc"`', async () => {
    const jwk = await publicJwk();
    wireHappyPath([{ ...jwk, use: 'enc' }]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });
});

describe('createIdJagIssuerKeyResolver — document validation', () => {
  it('refuses metadata that declares a DIFFERENT issuer than the one it was fetched under', async () => {
    wireHappyPath([await publicJwk()], { documentIssuer: 'https://someone-else.example.com' });
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses a non-https `jwks_uri`', async () => {
    egressGet.mockImplementation(async (_fastify: unknown, url: string) => {
      if (url === DISCOVERY_URL) {
        return ok({ issuer: ISSUER, jwks_uri: 'http://idp.example.com/jwks.json' });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses a non-200 discovery response', async () => {
    egressGet.mockResolvedValue({ status: 404, body: '{}', headers: {} });
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses an unparseable document', async () => {
    egressGet.mockResolvedValue({ status: 200, body: 'not json', headers: {} });
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('refuses an empty JWK Set', async () => {
    wireHappyPath([]);
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });

  it('surfaces an SSRF-blocked target as "no key" rather than an exception', async () => {
    egressGet.mockRejectedValue(blockedEgress('host resolves to a non-public address'));
    const { fastify } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
  });
});

describe('createIdJagIssuerKeyResolver — caching', () => {
  it('serves the second resolution from cache without re-fetching', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

    await resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' });
    const fetchesAfterFirst = egressGet.mock.calls.length;
    await resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' });

    expect(egressGet.mock.calls.length).toBe(fetchesAfterFirst);
  });

  it('re-fetches when `forceRefresh` is set, so a rotated key is picked up', async () => {
    wireHappyPath([await publicJwk('old-kid')]);
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

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

    await createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' });

    expect(redis.keys()).toEqual([]);
  });

  it('treats an unreachable cache as a miss rather than a failure', async () => {
    wireHappyPath([await publicJwk()]);
    const { fastify } = fastifyStub();
    fastify.redis.get.mockRejectedValue(new Error('redis down'));
    fastify.redis.set.mockRejectedValue(new Error('redis down'));

    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeDefined();
  });
});

describe('createIdJagIssuerKeyResolver — refresh cooldown (#433)', () => {
  const COOLDOWN_KEY = REDIS_KEYS.ID_JAG_KEY_REFRESH(ISSUER);

  it('claims the cooldown with SET NX EX before it fetches anything', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();

    await createIdJagIssuerKeyResolver(
      fastify,
      REALM
    )({
      issuer: ISSUER,
      keyId: 'key-a',
      algorithm: 'EdDSA',
      forceRefresh: true,
    });

    const claim = redis.set.mock.calls.findIndex(([key]) => key === COOLDOWN_KEY);
    expect(redis.set.mock.calls[claim]).toEqual([COOLDOWN_KEY, '1', 'EX', 30, 'NX']);
    expect(redis.set.mock.invocationCallOrder[claim]).toBeLessThan(
      egressGet.mock.invocationCallOrder[0]
    );
  });

  it('refuses a second forced refresh inside the cooldown, without a fetch', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);
    const refresh = {
      issuer: ISSUER,
      keyId: 'key-a',
      algorithm: 'EdDSA',
      forceRefresh: true,
    } as const;

    await expect(resolve(refresh)).resolves.toBeDefined();
    const fetches = egressGet.mock.calls.length;

    redis.advance(29);
    await expect(resolve(refresh)).resolves.toBeUndefined();
    expect(egressGet.mock.calls.length).toBe(fetches);

    redis.advance(1);
    await expect(resolve(refresh)).resolves.toBeDefined();
    expect(egressGet.mock.calls.length).toBe(fetches * 2);
  });

  it('takes its length from ID_JAG_JWKS_REFRESH_COOLDOWN', async () => {
    ENV.ID_JAG_JWKS_REFRESH_COOLDOWN = 5;
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

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
    egressGet.mockImplementation((_fastify: unknown, url: string) =>
      url.startsWith(`${first.issuer}/`) ? first.fetch(url) : second.fetch(url)
    );
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

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
      createIdJagIssuerKeyResolver(
        fastify,
        REALM
      )({
        issuer: ISSUER,
        keyId: 'key-a',
        algorithm: 'EdDSA',
        forceRefresh: true,
      })
    ).resolves.toBeUndefined();
    expect(egressGet).not.toHaveBeenCalled();
  });

  it('does not hold an ordinary cache miss to the cooldown', async () => {
    // Nothing is cached, so every resolution misses and fetches on its own.
    ENV.ID_JAG_JWKS_CACHE_TTL = 0;
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

    await resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA', forceRefresh: true });
    await expect(
      resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' })
    ).resolves.toBeDefined();
    expect(egressGet).toHaveBeenCalledTimes(4);
  });
});

describe('createIdJagIssuerKeyResolver — negative cache (#433)', () => {
  const FAILED_KEY = REDIS_KEYS.ID_JAG_FETCH_FAILED(ISSUER);

  it('remembers a failed fetch for ID_JAG_JWKS_NEGATIVE_CACHE_TTL and fetches nothing meanwhile', async () => {
    ENV.ID_JAG_JWKS_NEGATIVE_CACHE_TTL = 7;
    egressGet.mockRejectedValue(new Error('connect ETIMEDOUT'));
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    expect(redis.set).toHaveBeenCalledWith(FAILED_KEY, '1', 'EX', 7);
    expect(egressGet).toHaveBeenCalledTimes(1);

    redis.advance(6);
    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    expect(egressGet).toHaveBeenCalledTimes(1);

    redis.advance(1);
    wireHappyPath([await publicJwk()]);
    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeDefined();
  });

  it('remembers a failed JWKS fetch after a good discovery fetch', async () => {
    egressGet.mockImplementation(async (_fastify: unknown, url: string) => {
      if (url === DISCOVERY_URL) return ok({ issuer: ISSUER, jwks_uri: JWKS_URI });
      return { status: 503, body: '', headers: {} };
    });
    const { fastify } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();

    expect(egressGet.mock.calls.map(([, url]) => url)).toEqual([DISCOVERY_URL, JWKS_URI]);
  });

  it('counts a document that fails validation as a failed fetch', async () => {
    wireHappyPath([await publicJwk()], { documentIssuer: 'https://someone-else.example.com' });
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);

    await resolve({ issuer: ISSUER, algorithm: 'EdDSA' });
    await resolve({ issuer: ISSUER, algorithm: 'EdDSA' });

    expect(egressGet).toHaveBeenCalledTimes(1);
    expect(redis.keys()).toContain(FAILED_KEY);
  });

  // #481: whether the discovery fetch may reach a private address depends on
  // the realm (the deployment allowlist), so a refusal by the address check
  // says nothing about the issuer and must not hold it back for a realm the
  // allowlist opens it for.
  it('does not remember a discovery fetch the address check refused', async () => {
    egressGet.mockRejectedValue(blockedEgress('resolves to a private address'));
    const { fastify, redis } = fastifyStub();

    await expect(
      createIdJagIssuerKeyResolver(fastify, 'other')({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
    expect(redis.keys()).not.toContain(FAILED_KEY);

    wireHappyPath([await publicJwk()]);
    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeDefined();
  });

  it('still remembers a discovery fetch refused for a reason no realm changes', async () => {
    egressGet.mockRejectedValue(blockedEgress('redirect refused', 'redirect'));
    const { fastify, redis } = fastifyStub();

    await createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' });

    expect(redis.keys()).toContain(FAILED_KEY);
  });

  it('still remembers a refused jwks_uri, which no realm may reach', async () => {
    egressGet.mockImplementation(async (_fastify: unknown, url: string) => {
      if (url === DISCOVERY_URL) return ok({ issuer: ISSUER, jwks_uri: JWKS_URI });
      throw blockedEgress('resolves to a private address');
    });
    const { fastify, redis } = fastifyStub();

    await createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' });

    expect(redis.keys()).toContain(FAILED_KEY);
  });

  it('remembers a refused discovery fetch for the realm alone, for 60 seconds', async () => {
    egressGet.mockRejectedValue(blockedEgress('resolves to a private address'));
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, 'other');
    const refusedKey = REDIS_KEYS.ID_JAG_FETCH_REFUSED(ISSUER, 'other');

    await expect(resolve({ issuer: ISSUER, algorithm: 'EdDSA' })).resolves.toBeUndefined();
    expect(redis.set).toHaveBeenCalledWith(refusedKey, '1', 'EX', 60);
    expect(redis.keys()).not.toContain(REDIS_KEYS.ID_JAG_FETCH_REFUSED(ISSUER, REALM));

    // A forced refresh is held back too: the name is not resolved again.
    redis.advance(59);
    await expect(
      resolve({ issuer: ISSUER, algorithm: 'EdDSA', forceRefresh: true })
    ).resolves.toBeUndefined();
    expect(egressGet).toHaveBeenCalledTimes(1);

    redis.advance(1);
    await resolve({ issuer: ISSUER, algorithm: 'EdDSA' });
    expect(egressGet).toHaveBeenCalledTimes(2);
  });

  // A document one realm fetched through its allowlist entry must not answer
  // for a realm the allowlist does not open the issuer's address for.
  it("never answers one realm's discovery from another realm's cached document", async () => {
    wireHappyPath([await publicJwk()]);
    const { fastify } = fastifyStub();
    await expect(
      createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeDefined();

    egressGet.mockReset();
    egressGet.mockRejectedValue(blockedEgress('resolves to a private address'));
    await expect(
      createIdJagIssuerKeyResolver(fastify, 'other')({ issuer: ISSUER, algorithm: 'EdDSA' })
    ).resolves.toBeUndefined();
    expect(egressGet).toHaveBeenCalledTimes(1);
    expect(egressGet).toHaveBeenCalledWith(
      fastify,
      DISCOVERY_URL,
      expect.objectContaining({ source: 'operator', realm: 'other' })
    );
  });

  it("logs the host of a failed document fetch, never the remote document's URL", async () => {
    const secretPath = 'https://keys.example.net/tenant-7f3a/jwks.json?sig=abc';
    egressGet.mockImplementation(async (_fastify: unknown, url: string) => {
      if (url === DISCOVERY_URL) return ok({ issuer: ISSUER, jwks_uri: secretPath });
      return { status: 503, body: '', headers: {} };
    });
    const { fastify } = fastifyStub();

    await createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' });

    expect(fastify.log.debug).toHaveBeenCalledWith(
      { host: 'keys.example.net', what: 'jwks', status: 503 },
      'ID-JAG issuer document not 200'
    );
    expect(JSON.stringify(fastify.log.debug.mock.calls)).not.toContain('tenant-7f3a');
  });

  it('shares a discovery fetch in flight within one realm only', async () => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const jwk = await publicJwk();
    egressGet.mockImplementation(async (_fastify: unknown, url: string) => {
      if (url === DISCOVERY_URL) {
        await held;
        return ok({ issuer: ISSUER, jwks_uri: JWKS_URI });
      }
      return ok({ keys: [jwk] });
    });
    const { fastify } = fastifyStub();
    const request = { issuer: ISSUER, algorithm: 'EdDSA' as const };

    const resolutions = [
      createIdJagIssuerKeyResolver(fastify, REALM)(request),
      createIdJagIssuerKeyResolver(fastify, REALM)(request),
      createIdJagIssuerKeyResolver(fastify, 'other')(request),
    ];
    await vi.waitFor(() =>
      expect(egressGet.mock.calls.filter(([, url]) => url === DISCOVERY_URL)).toHaveLength(2)
    );
    release();
    await Promise.all(resolutions);

    expect(egressGet.mock.calls.filter(([, url]) => url === DISCOVERY_URL)).toHaveLength(2);
    expect(egressGet.mock.calls.map(([, , options]) => options.realm)).toEqual(
      expect.arrayContaining([REALM, 'other'])
    );
  });

  it('writes no failure after a successful fetch', async () => {
    wireHappyPath([await publicJwk()]);
    const { fastify, redis } = fastifyStub();

    await createIdJagIssuerKeyResolver(fastify, REALM)({ issuer: ISSUER, algorithm: 'EdDSA' });

    expect(redis.keys()).not.toContain(FAILED_KEY);
  });

  it('is not consulted while the documents are cached', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);
    await resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' });

    await redis.set(FAILED_KEY, '1', 'EX', 30);
    await expect(
      resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA' })
    ).resolves.toBeDefined();
  });

  it('refuses a forced refresh while a failure is on record, without spending the cooldown', async () => {
    wireHappyPath([await publicJwk('key-a')]);
    const { fastify, redis } = fastifyStub();
    const resolve = createIdJagIssuerKeyResolver(fastify, REALM);
    await redis.set(FAILED_KEY, '1', 'EX', 30);

    await expect(
      resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA', forceRefresh: true })
    ).resolves.toBeUndefined();
    expect(egressGet).not.toHaveBeenCalled();
    expect(redis.keys()).not.toContain(REDIS_KEYS.ID_JAG_KEY_REFRESH(ISSUER));

    redis.advance(30);
    await expect(
      resolve({ issuer: ISSUER, keyId: 'key-a', algorithm: 'EdDSA', forceRefresh: true })
    ).resolves.toBeDefined();
  });
});
