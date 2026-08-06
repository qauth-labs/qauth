import { generateSigningKeyPair } from '@qauth-labs/core-crypto';
import { exportJWK, type JWK } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { ENV, ssrfSafeGet } = vi.hoisted(() => ({
  ENV: {
    ID_JAG_ENABLED: true,
    ID_JAG_TRUSTED_ISSUERS: [] as string[],
    ID_JAG_FETCH_TIMEOUT_MS: 5000,
    ID_JAG_JWKS_CACHE_TTL: 300,
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

/** Minimal in-memory `fastify.redis` stand-in (no TTL clock). */
function fastifyStub() {
  const store = new Map<string, string>();
  return {
    store,
    fastify: {
      redis: {
        get: vi.fn(async (k: string) => store.get(k) ?? null),
        set: vi.fn(async (k: string, v: string) => {
          store.set(k, v);
          return 'OK';
        }),
      },
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
    const { fastify, store } = fastifyStub();

    await createIdJagIssuerKeyResolver(fastify)({ issuer: ISSUER, algorithm: 'EdDSA' });

    expect(store.size).toBe(0);
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
