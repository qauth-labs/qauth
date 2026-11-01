import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { getJsonObject } from '../../helpers/http';
import { call } from '../../helpers/operations';

const { baseUrl } = wireConfig();

/**
 * Members that only a private or symmetric key carries (RFC 7518 §6.2.2, §6.3.2,
 * §6.4.1; RFC 8037 §2). None may appear in a published key set.
 */
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;

/** The post-quantum key the server publishes beside the classical ones when hybrid signing is on. */
const HYBRID_ALGORITHM = 'ML-DSA-65';

/** `application/jwk-set+json` (RFC 7517 §8.5); plain JSON is accepted too. */
const JWK_SET_CONTENT_TYPE = /^application\/(jwk-set\+)?json\b/i;

async function discovery(): Promise<Record<string, unknown>> {
  const { body } = await getJsonObject(serverPath(baseUrl, '/.well-known/openid-configuration'));
  return body;
}

async function discoveredKeySet(): Promise<Record<string, unknown>[]> {
  const jwksUri = (await discovery())['jwks_uri'];
  expect(jwksUri, 'discovery names a jwks_uri').toBeTypeOf('string');

  const { body } = await getJsonObject(jwksUri as string, JWK_SET_CONTENT_TYPE);
  expect(Array.isArray(body['keys']), 'the key set has a "keys" array').toBe(true);
  return body['keys'] as Record<string, unknown>[];
}

describe('RFC 7517 §5 — the JWK Set at the discovered jwks_uri', () => {
  it('answers 200 with a JSON object whose "keys" array is not empty', async () => {
    const keys = await discoveredKeySet();

    expect(keys.length).toBeGreaterThan(0);
  });

  it('is served at the jwks_uri path as application/jwk-set+json (§8.5)', async () => {
    const response = await call('GET /.well-known/jwks.json');
    await response.body?.cancel();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type') ?? '').toMatch(/^application\/jwk-set\+json\b/i);
    expect((await discovery())['jwks_uri']).toBe(serverPath(baseUrl, '/.well-known/jwks.json'));
  });

  it('publishes public keys only, each with a "kty" (§4.1)', async () => {
    const keys = await discoveredKeySet();

    for (const key of keys) {
      expect(key['kty'], JSON.stringify(key)).toBeTypeOf('string');
      for (const member of PRIVATE_MEMBERS) {
        expect(key, `a published key carries "${member}"`).not.toHaveProperty(member);
      }
    }
  });

  it('gives every key its own "kid", so a token header selects exactly one (§4.5)', async () => {
    const keys = await discoveredKeySet();

    const kids = keys.map((key) => key['kid']);
    for (const kid of kids) expect(kid, JSON.stringify(kids)).toBeTypeOf('string');
    expect(new Set(kids).size, JSON.stringify(kids)).toBe(kids.length);
  });

  it('marks every key for signatures, with an algorithm discovery advertises (§4.2, §4.4)', async () => {
    const keys = await discoveredKeySet();
    const advertised = (await discovery())['id_token_signing_alg_values_supported'] as string[];

    for (const key of keys) {
      if (key['use'] !== undefined) expect(key['use'], JSON.stringify(key)).toBe('sig');
      expect(key['alg'], JSON.stringify(key)).toBeTypeOf('string');
      // The hybrid key signs beside a classical signature; it is never an ID
      // token's only algorithm, so discovery does not list it.
      if (key['alg'] !== HYBRID_ALGORITHM) {
        expect(advertised, JSON.stringify(key)).toContain(key['alg']);
      }
    }
    // And every advertised algorithm has a key to verify it.
    for (const algorithm of advertised) {
      expect(
        keys.some((key) => key['alg'] === algorithm),
        `no published key for ${algorithm}`
      ).toBe(true);
    }
  });
});
