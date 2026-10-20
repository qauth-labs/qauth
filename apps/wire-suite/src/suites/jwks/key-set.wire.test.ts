import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { getJsonObject } from '../../helpers/http';

const { baseUrl } = wireConfig();

/**
 * Members that only a private or symmetric key carries (RFC 7518 §6.2.2, §6.3.2,
 * §6.4.1; RFC 8037 §2). None may appear in a published key set.
 */
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;

async function discoveredKeySet(): Promise<Record<string, unknown>[]> {
  const { body: configuration } = await getJsonObject(
    serverPath(baseUrl, '/.well-known/openid-configuration')
  );
  const jwksUri = configuration['jwks_uri'];
  expect(jwksUri, 'discovery names a jwks_uri').toBeTypeOf('string');

  // RFC 7517 §8.5 registers application/jwk-set+json; plain JSON is accepted too.
  const { body } = await getJsonObject(jwksUri as string, /^application\/(jwk-set\+)?json\b/i);
  expect(Array.isArray(body['keys']), 'the key set has a "keys" array').toBe(true);
  return body['keys'] as Record<string, unknown>[];
}

describe('RFC 7517 §5 — the JWK Set at the discovered jwks_uri', () => {
  it('answers 200 with a JSON object whose "keys" array is not empty', async () => {
    const keys = await discoveredKeySet();

    expect(keys.length).toBeGreaterThan(0);
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
});
