import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import {
  basicAuthorization,
  confidentialClient,
  SEEDED_CLIENT_SCOPE,
} from '../../fixtures/clients';
import { getJsonObject } from '../../helpers/http';
import { remoteKeySet, verifyJwt } from '../../helpers/jwt';

const { baseUrl } = wireConfig();

/**
 * The smallest end-to-end check that the run is wired: the client the CI job
 * seeded can authenticate, and the token it gets verifies against the key set
 * the server publishes. The full token-endpoint matrix belongs to later suites.
 */
describe('RFC 6749 §4.4 — the client credentials grant, with the seeded client', () => {
  it('issues a Bearer access token that verifies against the discovered JWKS (§4.4.3)', async () => {
    const { body: metadata } = await getJsonObject(
      serverPath(baseUrl, '/.well-known/oauth-authorization-server')
    );
    const client = confidentialClient();

    const response = await fetch(metadata['token_endpoint'] as string, {
      method: 'POST',
      headers: {
        authorization: basicAuthorization(client),
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ grant_type: 'client_credentials', scope: SEEDED_CLIENT_SCOPE }),
      redirect: 'manual',
    });
    const text = await response.text();
    expect(response.status, text).toBe(200);
    expect(response.headers.get('content-type') ?? '').toMatch(/^application\/json\b/i);
    expect(response.headers.get('cache-control') ?? '', 'RFC 6749 §5.1 no-store').toMatch(
      /no-store/i
    );

    const token = JSON.parse(text) as Record<string, unknown>;
    expect(String(token['token_type']).toLowerCase()).toBe('bearer');
    expect(token['expires_in']).toBeTypeOf('number');
    expect(token).not.toHaveProperty('refresh_token');

    const { payload } = await verifyJwt(
      token['access_token'] as string,
      remoteKeySet(metadata['jwks_uri'] as string),
      { issuer: baseUrl }
    );
    expect(payload['client_id']).toBe(client.id);
    expect(String(payload['scope']).split(' ')).toContain(SEEDED_CLIENT_SCOPE);
  });
});
