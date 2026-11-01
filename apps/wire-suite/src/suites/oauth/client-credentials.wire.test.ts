import { describe, expect, it } from 'vitest';

import { wireConfig } from '../../config';
import { type ClientAuthentication, tokenRequest } from '../../fixtures/authorization';
import {
  basicAuthorization,
  confidentialClient,
  SEEDED_CLIENT_SCOPE,
} from '../../fixtures/clients';
import { expectOAuthError } from '../../helpers/error-shape';
import { getJsonObject } from '../../helpers/http';
import { remoteKeySet, verifyJwt } from '../../helpers/jwt';
import { call } from '../../helpers/operations';

const { baseUrl } = wireConfig();

function clientCredentials(
  authentication: ClientAuthentication,
  scope: string = SEEDED_CLIENT_SCOPE
): Promise<Response> {
  return tokenRequest({ grant_type: 'client_credentials', scope }, authentication);
}

/**
 * The smallest end-to-end check that the run is wired: the client the CI job
 * seeded can authenticate, and the token it gets verifies against the key set
 * the server publishes.
 */
describe('RFC 6749 §4.4 — the client credentials grant, with the seeded client', () => {
  it('issues a Bearer access token that verifies against the discovered JWKS (§4.4.3)', async () => {
    const { body: metadata } = await getJsonObject(
      `${baseUrl.replace(/\/$/, '')}/.well-known/oauth-authorization-server`
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
    expect(token).not.toHaveProperty('id_token');

    const { payload } = await verifyJwt(
      token['access_token'] as string,
      remoteKeySet(metadata['jwks_uri'] as string),
      { issuer: baseUrl, typ: 'at+jwt' }
    );
    expect(payload['client_id']).toBe(client.id);
    expect(String(payload['scope']).split(' ')).toContain(SEEDED_CLIENT_SCOPE);
  });

  it('refuses a scope the client was not given with 400 invalid_scope (§4.4.2, §5.2)', async () => {
    await expectOAuthError(await clientCredentials('client_secret_basic', 'wire:write'), {
      status: 400,
      error: 'invalid_scope',
    });
  });
});

describe('RFC 6749 §2.3.1 — client password authentication at the token endpoint', () => {
  it.each(['client_secret_basic', 'client_secret_post'] as const)(
    'authenticates the client with %s (§2.3.1)',
    async (authentication) => {
      const response = await clientCredentials(authentication);
      const text = await response.text();

      expect(response.status, text).toBe(200);
      expect(JSON.parse(text)).toHaveProperty('access_token');
    }
  );

  it('refuses a wrong secret in the Basic header with 401 invalid_client and a Basic challenge (§2.3.1, §5.2)', async () => {
    const client = { ...confidentialClient(), secret: 'wire-suite-wrong-secret' };

    const response = await tokenRequest(
      { grant_type: 'client_credentials', scope: SEEDED_CLIENT_SCOPE },
      'client_secret_basic',
      client
    );

    expect(response.headers.get('www-authenticate') ?? '').toMatch(/^Basic\b/i);
    await expectOAuthError(response, { status: 401, error: 'invalid_client' });
  });

  it('refuses a wrong secret in the body with 401 invalid_client (§2.3.1, §5.2)', async () => {
    const client = { ...confidentialClient(), secret: 'wire-suite-wrong-secret' };

    await expectOAuthError(
      await tokenRequest(
        { grant_type: 'client_credentials', scope: SEEDED_CLIENT_SCOPE },
        'client_secret_post',
        client
      ),
      { status: 401, error: 'invalid_client' }
    );
  });

  it('refuses a request that authenticates with both methods at once with 401 invalid_client (§2.3)', async () => {
    const client = confidentialClient();

    await expectOAuthError(
      await call('POST /oauth/token', {
        headers: { authorization: basicAuthorization(client) },
        form: {
          grant_type: 'client_credentials',
          scope: SEEDED_CLIENT_SCOPE,
          client_id: client.id,
          client_secret: client.secret,
        },
      }),
      { status: 401, error: 'invalid_client' }
    );
  });
});
