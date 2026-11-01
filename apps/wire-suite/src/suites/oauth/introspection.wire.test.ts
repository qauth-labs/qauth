import { describe, expect, it } from 'vitest';

import { wireConfig } from '../../config';
import {
  type ClientAuthentication,
  readTokenResponse,
  tokenRequest,
} from '../../fixtures/authorization';
import {
  basicAuthorization,
  confidentialClient,
  SEEDED_CLIENT_SCOPE,
} from '../../fixtures/clients';
import { call } from '../../helpers/operations';

const { baseUrl } = wireConfig();

/** An access token the seeded client gets for itself. */
async function clientToken(): Promise<string> {
  const tokens = await readTokenResponse(
    await tokenRequest({ grant_type: 'client_credentials', scope: SEEDED_CLIENT_SCOPE })
  );
  return tokens.access_token;
}

/** Introspect `token` as the seeded client, and read the 200 JSON answer. */
async function introspect(
  token: string,
  authentication: ClientAuthentication = 'client_secret_basic'
): Promise<Record<string, unknown>> {
  const client = confidentialClient();
  const response =
    authentication === 'client_secret_basic'
      ? await call('POST /oauth/introspect', {
          headers: { authorization: basicAuthorization(client) },
          form: { token },
        })
      : await call('POST /oauth/introspect', {
          form: { token, client_id: client.id, client_secret: client.secret },
        });
  const text = await response.text();
  expect(response.status, text).toBe(200);
  expect(response.headers.get('content-type') ?? '').toMatch(/^application\/json\b/i);
  return JSON.parse(text) as Record<string, unknown>;
}

describe('RFC 7662 §2 — token introspection by the client the token was issued to', () => {
  it('reports a live access token active, with the claims a resource server needs (§2.2)', async () => {
    const client = confidentialClient();
    const token = await clientToken();

    const answer = await introspect(token);

    expect(answer['active']).toBe(true);
    expect(answer['client_id']).toBe(client.id);
    expect(answer['iss']).toBe(baseUrl);
    expect(String(answer['scope']).split(' ')).toContain(SEEDED_CLIENT_SCOPE);
    expect(answer['token_type']).toBe('Bearer');
    expect(answer['exp']).toBeTypeOf('number');
    expect(answer['iat']).toBeTypeOf('number');
    expect(answer['exp'] as number).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('reports a string that is no token inactive, and says nothing else about it (§2.2)', async () => {
    expect(await introspect('wire-suite-not-a-token')).toEqual({ active: false });
  });

  it.each(['client_secret_basic', 'client_secret_post'] as const)(
    'authenticates the caller with %s (§2.1; RFC 6749 §2.3.1)',
    async (authentication) => {
      const token = await clientToken();

      expect((await introspect(token, authentication))['active']).toBe(true);
    }
  );
});
