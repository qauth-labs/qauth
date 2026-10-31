import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { authorizationRequest } from '../../fixtures/authorization';
import { expectOAuthError } from '../../helpers/error-shape';
import { getJsonObject } from '../../helpers/http';
import { call } from '../../helpers/operations';

/**
 * Registration on a default deployment, as the documentation describes it:
 * RFC 7591 dynamic registration is open (no initial access token), its scopes
 * capped to the realm's allowlist, and client ID metadata documents are off.
 *
 * The suite takes its working clients from `seed/clients.json` only. The
 * clients registered here exist to prove registration itself: one is used
 * only to show that the secret it was issued authenticates.
 */

const { baseUrl } = wireConfig();

const DISCOVERY_DOCUMENTS = [
  '/.well-known/oauth-authorization-server',
  '/.well-known/openid-configuration',
];

function register(metadata: Record<string, unknown>): Promise<Response> {
  return call('POST /oauth/register', { json: metadata });
}

async function readRegistration(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  expect(response.status, text).toBe(201);
  expect(response.headers.get('content-type') ?? '').toMatch(/^application\/json\b/i);
  expect(response.headers.get('cache-control') ?? '', 'RFC 7591 §3.2.1 no-store').toMatch(
    /no-store/i
  );
  return JSON.parse(text) as Record<string, unknown>;
}

describe('RFC 7591 §3 — open dynamic registration on a default deployment', () => {
  it('registers a confidential client and answers 201 with its client_id and secret, never cached (§3.1, §3.2.1)', async () => {
    const before = Math.floor(Date.now() / 1000) - 5;

    const client = await readRegistration(
      await register({
        client_name: `wire-suite registration ${randomUUID()}`,
        grant_types: ['client_credentials'],
        response_types: [],
        token_endpoint_auth_method: 'client_secret_post',
        scope: 'openid email wire:read',
      })
    );

    expect(client['client_id']).toBeTypeOf('string');
    expect(client['client_secret']).toBeTypeOf('string');
    // 0: the secret does not expire (§3.2.1).
    expect(client['client_secret_expires_at']).toBe(0);
    expect(client['client_id_issued_at'] as number).toBeGreaterThanOrEqual(before);
    expect(client['token_endpoint_auth_method']).toBe('client_secret_post');
    expect(client['grant_types']).toEqual(['client_credentials']);
    // The realm's allowlist caps the scope: a scope outside it is dropped (§2).
    expect(String(client['scope']).split(' ').sort()).toEqual(['email', 'openid']);
  });

  it('issues a secret that authenticates with the method it was registered for (§3.2.1; RFC 6749 §2.3.1)', async () => {
    const client = await readRegistration(
      await register({
        grant_types: ['client_credentials'],
        response_types: [],
        token_endpoint_auth_method: 'client_secret_post',
        scope: 'openid',
      })
    );
    const revokeAs = (secret: string) =>
      call('POST /oauth/revoke', {
        form: {
          token: 'wire-suite-not-a-token',
          client_id: client['client_id'] as string,
          client_secret: secret,
        },
      });

    const accepted = await revokeAs(client['client_secret'] as string);
    expect(accepted.status, await accepted.text()).toBe(200);

    await expectOAuthError(await revokeAs('wire-suite-wrong-secret'), {
      status: 401,
      error: 'invalid_client',
    });
  });

  it('registers a client that names no method as a public client, with no secret (§2, §3.2.1)', async () => {
    const client = await readRegistration(
      await register({ redirect_uris: ['http://127.0.0.1:9/wire-suite/registered-callback'] })
    );

    expect(client['token_endpoint_auth_method']).toBe('none');
    expect(client).not.toHaveProperty('client_secret');
    expect(client['grant_types']).toEqual(['authorization_code', 'refresh_token']);
    expect(client['response_types']).toEqual(['code']);
    expect(client['redirect_uris']).toEqual(['http://127.0.0.1:9/wire-suite/registered-callback']);
  });
});

describe('RFC 8414 §2 — client ID metadata documents, off on a default deployment', () => {
  it.each(DISCOVERY_DOCUMENTS)(
    'leaves client_id_metadata_document_supported out of %s (§2)',
    async (path) => {
      const { body } = await getJsonObject(serverPath(baseUrl, path));

      expect(body).not.toHaveProperty('client_id_metadata_document_supported');
    }
  );
});

describe('RFC 6749 §4.1.2.1 — a URL client_id while client ID metadata documents are off', () => {
  it('answers it exactly as a client_id that names no client: 400 invalid_request, no redirect (§4.1.2.1)', async () => {
    const asUrl = authorizationRequest({
      client_id: `https://wire-suite.example/clients/${randomUUID()}`,
    });
    const asName = authorizationRequest({ client_id: `wire-suite-${randomUUID()}` });

    const urlResponse = await call('GET /oauth/authorize', { query: asUrl.params });
    const nameResponse = await call('GET /oauth/authorize', { query: asName.params });
    expect(urlResponse.headers.get('location')).toBeNull();
    expect(nameResponse.headers.get('location')).toBeNull();

    const urlError = await expectOAuthError(urlResponse, { status: 400, error: 'invalid_request' });
    const nameError = await expectOAuthError(nameResponse, {
      status: 400,
      error: 'invalid_request',
    });
    expect(urlError).toEqual(nameError);
  });
});
