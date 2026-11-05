/**
 * The provider, as the contract test kit's scenario plays it: a fake of the
 * authorization server the plugin signs people in at. Test support, never
 * published (see the package's `files`).
 */
import type { AuthMethodEgressRequest, AuthMethodEgressResponse } from '@qauth-labs/plugin-sdk';
import type { AuthMethodKitScenario } from '@qauth-labs/plugin-sdk/testing';

import type { ExampleConfig } from './index.js';

const PROVIDER = 'https://provider.example';

/** The config one realm gives the method in the kit's run. */
export const config: ExampleConfig = {
  issuer: PROVIDER,
  authorizationEndpoint: `${PROVIDER}/authorize`,
  tokenEndpoint: `${PROVIDER}/token`,
  userinfoEndpoint: `${PROVIDER}/userinfo`,
  clientId: 'example-client',
  // Realistic length: the kit looks for every secret in every log line.
  clientSecret: 'example-client-secret-7f3a9c',
};

/** The person the provider signs in. */
export const SUBJECT = 'person-4711';

function answer(
  request: AuthMethodEgressRequest,
  status: number,
  body: unknown
): AuthMethodEgressResponse {
  return {
    status,
    headers: { 'content-type': 'application/json' },
    body: new TextEncoder().encode(JSON.stringify(body)),
    url: request.url,
  };
}

/** The provider's token and userinfo endpoints. */
export function provider(request: AuthMethodEgressRequest): AuthMethodEgressResponse {
  if (request.method === 'POST' && request.url === config.tokenEndpoint) {
    const form = new URLSearchParams(typeof request.body === 'string' ? request.body : '');
    const code = form.get('code') ?? '';
    if (
      form.get('grant_type') !== 'authorization_code' ||
      form.get('client_secret') !== config.clientSecret ||
      !code.startsWith('code-for-') ||
      (form.get('code_verifier') ?? '') === ''
    ) {
      return answer(request, 400, { error: 'invalid_grant' });
    }
    return answer(request, 200, {
      access_token: `token-for-${code.slice('code-for-'.length)}`,
      token_type: 'Bearer',
    });
  }
  if (request.method === 'GET' && request.url === config.userinfoEndpoint) {
    const token = (request.headers?.['authorization'] ?? '').replace(/^Bearer /, '');
    if (!token.startsWith('token-for-')) return answer(request, 401, { error: 'invalid_token' });
    return answer(request, 200, {
      sub: token.slice('token-for-'.length),
      email: 'person@example.com',
      email_verified: true,
    });
  }
  return answer(request, 404, { error: 'not_found' });
}

/** The kit's scenario: the person signs in, or declines, at the provider. */
export const scenario: AuthMethodKitScenario = {
  config,
  egress: provider,
  callback(authorizationRequest) {
    const state = authorizationRequest.searchParams.get('state') ?? '';
    return { path: '/callback', method: 'GET', query: { code: `code-for-${SUBJECT}`, state } };
  },
  declined(authorizationRequest) {
    const state = authorizationRequest.searchParams.get('state') ?? '';
    return { path: '/callback', method: 'GET', query: { error: 'access_denied', state } };
  },
};
