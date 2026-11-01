import type { AuthMethodEgress, AuthMethodEgressRequest } from '@qauth-labs/server-federation';
import { describe, expect, it, vi } from 'vitest';

import { createFakeProvider, type FakeProvider } from '../testing/fake-provider';
import { upstreamOidcConfigSchema } from './config';
import { fetchDiscoveryDocument, resolveProviderMetadata } from './metadata';

/**
 * Discovery (#601, OpenID Connect Discovery 1.0 §4, ADR-019 Decision 8):
 * the document's issuer must be the configured one, and every URL it names
 * is a `remote_document` destination.
 */

const ISSUER = 'https://idp.example.com';

function config(overrides: Record<string, unknown> = {}) {
  return upstreamOidcConfigSchema.parse({
    issuer: ISSUER,
    clientId: 'qauth-client',
    clientAuthentication: { method: 'client_secret_basic', clientSecret: 'secret-secret' },
    ...overrides,
  });
}

function egressOf(provider: FakeProvider) {
  const calls: AuthMethodEgressRequest[] = [];
  const egress: AuthMethodEgress = {
    request: vi.fn(async (request: AuthMethodEgressRequest) => {
      calls.push(request);
      return provider.answer(request);
    }),
  };
  return { egress, calls };
}

async function discover(provider: FakeProvider, overrides: Record<string, unknown> = {}) {
  const { egress } = egressOf(provider);
  const parsed = config(overrides);
  return resolveProviderMetadata(parsed, () => fetchDiscoveryDocument(egress, parsed.issuer));
}

describe('discovery', () => {
  it('reads the document as an admin destination and its URLs as remote documents', async () => {
    const provider = await createFakeProvider({ issuer: ISSUER });
    const { egress, calls } = egressOf(provider);
    const parsed = config();
    const metadata = await resolveProviderMetadata(parsed, () =>
      fetchDiscoveryDocument(egress, parsed.issuer)
    );
    expect(calls).toEqual([
      {
        method: 'GET',
        url: `${ISSUER}/.well-known/openid-configuration`,
        headers: { accept: 'application/json' },
        purpose: 'upstream-discovery',
        source: 'admin',
        redirect: 'error',
      },
    ]);
    expect(metadata).toEqual({
      issuer: ISSUER,
      authorizationEndpoint: provider.authorizationEndpoint,
      tokenEndpoint: provider.tokenEndpoint,
      jwksUri: provider.jwksUri,
      userinfoEndpoint: provider.userinfoEndpoint,
      issParameterSupported: true,
      idTokenSigningAlgorithms: ['ES256'],
      endpointSource: 'remote_document',
    });
  });

  it('drops a terminating slash of the issuer before the well-known path', async () => {
    const provider = await createFakeProvider({ issuer: `${ISSUER}/tenant/` });
    const { egress, calls } = egressOf(provider);
    await fetchDiscoveryDocument(egress, `${ISSUER}/tenant/`);
    expect(calls[0].url).toBe(`${ISSUER}/tenant/.well-known/openid-configuration`);
  });

  it.each([
    ['another issuer', 'https://evil.example.com'],
    ['the issuer with a trailing slash', `${ISSUER}/`],
    ['the issuer in another case', 'https://IDP.example.com'],
    ['no issuer', undefined],
  ])('refuses a document with %s', async (_name, issuer) => {
    const provider = await createFakeProvider({ issuer: ISSUER });
    provider.tamper.discovery = { issuer };
    await expect(discover(provider)).rejects.toMatchObject({
      reason: 'invalid_response',
      message: expect.stringContaining('issuer'),
    });
  });

  it.each([
    ['an http token endpoint', { token_endpoint: 'http://idp.example.com/token' }],
    ['a jwks_uri with credentials', { jwks_uri: 'https://u:p@idp.example.com/jwks' }],
    ['an authorization endpoint with a fragment', { authorization_endpoint: `${ISSUER}/a#x` }],
    ['no token endpoint', { token_endpoint: undefined }],
    ['no jwks_uri', { jwks_uri: undefined }],
    ['a relative userinfo endpoint', { userinfo_endpoint: '/userinfo' }],
    ['no code among the response types', { response_types_supported: ['id_token'] }],
    ['no S256 among the PKCE methods', { code_challenge_methods_supported: ['plain'] }],
    [
      'no support for the configured client authentication',
      { token_endpoint_auth_methods_supported: ['client_secret_post'] },
    ],
    ['a list that is not a list of strings', { code_challenge_methods_supported: 'S256' }],
    ['a non-boolean iss support member', { authorization_response_iss_parameter_supported: 'yes' }],
    [
      'none of the allowed ID token algorithms',
      { id_token_signing_alg_values_supported: ['HS256'] },
    ],
  ])('refuses a document with %s', async (_name, tampering) => {
    const provider = await createFakeProvider({ issuer: ISSUER });
    provider.tamper.discovery = tampering;
    await expect(discover(provider)).rejects.toMatchObject({ reason: 'invalid_response' });
  });

  it('refuses form_post when the provider does not list it', async () => {
    const provider = await createFakeProvider({ issuer: ISSUER });
    provider.tamper.discovery = { response_modes_supported: ['query'] };
    await expect(discover(provider, { responseMode: 'form_post' })).rejects.toThrow(/form_post/);
  });

  it('refuses userinfo reads from a provider that names no userinfo endpoint', async () => {
    const provider = await createFakeProvider({ issuer: ISSUER });
    provider.tamper.discovery = { userinfo_endpoint: undefined };
    await expect(discover(provider, { fetchUserinfo: true })).rejects.toThrow(/userinfo/);
    await expect(discover(provider)).resolves.not.toHaveProperty('userinfoEndpoint');
  });

  it('narrows the config’s algorithms to those the provider lists', async () => {
    const provider = await createFakeProvider({ issuer: ISSUER });
    provider.tamper.discovery = {
      id_token_signing_alg_values_supported: ['RS256', 'ES256', 'HS256'],
    };
    const metadata = await discover(provider, { idTokenSigningAlgorithms: ['ES256', 'EdDSA'] });
    expect(metadata.idTokenSigningAlgorithms).toEqual(['ES256']);
  });

  it.each([
    ['a status other than 200', { status: 404 }, 'invalid_response'],
    ['a body that is not JSON', { headers: { 'content-type': 'text/html' } }, 'invalid_response'],
    ['a JSON list', { body: Buffer.from('[]') }, 'invalid_response'],
  ])('refuses %s', async (_name, change, reason) => {
    const provider = await createFakeProvider({ issuer: ISSUER });
    const egress: AuthMethodEgress = {
      request: async (request) => ({ ...(await provider.answer(request)), ...change }),
    };
    await expect(fetchDiscoveryDocument(egress, ISSUER)).rejects.toMatchObject({ reason });
  });

  it('reports a provider the egress client cannot reach as upstream_unavailable', async () => {
    const egress: AuthMethodEgress = {
      request: async () => {
        throw new Error('egress to idp.example.com refused: a private address');
      },
    };
    await expect(fetchDiscoveryDocument(egress, ISSUER)).rejects.toMatchObject({
      reason: 'upstream_unavailable',
    });
  });
});

describe('endpoints set by hand', () => {
  it('reads no document and sends the endpoints as admin destinations', async () => {
    const load = vi.fn(async () => ({}));
    const metadata = await resolveProviderMetadata(
      config({
        endpoints: {
          authorization: 'https://idp.internal.example/authorize',
          token: 'https://idp.internal.example/token',
          jwks: 'https://idp.internal.example/jwks',
        },
      }),
      load
    );
    expect(load).not.toHaveBeenCalled();
    expect(metadata).toMatchObject({
      tokenEndpoint: 'https://idp.internal.example/token',
      issParameterSupported: false,
      endpointSource: 'admin',
    });
  });
});
