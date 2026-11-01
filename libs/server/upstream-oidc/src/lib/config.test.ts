import { describe, expect, it } from 'vitest';
import { toJSONSchema } from 'zod';

import { discoveryUrl, upstreamOidcConfigSchema } from './config';

/** The config schema of the generic upstream OIDC client (#601). */

const BASE = {
  issuer: 'https://idp.example.com',
  clientId: 'qauth-client',
  clientAuthentication: { method: 'client_secret_basic', clientSecret: 'a-secret-value' },
};

describe('upstreamOidcConfigSchema', () => {
  it('fills the defaults', () => {
    expect(upstreamOidcConfigSchema.parse(BASE)).toEqual({
      ...BASE,
      scopes: ['openid', 'email', 'profile'],
      responseMode: 'query',
      idTokenSigningAlgorithms: ['RS256', 'PS256', 'ES256', 'EdDSA'],
      fetchUserinfo: false,
    });
    expect(
      upstreamOidcConfigSchema.parse({
        ...BASE,
        clientAuthentication: { method: 'private_key_jwt' },
      }).clientAuthentication
    ).toEqual({ method: 'private_key_jwt', signingAlgorithm: 'RS256' });
  });

  it.each([
    ['an http issuer', { issuer: 'http://idp.example.com' }],
    ['an issuer with a query', { issuer: 'https://idp.example.com/?tenant=1' }],
    ['an issuer with a fragment', { issuer: 'https://idp.example.com/#x' }],
    ['an issuer with credentials', { issuer: 'https://u:p@idp.example.com' }],
    ['a relative issuer', { issuer: '/idp' }],
    ['scopes without openid', { scopes: ['email'] }],
    ['repeated scopes', { scopes: ['openid', 'openid'] }],
    ['a scope with a space', { scopes: ['openid', 'a b'] }],
    ['alg none', { idTokenSigningAlgorithms: ['none'] }],
    ['an HS algorithm', { idTokenSigningAlgorithms: ['HS256'] }],
    ['no algorithm', { idTokenSigningAlgorithms: [] }],
    ['client authentication none', { clientAuthentication: { method: 'none' } }],
    [
      'a secret method without a secret',
      { clientAuthentication: { method: 'client_secret_post' } },
    ],
    [
      'a secret on private_key_jwt',
      { clientAuthentication: { method: 'private_key_jwt', clientSecret: 'x' } },
    ],
    ['an unknown member', { tokenEndpoint: 'https://idp.example.com/token' }],
    [
      'an http endpoint set by hand',
      {
        endpoints: {
          authorization: 'https://idp.example.com/a',
          token: 'http://idp.example.com/t',
          jwks: 'https://idp.example.com/j',
        },
      },
    ],
    [
      'endpoints without a jwks_uri',
      { endpoints: { authorization: 'https://a', token: 'https://t' } },
    ],
    ['an unknown response mode', { responseMode: 'fragment' }],
  ])('refuses %s', (_name, overrides) => {
    expect(upstreamOidcConfigSchema.safeParse({ ...BASE, ...overrides }).success).toBe(false);
  });

  it('marks the client secret writeOnly, so an admin API keeps it out of responses', () => {
    const schema = JSON.stringify(toJSONSchema(upstreamOidcConfigSchema));
    expect(schema).toMatch(/"clientSecret":\{[^}]*"writeOnly":true/);
  });
});

describe('discoveryUrl', () => {
  it('drops one terminating slash before the well-known path', () => {
    expect(discoveryUrl('https://idp.example.com')).toBe(
      'https://idp.example.com/.well-known/openid-configuration'
    );
    expect(discoveryUrl('https://idp.example.com/tenant/')).toBe(
      'https://idp.example.com/tenant/.well-known/openid-configuration'
    );
  });
});
