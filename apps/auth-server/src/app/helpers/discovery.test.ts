import { describe, expect, it } from 'vitest';

import {
  buildAuthorizationServerMetadata,
  buildOpenIdConfiguration,
  DEFAULT_SCOPES_SUPPORTED,
} from './discovery';

const ISSUER = 'https://auth.example.com';

describe('buildAuthorizationServerMetadata', () => {
  it('emits RFC 8414 required fields anchored on the issuer', () => {
    const meta = buildAuthorizationServerMetadata({ issuer: ISSUER });

    expect(meta['issuer']).toBe(ISSUER);
    expect(meta['authorization_endpoint']).toBe(`${ISSUER}/oauth/authorize`);
    expect(meta['token_endpoint']).toBe(`${ISSUER}/oauth/token`);
    expect(meta['jwks_uri']).toBe(`${ISSUER}/.well-known/jwks.json`);
    expect(meta['userinfo_endpoint']).toBe(`${ISSUER}/oauth/userinfo`);
    expect(meta['introspection_endpoint']).toBe(`${ISSUER}/oauth/introspect`);
    expect(meta['registration_endpoint']).toBe(`${ISSUER}/oauth/register`);
  });

  it('advertises only OAuth 2.1-compliant response types, grants, and PKCE methods', () => {
    const meta = buildAuthorizationServerMetadata({ issuer: ISSUER });

    expect(meta['response_types_supported']).toEqual(['code']);
    expect(meta['grant_types_supported']).toEqual([
      'authorization_code',
      'client_credentials',
      'refresh_token',
    ]);
    expect(meta['code_challenge_methods_supported']).toEqual(['S256']);
    expect(meta['token_endpoint_auth_methods_supported']).toEqual([
      'client_secret_basic',
      'client_secret_post',
      'none',
    ]);
    expect(meta['id_token_signing_alg_values_supported']).toEqual(['EdDSA']);
    expect(meta['subject_types_supported']).toEqual(['public']);
  });

  it('falls back to the default scope list when none is provided', () => {
    const meta = buildAuthorizationServerMetadata({ issuer: ISSUER });

    expect(meta['scopes_supported']).toEqual([...DEFAULT_SCOPES_SUPPORTED]);
  });

  it('honours a custom scope list', () => {
    const meta = buildAuthorizationServerMetadata({
      issuer: ISSUER,
      scopesSupported: ['openid', 'custom:read'],
    });

    expect(meta['scopes_supported']).toEqual(['openid', 'custom:read']);
  });

  it('strips a trailing slash on the issuer so URLs are not double-slashed', () => {
    const meta = buildAuthorizationServerMetadata({ issuer: `${ISSUER}/` });

    expect(meta['issuer']).toBe(ISSUER);
    expect(meta['token_endpoint']).toBe(`${ISSUER}/oauth/token`);
  });
});

describe('buildOpenIdConfiguration', () => {
  it('extends AS metadata with OIDC-only fields without dropping the base fields', () => {
    const oidc = buildOpenIdConfiguration({ issuer: ISSUER });

    // Base fields preserved.
    expect(oidc['issuer']).toBe(ISSUER);
    expect(oidc['jwks_uri']).toBe(`${ISSUER}/.well-known/jwks.json`);
    expect(oidc['id_token_signing_alg_values_supported']).toEqual(['EdDSA']);

    // OIDC-only.
    expect(oidc['claims_supported']).toEqual(
      expect.arrayContaining(['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'email_verified'])
    );
  });
});
