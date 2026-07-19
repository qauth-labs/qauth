import { describe, expect, it } from 'vitest';

import {
  buildAuthorizationServerMetadata,
  buildOpenIdConfiguration,
  DEFAULT_SCOPES_SUPPORTED,
  resolveIssuerIdentifier,
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
      'urn:ietf:params:oauth:grant-type:token-exchange',
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

  it('advertises client_id_metadata_document_supported when CIMD is enabled (MCP 2025-11-25)', () => {
    const meta = buildAuthorizationServerMetadata({
      issuer: ISSUER,
      clientIdMetadataDocumentSupported: true,
    });

    expect(meta['client_id_metadata_document_supported']).toBe(true);
  });

  it('advertises authorization_response_iss_parameter_supported (RFC 9207 §3, #282)', () => {
    const meta = buildAuthorizationServerMetadata({ issuer: ISSUER });

    // Unconditional: /oauth/authorize emits `iss` on every authorization
    // response, so the flag can never be a lie regardless of deployment config.
    expect(meta['authorization_response_iss_parameter_supported']).toBe(true);
  });

  it('omits the CIMD flag entirely when disabled (does not over-advertise)', () => {
    const enabledDefault = buildAuthorizationServerMetadata({ issuer: ISSUER });
    const explicitlyOff = buildAuthorizationServerMetadata({
      issuer: ISSUER,
      clientIdMetadataDocumentSupported: false,
    });

    expect('client_id_metadata_document_supported' in enabledDefault).toBe(false);
    expect('client_id_metadata_document_supported' in explicitlyOff).toBe(false);
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

  it('carries the CIMD flag into the OIDC config too (advertised on BOTH documents)', () => {
    const oidc = buildOpenIdConfiguration({
      issuer: ISSUER,
      clientIdMetadataDocumentSupported: true,
    });

    expect(oidc['client_id_metadata_document_supported']).toBe(true);
  });

  it('carries authorization_response_iss_parameter_supported into the OIDC config (RFC 9207 §3, #282)', () => {
    // RFC 9207 §3 requires the flag wherever the AS publishes metadata; an MCP
    // client that only reads /.well-known/openid-configuration must still learn
    // that `iss` is emitted and therefore worth validating.
    const oidc = buildOpenIdConfiguration({ issuer: ISSUER });

    expect(oidc['authorization_response_iss_parameter_supported']).toBe(true);
  });
});

describe('resolveIssuerIdentifier (RFC 9207 §2 verbatim contract, #282)', () => {
  it('strips exactly one trailing slash and nothing else (RFC 8414 §2)', () => {
    expect(resolveIssuerIdentifier(ISSUER)).toBe(ISSUER);
    expect(resolveIssuerIdentifier(`${ISSUER}/`)).toBe(ISSUER);
  });

  it('does NOT normalise the issuer — case, default port, and encoding survive', () => {
    // These are precisely the rewrites `new URL(...).toString()` would apply.
    // RFC 9207 §2.4 has clients compare `iss` to their configured issuer by
    // simple string comparison (RFC 3986 §6.2.1) with NO normalisation, so any
    // rewrite here silently breaks every conforming client.
    expect(resolveIssuerIdentifier('https://Auth.EXAMPLE.com')).toBe('https://Auth.EXAMPLE.com');
    expect(resolveIssuerIdentifier('https://auth.example.com:443')).toBe(
      'https://auth.example.com:443'
    );
    expect(resolveIssuerIdentifier('https://auth.example.com/tenant%2Done')).toBe(
      'https://auth.example.com/tenant%2Done'
    );
    expect(resolveIssuerIdentifier('https://auth.example.com/a/../b')).toBe(
      'https://auth.example.com/a/../b'
    );
  });

  it('is the exact function that produces the advertised `issuer` member', () => {
    // The invariant #282 rests on: whatever /oauth/authorize puts in `iss` is
    // byte-identical to discovery's `issuer` because both go through here.
    for (const raw of [ISSUER, `${ISSUER}/`, 'https://Auth.EXAMPLE.com:8443/idp']) {
      expect(buildAuthorizationServerMetadata({ issuer: raw })['issuer']).toBe(
        resolveIssuerIdentifier(raw)
      );
      expect(buildOpenIdConfiguration({ issuer: raw })['issuer']).toBe(
        resolveIssuerIdentifier(raw)
      );
    }
  });
});
