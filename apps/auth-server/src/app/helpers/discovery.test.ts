import { describe, expect, it } from 'vitest';

import {
  ASSERTION_SIGNING_ALG_VALUES_SUPPORTED,
  ID_JAG_GRANT_PROFILE,
  JWT_BEARER_GRANT_TYPE,
} from '../schemas/oauth';
import {
  buildAuthorizationServerMetadata,
  buildOpenIdConfiguration,
  DEFAULT_SCOPES_SUPPORTED,
  resolveIssuerIdentifier,
} from './discovery';

const ISSUER = 'https://auth.example.com';

describe('buildAuthorizationServerMetadata', () => {
  it('emits RFC 8414 §2 required fields anchored on the issuer', () => {
    const meta = buildAuthorizationServerMetadata({ issuer: ISSUER });

    expect(meta['issuer']).toBe(ISSUER);
    expect(meta['authorization_endpoint']).toBe(`${ISSUER}/oauth/authorize`);
    expect(meta['token_endpoint']).toBe(`${ISSUER}/oauth/token`);
    expect(meta['jwks_uri']).toBe(`${ISSUER}/.well-known/jwks.json`);
    expect(meta['userinfo_endpoint']).toBe(`${ISSUER}/oauth/userinfo`);
    expect(meta['introspection_endpoint']).toBe(`${ISSUER}/oauth/introspect`);
    expect(meta['registration_endpoint']).toBe(`${ISSUER}/oauth/register`);
  });

  it('advertises only OAuth 2.1-compliant response types, grants, and PKCE methods (RFC 8414 §2)', () => {
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
      'private_key_jwt',
      'none',
    ]);
    expect(meta['id_token_signing_alg_values_supported']).toEqual(['EdDSA']);
    expect(meta['subject_types_supported']).toEqual(['public']);
  });

  describe('private_key_jwt client authentication (#384)', () => {
    it('advertises private_key_jwt unconditionally — it is opt-in per client, not feature-flagged', () => {
      for (const idJagEnabled of [true, false]) {
        const meta = buildAuthorizationServerMetadata({ issuer: ISSUER, idJagEnabled });
        expect(meta['token_endpoint_auth_methods_supported']).toContain('private_key_jwt');
      }
    });

    it('publishes exactly the signing algorithms the assertion verifier accepts', () => {
      const meta = buildAuthorizationServerMetadata({ issuer: ISSUER });

      // RFC 8414 §2 requires this member whenever a JWT-based client auth
      // method is advertised. It MUST be the verifier's own allowlist —
      // a hand-maintained copy would drift and publish a false capability.
      expect(meta['token_endpoint_auth_signing_alg_values_supported']).toEqual([
        ...ASSERTION_SIGNING_ALG_VALUES_SUPPORTED,
      ]);
    });

    it('never advertises a symmetric or "none" client-assertion algorithm', () => {
      const meta = buildAuthorizationServerMetadata({ issuer: ISSUER });
      const algs = meta['token_endpoint_auth_signing_alg_values_supported'] as string[];

      // `HS*` would be client_secret_jwt (not implemented); `none` would be an
      // unsigned assertion. Either would let a caller authenticate without
      // proving possession of the registered private key.
      expect(algs.some((a) => a.startsWith('HS'))).toBe(false);
      expect(algs).not.toContain('none');
      expect(algs.length).toBeGreaterThan(0);
    });

    it('does NOT extend introspection/revocation auth methods (no over-advertising)', () => {
      const meta = buildAuthorizationServerMetadata({ issuer: ISSUER });

      expect(meta['introspection_endpoint_auth_methods_supported']).not.toContain(
        'private_key_jwt'
      );
      expect(meta['revocation_endpoint_auth_methods_supported']).not.toContain('private_key_jwt');
    });
  });

  describe('ID-JAG gating (ADR-011) — discovery must never advertise a disabled capability', () => {
    it('omits the jwt-bearer grant and the grant-profile member when ID-JAG is disabled', () => {
      const off = buildAuthorizationServerMetadata({ issuer: ISSUER, idJagEnabled: false });
      const defaulted = buildAuthorizationServerMetadata({ issuer: ISSUER });

      for (const meta of [off, defaulted]) {
        // Default-off must behave identically to explicitly-off: the config
        // default is false, so an unwired caller cannot accidentally advertise.
        expect(meta['grant_types_supported']).not.toContain(JWT_BEARER_GRANT_TYPE);
        expect('authorization_grant_profiles_supported' in meta).toBe(false);
      }
    });

    it('advertises both once ID-JAG is enabled', () => {
      const meta = buildAuthorizationServerMetadata({ issuer: ISSUER, idJagEnabled: true });

      expect(meta['grant_types_supported']).toContain(JWT_BEARER_GRANT_TYPE);
      expect(meta['authorization_grant_profiles_supported']).toEqual([ID_JAG_GRANT_PROFILE]);
    });

    it('keeps the pre-existing grants untouched in both states', () => {
      // Enabling a new grant must never remove or reorder an advertised one.
      const base = ['authorization_code', 'client_credentials', 'refresh_token'];
      for (const idJagEnabled of [true, false]) {
        const grants = buildAuthorizationServerMetadata({ issuer: ISSUER, idJagEnabled })[
          'grant_types_supported'
        ] as string[];
        expect(grants.slice(0, 3)).toEqual(base);
        expect(grants).toContain('urn:ietf:params:oauth:grant-type:token-exchange');
      }
    });
  });

  it('advertises the ID-token signing algorithms passed in (#309 RS256 + EdDSA)', () => {
    const meta = buildAuthorizationServerMetadata({
      issuer: ISSUER,
      idTokenSigningAlgValuesSupported: ['RS256', 'EdDSA'],
    });

    expect(meta['id_token_signing_alg_values_supported']).toEqual(['RS256', 'EdDSA']);
  });

  it('defaults the ID-token signing algorithms to EdDSA-only when none is passed (#309)', () => {
    const meta = buildAuthorizationServerMetadata({ issuer: ISSUER });

    expect(meta['id_token_signing_alg_values_supported']).toEqual(['EdDSA']);
  });

  it('falls back to the default scope list when none is provided (OIDC Discovery 1.0 §3)', () => {
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

  it('states request/request_uri support explicitly rather than inheriting the defaults (#286)', () => {
    const meta = buildAuthorizationServerMetadata({ issuer: ISSUER });

    // The members must be PRESENT, not merely falsy. RFC 8414 §2 defaults an
    // omitted `request_uri_parameter_supported` to TRUE, so omission is what
    // published the wrong claim in the first place.
    expect('request_parameter_supported' in meta).toBe(true);
    expect('request_uri_parameter_supported' in meta).toBe(true);
    expect(meta['request_parameter_supported']).toBe(false);
    expect(meta['request_uri_parameter_supported']).toBe(false);
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

  it('carries the RS256+EdDSA signing algorithms into the OIDC config (#309)', () => {
    const oidc = buildOpenIdConfiguration({
      issuer: ISSUER,
      idTokenSigningAlgValuesSupported: ['RS256', 'EdDSA'],
    });

    expect(oidc['id_token_signing_alg_values_supported']).toEqual(['RS256', 'EdDSA']);
  });

  it('carries the CIMD flag into the OIDC config too (advertised on BOTH documents)', () => {
    const oidc = buildOpenIdConfiguration({
      issuer: ISSUER,
      clientIdMetadataDocumentSupported: true,
    });

    expect(oidc['client_id_metadata_document_supported']).toBe(true);
  });

  it('carries the explicit request/request_uri flags into the OIDC config (#286, OIDC Discovery 1.0 §3)', () => {
    // OIDC Discovery §3 repeats RFC 8414's asymmetric defaults, so the same
    // false-capability claim would appear on this document if the base builder
    // stopped emitting them.
    const oidc = buildOpenIdConfiguration({ issuer: ISSUER });

    expect('request_uri_parameter_supported' in oidc).toBe(true);
    expect(oidc['request_parameter_supported']).toBe(false);
    expect(oidc['request_uri_parameter_supported']).toBe(false);
  });

  it('carries the ID-JAG gating into the OIDC config in BOTH directions (ADR-011)', () => {
    // `buildOpenIdConfiguration` spreads the AS metadata, so a client that only
    // reads /.well-known/openid-configuration must see the same truth.
    const on = buildOpenIdConfiguration({ issuer: ISSUER, idJagEnabled: true });
    expect(on['grant_types_supported']).toContain(JWT_BEARER_GRANT_TYPE);
    expect(on['authorization_grant_profiles_supported']).toEqual([ID_JAG_GRANT_PROFILE]);

    const off = buildOpenIdConfiguration({ issuer: ISSUER, idJagEnabled: false });
    expect(off['grant_types_supported']).not.toContain(JWT_BEARER_GRANT_TYPE);
    expect('authorization_grant_profiles_supported' in off).toBe(false);
  });

  it('carries the private_key_jwt auth method and its algorithms into the OIDC config (#384)', () => {
    const oidc = buildOpenIdConfiguration({ issuer: ISSUER });

    expect(oidc['token_endpoint_auth_methods_supported']).toContain('private_key_jwt');
    expect(oidc['token_endpoint_auth_signing_alg_values_supported']).toEqual([
      ...ASSERTION_SIGNING_ALG_VALUES_SUPPORTED,
    ]);
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

  it('is the exact function that produces the advertised `issuer` member (RFC 9207 §2.3)', () => {
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
