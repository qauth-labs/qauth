import { BadRequestError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { validateAndNormalize, validateRedirectUri } from './dynamic-client-registration';

describe('validateRedirectUri', () => {
  it('accepts https URIs', () => {
    expect(() => validateRedirectUri('https://app.example/cb')).not.toThrow();
  });

  it('accepts http only for loopback addresses', () => {
    expect(() => validateRedirectUri('http://127.0.0.1:8080/cb')).not.toThrow();
    expect(() => validateRedirectUri('http://[::1]:8080/cb')).not.toThrow();
    expect(() => validateRedirectUri('http://localhost:9000/cb')).not.toThrow();
  });

  it('rejects http for non-loopback hosts', () => {
    expect(() => validateRedirectUri('http://app.example/cb')).toThrow(BadRequestError);
  });

  it('accepts custom schemes for native apps', () => {
    expect(() => validateRedirectUri('com.example.app:/oauth/callback')).not.toThrow();
  });

  it('rejects redirect URIs containing a fragment', () => {
    expect(() => validateRedirectUri('https://app.example/cb#fragment')).toThrow(BadRequestError);
  });

  it('rejects malformed URIs', () => {
    expect(() => validateRedirectUri('not a url')).toThrow(BadRequestError);
  });
});

describe('validateAndNormalize', () => {
  const allowedScopes = ['openid', 'profile', 'email', 'offline_access'];

  it('defaults grant_types/response_types/token_endpoint_auth_method when omitted', () => {
    const n = validateAndNormalize({ redirect_uris: ['https://app.example/cb'] }, allowedScopes);
    expect(n.grantTypes).toEqual(['authorization_code', 'refresh_token']);
    expect(n.responseTypes).toEqual(['code']);
    expect(n.tokenEndpointAuthMethod).toBe('none');
    expect(n.isPublic).toBe(true);
  });

  it('caps requested scopes to the realm allowlist', () => {
    const n = validateAndNormalize(
      {
        redirect_uris: ['https://app.example/cb'],
        scope: 'openid email',
      },
      allowedScopes
    );
    expect(n.scopes).toEqual(['openid', 'email']);
    expect(n.scopeString).toBe('openid email');
  });

  it('rejects scopes outside the realm allowlist', () => {
    expect(() =>
      validateAndNormalize(
        {
          redirect_uris: ['https://app.example/cb'],
          scope: 'openid memory:admin',
        },
        allowedScopes
      )
    ).toThrow(/invalid_client_metadata.*memory:admin/);
  });

  it('rejects all scopes when the realm allowlist is empty', () => {
    expect(() =>
      validateAndNormalize(
        {
          redirect_uris: ['https://app.example/cb'],
          scope: 'openid',
        },
        []
      )
    ).toThrow(BadRequestError);
  });

  it('requires redirect_uris for authorization_code grants', () => {
    expect(() =>
      validateAndNormalize(
        { grant_types: ['authorization_code'], response_types: ['code'] },
        allowedScopes
      )
    ).toThrow(/invalid_redirect_uri/);
  });

  it('allows client_credentials without redirect_uris', () => {
    const n = validateAndNormalize(
      {
        grant_types: ['client_credentials'],
        response_types: [],
        token_endpoint_auth_method: 'client_secret_basic',
      },
      allowedScopes
    );
    expect(n.redirectUris).toEqual([]);
    expect(n.isPublic).toBe(false);
  });

  it('rejects client_credentials with token_endpoint_auth_method=none', () => {
    expect(() =>
      validateAndNormalize(
        {
          grant_types: ['client_credentials'],
          response_types: [],
          token_endpoint_auth_method: 'none',
        },
        allowedScopes
      )
    ).toThrow(/invalid_client_metadata.*client_credentials/);
  });

  it('rejects authorization_code grant without code response_type', () => {
    expect(() =>
      validateAndNormalize(
        {
          redirect_uris: ['https://app.example/cb'],
          grant_types: ['authorization_code'],
          response_types: [],
        },
        allowedScopes
      )
    ).toThrow(/invalid_client_metadata.*code.*response type/);
  });

  it('marks confidential clients as non-public', () => {
    const n = validateAndNormalize(
      {
        redirect_uris: ['https://app.example/cb'],
        token_endpoint_auth_method: 'client_secret_basic',
      },
      allowedScopes
    );
    expect(n.isPublic).toBe(false);
    expect(n.tokenEndpointAuthMethod).toBe('client_secret_basic');
  });
});
