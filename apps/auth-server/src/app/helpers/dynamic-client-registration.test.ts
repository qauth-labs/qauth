import { BadRequestError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

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

  it('accepts portless loopback redirects (RFC 8252 §7.3 — the port is chosen per request, #414)', () => {
    expect(() => validateRedirectUri('http://127.0.0.1/callback')).not.toThrow();
    expect(() => validateRedirectUri('http://[::1]/callback')).not.toThrow();
    expect(() => validateRedirectUri('http://localhost/callback')).not.toThrow();
  });

  it('rejects http for non-loopback hosts', () => {
    expect(() => validateRedirectUri('http://app.example/cb')).toThrow(BadRequestError);
  });

  it('accepts private-use schemes for native apps (RFC 8252 §7.1)', () => {
    expect(() => validateRedirectUri('com.example.app:/oauth/callback')).not.toThrow();
    expect(() => validateRedirectUri('com.example.app://oauth/callback')).not.toThrow();
    expect(() =>
      validateRedirectUri('com.googleusercontent.apps.123-abc:/oauth2redirect')
    ).not.toThrow();
  });

  // Found while fixing the findings of scan qauth-20261015-005: any
  // syntactically valid scheme used to pass.
  it.each([
    'javascript:alert(document.domain)',
    'JAVASCRIPT:alert(1)//',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
    'blob:https://app.example/0b3f5a2e-6c1d-4d7e-9a8b-1f2e3d4c5b6a',
    'about:blank',
    'myapp:/callback',
    'myapp://callback',
    'ftp://files.example/cb',
    'wss://app.example/cb',
    'com..example:/cb',
  ])('refuses the redirect URI %s (scheme not allowed)', (uri) => {
    expect(() => validateRedirectUri(uri)).toThrow(/^invalid_redirect_uri: unsupported scheme: /);
  });

  it('rejects redirect URIs containing a fragment', () => {
    expect(() => validateRedirectUri('https://app.example/cb#fragment')).toThrow(BadRequestError);
  });

  it('rejects malformed URIs', () => {
    expect(() => validateRedirectUri('not a url')).toThrow(BadRequestError);
  });

  it('rejects a tab or line break anywhere in the URI, which new URL() would silently delete', () => {
    for (const uri of [
      'https://app.example/c\tb',
      'https://app.exa\nmple/cb',
      'https://app.example/cb\r\n',
      '\thttps://app.example/cb',
    ]) {
      expect(() => validateRedirectUri(uri)).toThrow(BadRequestError);
    }
  });

  it('refuses a URI that is not printable ASCII BEFORE parsing it', () => {
    // `new URL()` is quadratic in the distinct non-ASCII characters of a host:
    // twenty 2048-character CJK hosts held the event loop for ~0.36 s per
    // anonymous registration. RFC 3986 URIs are ASCII; an IDN host is written
    // in its `xn--` form.
    const cjkHost = Array.from({ length: 1000 }, (_, i) => String.fromCodePoint(0x4e00 + i)).join(
      ''
    );
    const URLConstructor = globalThis.URL;
    const constructed = vi.fn();
    vi.stubGlobal(
      'URL',
      class extends URLConstructor {
        constructor(...args: ConstructorParameters<typeof URL>) {
          constructed();
          super(...args);
        }
      }
    );
    try {
      for (const uri of [
        `https://${cjkHost}/cb`,
        'https://bücher.example/cb',
        'https://a.example/c b',
      ]) {
        expect(() => validateRedirectUri(uri)).toThrow(BadRequestError);
      }
      expect(constructed).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
    expect(() => validateRedirectUri('https://xn--bcher-kva.example/cb')).not.toThrow();
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

  it('registers a portless loopback redirect verbatim (#414)', () => {
    const uris = [
      'http://127.0.0.1/callback',
      'http://[::1]/callback',
      'http://localhost/callback',
    ];
    const n = validateAndNormalize({ redirect_uris: uris }, allowedScopes);
    expect(n.redirectUris).toEqual(uris);
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

  it('caps out scopes outside the realm allowlist instead of rejecting (RFC 7591 §2)', () => {
    const n = validateAndNormalize(
      {
        redirect_uris: ['https://app.example/cb'],
        scope: 'openid example:admin',
      },
      allowedScopes
    );
    expect(n.scopes).toEqual(['openid']);
    expect(n.scopeString).toBe('openid');
  });

  it('de-dupes requested scopes while capping', () => {
    const n = validateAndNormalize(
      {
        redirect_uris: ['https://app.example/cb'],
        scope: 'openid openid email example:admin',
      },
      allowedScopes
    );
    expect(n.scopes).toEqual(['openid', 'email']);
  });

  it('drops all scopes when the realm allowlist is empty', () => {
    const n = validateAndNormalize(
      {
        redirect_uris: ['https://app.example/cb'],
        scope: 'openid',
      },
      []
    );
    expect(n.scopes).toEqual([]);
    expect(n.scopeString).toBeUndefined();
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
