import { InvalidClientMetadataError, InvalidRedirectUriError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

import { validateAndNormalize, validateRedirectUri } from './dynamic-client-registration';

/** `REDIRECT_URI_CUSTOM_SCHEMES` unset: the default. */
const NO_CUSTOM_SCHEMES: readonly string[] = [];

describe('validateRedirectUri', () => {
  it('accepts https URIs', () => {
    expect(() => validateRedirectUri('https://app.example/cb', NO_CUSTOM_SCHEMES)).not.toThrow();
  });

  it('accepts http only for loopback addresses', () => {
    expect(() => validateRedirectUri('http://127.0.0.1:8080/cb', NO_CUSTOM_SCHEMES)).not.toThrow();
    expect(() => validateRedirectUri('http://[::1]:8080/cb', NO_CUSTOM_SCHEMES)).not.toThrow();
    expect(() => validateRedirectUri('http://localhost:9000/cb', NO_CUSTOM_SCHEMES)).not.toThrow();
  });

  it('accepts portless loopback redirects (RFC 8252 §7.3 — the port is chosen per request, #414)', () => {
    expect(() => validateRedirectUri('http://127.0.0.1/callback', NO_CUSTOM_SCHEMES)).not.toThrow();
    expect(() => validateRedirectUri('http://[::1]/callback', NO_CUSTOM_SCHEMES)).not.toThrow();
    expect(() => validateRedirectUri('http://localhost/callback', NO_CUSTOM_SCHEMES)).not.toThrow();
  });

  it('rejects http for non-loopback hosts', () => {
    expect(() => validateRedirectUri('http://app.example/cb', NO_CUSTOM_SCHEMES)).toThrow(
      InvalidRedirectUriError
    );
  });

  it('accepts private-use schemes for native apps (RFC 8252 §7.1)', () => {
    expect(() =>
      validateRedirectUri('com.example.app:/oauth/callback', NO_CUSTOM_SCHEMES)
    ).not.toThrow();
    expect(() =>
      validateRedirectUri('com.example.app://oauth/callback', NO_CUSTOM_SCHEMES)
    ).not.toThrow();
    expect(() =>
      validateRedirectUri('com.googleusercontent.apps.123-abc:/oauth2redirect', NO_CUSTOM_SCHEMES)
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
    expect(() => validateRedirectUri(uri, NO_CUSTOM_SCHEMES)).toThrow(InvalidRedirectUriError);
  });

  describe('REDIRECT_URI_CUSTOM_SCHEMES (#774)', () => {
    const cursorCallback = 'cursor://anysphere.cursor-mcp/oauth/callback';

    it('refuses a bare scheme by default, with the existing error', () => {
      expect(() => validateRedirectUri(cursorCallback, NO_CUSTOM_SCHEMES)).toThrow(
        InvalidRedirectUriError
      );
    });

    it('accepts a bare scheme the deployment lists', () => {
      expect(() => validateRedirectUri(cursorCallback, ['cursor'])).not.toThrow();
    });

    it('still refuses a bare scheme that is not listed', () => {
      expect(() => validateRedirectUri('myapp://callback', ['cursor'])).toThrow(
        InvalidRedirectUriError
      );
    });

    it('still refuses a fragment on a listed scheme', () => {
      expect(() => validateRedirectUri(`${cursorCallback}#x`, ['cursor'])).toThrow(
        InvalidRedirectUriError
      );
    });

    it('refuses javascript: even when the list names it', () => {
      expect(() => validateRedirectUri('javascript:alert(1)', ['javascript'])).toThrow(
        InvalidRedirectUriError
      );
    });

    it('carries the list through dynamic registration', () => {
      const body = { redirect_uris: [cursorCallback] };
      expect(() => validateAndNormalize(body, ['openid'], NO_CUSTOM_SCHEMES)).toThrow(
        InvalidRedirectUriError
      );
      expect(validateAndNormalize(body, ['openid'], ['cursor']).redirectUris).toEqual([
        cursorCallback,
      ]);
    });
  });

  it('rejects redirect URIs containing a fragment', () => {
    expect(() => validateRedirectUri('https://app.example/cb#fragment', NO_CUSTOM_SCHEMES)).toThrow(
      InvalidRedirectUriError
    );
  });

  it('rejects malformed URIs', () => {
    expect(() => validateRedirectUri('not a url', NO_CUSTOM_SCHEMES)).toThrow(
      InvalidRedirectUriError
    );
  });

  it('rejects a tab or line break anywhere in the URI, which new URL() would silently delete', () => {
    for (const uri of [
      'https://app.example/c\tb',
      'https://app.exa\nmple/cb',
      'https://app.example/cb\r\n',
      '\thttps://app.example/cb',
    ]) {
      expect(() => validateRedirectUri(uri, NO_CUSTOM_SCHEMES)).toThrow(InvalidRedirectUriError);
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
        expect(() => validateRedirectUri(uri, NO_CUSTOM_SCHEMES)).toThrow(InvalidRedirectUriError);
      }
      expect(constructed).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
    expect(() =>
      validateRedirectUri('https://xn--bcher-kva.example/cb', NO_CUSTOM_SCHEMES)
    ).not.toThrow();
  });
});

describe('validateAndNormalize', () => {
  const allowedScopes = ['openid', 'profile', 'email', 'offline_access'];

  it('defaults grant_types/response_types/token_endpoint_auth_method when omitted', () => {
    const n = validateAndNormalize(
      { redirect_uris: ['https://app.example/cb'] },
      allowedScopes,
      NO_CUSTOM_SCHEMES
    );
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
    const n = validateAndNormalize({ redirect_uris: uris }, allowedScopes, NO_CUSTOM_SCHEMES);
    expect(n.redirectUris).toEqual(uris);
  });

  it('caps requested scopes to the realm allowlist', () => {
    const n = validateAndNormalize(
      {
        redirect_uris: ['https://app.example/cb'],
        scope: 'openid email',
      },
      allowedScopes,
      NO_CUSTOM_SCHEMES
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
      allowedScopes,
      NO_CUSTOM_SCHEMES
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
      allowedScopes,
      NO_CUSTOM_SCHEMES
    );
    expect(n.scopes).toEqual(['openid', 'email']);
  });

  it('drops all scopes when the realm allowlist is empty', () => {
    const n = validateAndNormalize(
      {
        redirect_uris: ['https://app.example/cb'],
        scope: 'openid',
      },
      [],
      NO_CUSTOM_SCHEMES
    );
    expect(n.scopes).toEqual([]);
    expect(n.scopeString).toBeUndefined();
  });

  // #507: the admin: prefix is reserved for the admin API.
  it.each(['admin:read', 'admin:write', 'admin:security', 'admin:anything', 'Admin:Security'])(
    'refuses the whole registration when it asks for %s',
    (adminScope) => {
      expect(() =>
        validateAndNormalize(
          { redirect_uris: ['https://app.example/cb'], scope: `openid ${adminScope}` },
          allowedScopes,
          NO_CUSTOM_SCHEMES
        )
      ).toThrow(
        expect.objectContaining({
          name: 'InvalidClientMetadataError',
          message: 'invalid_client_metadata',
          errorDescription:
            'scopes starting with admin: are reserved for the admin API and cannot be registered',
        })
      );
    }
  );

  it('refuses an admin scope even when the realm allowlist lists it', () => {
    expect(() =>
      validateAndNormalize(
        { redirect_uris: ['https://app.example/cb'], scope: 'admin:read' },
        [...allowedScopes, 'admin:read'],
        NO_CUSTOM_SCHEMES
      )
    ).toThrow(InvalidClientMetadataError);
  });

  it('leaves scopes that only contain "admin" to the allowlist', () => {
    const n = validateAndNormalize(
      {
        redirect_uris: ['https://app.example/cb'],
        scope: 'openid agent:admin example:admin administrator',
      },
      allowedScopes,
      NO_CUSTOM_SCHEMES
    );
    expect(n.scopes).toEqual(['openid']);
  });

  it('requires redirect_uris for authorization_code grants', () => {
    expect(() =>
      validateAndNormalize(
        { grant_types: ['authorization_code'], response_types: ['code'] },
        allowedScopes,
        NO_CUSTOM_SCHEMES
      )
    ).toThrow(InvalidRedirectUriError);
  });

  it('allows client_credentials without redirect_uris', () => {
    const n = validateAndNormalize(
      {
        grant_types: ['client_credentials'],
        response_types: [],
        token_endpoint_auth_method: 'client_secret_basic',
      },
      allowedScopes,
      NO_CUSTOM_SCHEMES
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
        allowedScopes,
        NO_CUSTOM_SCHEMES
      )
    ).toThrow(InvalidClientMetadataError);
  });

  it('rejects authorization_code grant without code response_type', () => {
    expect(() =>
      validateAndNormalize(
        {
          redirect_uris: ['https://app.example/cb'],
          grant_types: ['authorization_code'],
          response_types: [],
        },
        allowedScopes,
        NO_CUSTOM_SCHEMES
      )
    ).toThrow(InvalidClientMetadataError);
  });

  it('marks confidential clients as non-public', () => {
    const n = validateAndNormalize(
      {
        redirect_uris: ['https://app.example/cb'],
        token_endpoint_auth_method: 'client_secret_basic',
      },
      allowedScopes,
      NO_CUSTOM_SCHEMES
    );
    expect(n.isPublic).toBe(false);
    expect(n.tokenEndpointAuthMethod).toBe('client_secret_basic');
  });
});
