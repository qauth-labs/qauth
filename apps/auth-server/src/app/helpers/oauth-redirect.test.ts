import { describe, expect, it } from 'vitest';

import { ENVIRONMENT_PROFILES } from './environment-policy';
import {
  buildRedirectUrl,
  isHttpLocalhostRedirect,
  isRedirectUriAllowedForPolicy,
  redirectUriMatchesRegistered,
} from './oauth-redirect';

const ISS = 'https://auth.example.com';

describe('oauth-redirect — isHttpLocalhostRedirect (ADR-008 §5, #197)', () => {
  it('is true for http loopback hosts (localhost, 127.0.0.0/8, ::1)', () => {
    expect(isHttpLocalhostRedirect('http://localhost/cb')).toBe(true);
    expect(isHttpLocalhostRedirect('http://localhost:3000/cb')).toBe(true);
    expect(isHttpLocalhostRedirect('http://127.0.0.1/cb')).toBe(true);
    expect(isHttpLocalhostRedirect('http://127.1.2.3:8080/cb')).toBe(true);
    expect(isHttpLocalhostRedirect('http://[::1]:9000/cb')).toBe(true);
  });

  it('is false for https loopback (https is fine everywhere)', () => {
    expect(isHttpLocalhostRedirect('https://localhost/cb')).toBe(false);
    expect(isHttpLocalhostRedirect('https://127.0.0.1/cb')).toBe(false);
  });

  it('is false for non-loopback http (handled by the policy gate as a reject, not a dev allowance)', () => {
    expect(isHttpLocalhostRedirect('http://example.com/cb')).toBe(false);
    expect(isHttpLocalhostRedirect('http://169.254.169.254/cb')).toBe(false);
  });

  it('is false for unparseable input (existing checks stay authoritative)', () => {
    expect(isHttpLocalhostRedirect('not a url')).toBe(false);
    expect(isHttpLocalhostRedirect('')).toBe(false);
  });
});

describe('oauth-redirect — isRedirectUriAllowedForPolicy (ADR-008 §5, #197)', () => {
  it('development permits http://localhost redirects', () => {
    expect(
      isRedirectUriAllowedForPolicy('http://localhost:3000/cb', ENVIRONMENT_PROFILES.development)
    ).toBe(true);
  });

  it('staging and production permit http://localhost because PKCE is enforced (RFC 8252 native/CLI)', () => {
    expect(
      isRedirectUriAllowedForPolicy('http://localhost:3000/cb', ENVIRONMENT_PROFILES.staging)
    ).toBe(true);
    expect(
      isRedirectUriAllowedForPolicy('http://127.0.0.1/cb', ENVIRONMENT_PROFILES.production)
    ).toBe(true);
  });

  it('rejects http://localhost for a hypothetical non-dev profile without PKCE (fail-safe)', () => {
    // Guards the invariant: loopback is only conceded when PKCE backstops
    // code interception. A non-`development` profile that drops pkceRequired
    // must still reject plain-HTTP loopback.
    const noPkceNonDev = {
      ...ENVIRONMENT_PROFILES.production,
      localhostRedirectAllowed: false,
      pkceRequired: false,
    };
    expect(isRedirectUriAllowedForPolicy('http://localhost:3000/cb', noPkceNonDev)).toBe(false);
  });

  it('https redirects are permitted in every environment (the gate never widens)', () => {
    for (const env of ['development', 'staging', 'production'] as const) {
      expect(
        isRedirectUriAllowedForPolicy('https://example.com/cb', ENVIRONMENT_PROFILES[env])
      ).toBe(true);
      expect(isRedirectUriAllowedForPolicy('https://localhost/cb', ENVIRONMENT_PROFILES[env])).toBe(
        true
      );
    }
  });

  it('a custom-scheme native redirect is unaffected by the gate', () => {
    expect(
      isRedirectUriAllowedForPolicy(
        'com.example.app:/oauth2redirect',
        ENVIRONMENT_PROFILES.production
      )
    ).toBe(true);
  });
});

describe('oauth-redirect — buildRedirectUrl (unchanged behaviour)', () => {
  it('appends params and strips the fragment', () => {
    const url = buildRedirectUrl('https://example.com/cb#frag', {
      code: 'abc',
      state: 'xyz',
      iss: ISS,
    });
    expect(url).toBe(`https://example.com/cb?code=abc&state=xyz&iss=${encodeURIComponent(ISS)}`);
  });
});

describe('oauth-redirect — buildRedirectUrl RFC 9207 `iss` (#282)', () => {
  it('emits `iss` on the success response (RFC 9207 §2)', () => {
    const url = new URL(buildRedirectUrl('https://example.com/cb', { code: 'abc', iss: ISS }));
    expect(url.searchParams.get('iss')).toBe(ISS);
  });

  it('emits `iss` on error responses too — the mix-up defence must not be success-only', () => {
    // A mix-up attacker can also profit from an error the client reacts to,
    // so RFC 9207 §2 requires `iss` on §4.1.2.1 error redirects as well.
    const url = new URL(
      buildRedirectUrl('https://example.com/cb', {
        error: 'access_denied',
        error_description: 'User denied the authorization request.',
        state: 'xyz',
        iss: ISS,
      })
    );
    expect(url.searchParams.get('error')).toBe('access_denied');
    expect(url.searchParams.get('iss')).toBe(ISS);
  });

  it('emits `iss` even when it is empty rather than silently dropping it', () => {
    // The generic parameter loop skips empty values; `iss` deliberately does
    // not go through it. A misconfigured issuer must fail loudly at the client
    // (which rejects the mismatch) instead of degrading to no mix-up defence.
    const url = new URL(buildRedirectUrl('https://example.com/cb', { code: 'abc', iss: '' }));
    expect(url.searchParams.has('iss')).toBe(true);
    expect(url.searchParams.get('iss')).toBe('');
  });

  it('round-trips the issuer VERBATIM — no case folding, port elision, or path normalisation', () => {
    // Each of these differs from what `new URL(iss).toString()` would produce.
    // Clients compare with simple string comparison (RFC 3986 §6.2.1), so a
    // single rewritten byte is an authorization failure.
    const awkwardIssuers = [
      'https://Auth.EXAMPLE.com',
      'https://auth.example.com:443',
      'https://auth.example.com/a/../b',
      'https://auth.example.com/tenant%2Done',
      'https://auth.example.com/trailing/',
    ];
    for (const issuer of awkwardIssuers) {
      const url = new URL(buildRedirectUrl('https://example.com/cb', { code: 'abc', iss: issuer }));
      // searchParams.get() reverses the transport percent-encoding, which is
      // exactly what a conforming client does before comparing.
      expect(url.searchParams.get('iss')).toBe(issuer);
    }
  });

  it('preserves a pre-existing query string on the redirect_uri', () => {
    const url = new URL(
      buildRedirectUrl('https://example.com/cb?tenant=acme', { code: 'abc', iss: ISS })
    );
    expect(url.searchParams.get('tenant')).toBe('acme');
    expect(url.searchParams.get('iss')).toBe(ISS);
  });

  it('overrides an attacker-seeded `iss` already present in the registered redirect_uri', () => {
    // `searchParams.set` replaces rather than appends, so a redirect_uri
    // registered with `?iss=https://evil.example` cannot smuggle a second
    // value past a client that reads only the first occurrence.
    const url = new URL(
      buildRedirectUrl('https://example.com/cb?iss=https%3A%2F%2Fevil.example', {
        code: 'abc',
        iss: ISS,
      })
    );
    expect(url.searchParams.getAll('iss')).toEqual([ISS]);
  });
});

describe('oauth-redirect — redirectUriMatchesRegistered (RFC 8252 §7.3, #414)', () => {
  const match = (requested: string, ...registered: string[]) =>
    redirectUriMatchesRegistered(requested, registered);

  it('matches any exact registered string', () => {
    expect(
      match('https://app.example.com/cb', 'https://x.example/cb', 'https://app.example.com/cb')
    ).toBe(true);
    expect(match('com.example.app:/oauth', 'com.example.app:/oauth')).toBe(true);
    expect(match('http://127.0.0.1:8080/cb', 'http://127.0.0.1:8080/cb')).toBe(true);
  });

  it('lets only the port vary for a registered loopback redirect (127.0.0.0/8, [::1], localhost)', () => {
    expect(match('http://127.0.0.1:53817/callback', 'http://127.0.0.1/callback')).toBe(true);
    expect(match('http://127.0.0.1/callback', 'http://127.0.0.1:8080/callback')).toBe(true);
    expect(match('http://127.0.0.1:1/callback', 'http://127.0.0.1:65535/callback')).toBe(true);
    expect(match('http://127.4.5.6:9000/cb', 'http://127.4.5.6/cb')).toBe(true);
    expect(match('http://[::1]:53817/callback', 'http://[::1]/callback')).toBe(true);
    expect(match('http://localhost:53817/callback', 'http://localhost/callback')).toBe(true);
    expect(match('http://127.0.0.1:53817/cb?x=1', 'http://127.0.0.1/cb?x=1')).toBe(true);
    expect(match('http://127.0.0.1:53817', 'http://127.0.0.1')).toBe(true);
  });

  it('matches the CIMD document Claude Code publishes', () => {
    const doc = ['http://localhost/callback', 'http://127.0.0.1/callback'];
    expect(redirectUriMatchesRegistered('http://localhost:61234/callback', doc)).toBe(true);
    expect(redirectUriMatchesRegistered('http://127.0.0.1:61234/callback', doc)).toBe(true);
  });

  it('still rejects a different path, query, host or scheme on a loopback redirect', () => {
    const reg = 'http://127.0.0.1/callback';
    expect(match('http://127.0.0.1:53817/other', reg)).toBe(false);
    expect(match('http://127.0.0.1:53817/callback/', reg)).toBe(false);
    expect(match('http://127.0.0.1:53817/callbackx', reg)).toBe(false);
    expect(match('http://127.0.0.1:53817/Callback', reg)).toBe(false);
    expect(match('http://127.0.0.1:53817/callback?x=1', reg)).toBe(false);
    expect(match('http://127.0.0.1:53817/callback#f', reg)).toBe(false);
    expect(match('http://127.0.0.2:53817/callback', reg)).toBe(false);
    expect(match('http://localhost:53817/callback', reg)).toBe(false);
    expect(match('http://[::1]:53817/callback', reg)).toBe(false);
    expect(match('https://127.0.0.1:53817/callback', reg)).toBe(false);
    expect(match('http://127.0.0.1/callback', 'http://localhost/callback')).toBe(false);
    expect(match('http://LOCALHOST:53817/callback', 'http://localhost/callback')).toBe(false);
  });

  it('keeps exact matching, port included, for https, custom schemes and non-loopback hosts', () => {
    expect(match('https://localhost:8443/cb', 'https://localhost/cb')).toBe(false);
    expect(match('https://127.0.0.1:8443/cb', 'https://127.0.0.1:8080/cb')).toBe(false);
    expect(match('https://app.example.com:8443/cb', 'https://app.example.com/cb')).toBe(false);
    expect(match('http://example.com:8080/cb', 'http://example.com/cb')).toBe(false);
    expect(match('http://169.254.169.254:80/cb', 'http://169.254.169.254/cb')).toBe(false);
    expect(match('com.example.app://localhost:1234/cb', 'com.example.app://localhost/cb')).toBe(
      false
    );
  });

  it('refuses host-confusion and malformed-port shapes', () => {
    const reg = 'http://127.0.0.1/cb';
    expect(match('http://127.0.0.1@evil.example/cb', reg)).toBe(false);
    expect(match('http://127.0.0.1:80@evil.example/cb', reg)).toBe(false);
    expect(match('http://127.0.0.1.evil.example/cb', reg)).toBe(false);
    expect(match('http://localhost.evil.example:80/cb', 'http://localhost/cb')).toBe(false);
    expect(match('http://127.0.0.1\\@evil.example/cb', reg)).toBe(false);
    expect(match('http://127.0.0.1:/cb', reg)).toBe(false);
    expect(match('http://127.0.0.1:0/cb', reg)).toBe(false);
    expect(match('http://127.0.0.1:08080/cb', reg)).toBe(false);
    expect(match('http://127.0.0.1:65536/cb', reg)).toBe(false);
    expect(match('http://127.0.0.1:99999/cb', reg)).toBe(false);
    expect(match('http://127.0.0.1:8080:9090/cb', reg)).toBe(false);
    expect(match('http://127.0.0.300:8080/cb', 'http://127.0.0.300/cb')).toBe(false);
    expect(match('http://[::1]:8080/cb', 'http://[0:0:0:0:0:0:0:1]/cb')).toBe(false);
  });

  it('never matches against an empty registered set', () => {
    expect(match('http://127.0.0.1:53817/cb')).toBe(false);
  });

  it('every URI admitted through the port exception is gated by the environment policy', () => {
    for (const uri of [
      'http://127.0.0.1:53817/callback',
      'http://[::1]:53817/callback',
      'http://localhost:53817/callback',
    ]) {
      expect(isHttpLocalhostRedirect(uri)).toBe(true);
    }
  });
});
