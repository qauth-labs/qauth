import { describe, expect, it } from 'vitest';

import { ENVIRONMENT_PROFILES } from './environment-policy';
import {
  buildRedirectUrl,
  isHttpLocalhostRedirect,
  isRedirectUriAllowedForPolicy,
} from './oauth-redirect';

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

  it('staging and production reject http://localhost (https-only)', () => {
    expect(
      isRedirectUriAllowedForPolicy('http://localhost:3000/cb', ENVIRONMENT_PROFILES.staging)
    ).toBe(false);
    expect(
      isRedirectUriAllowedForPolicy('http://127.0.0.1/cb', ENVIRONMENT_PROFILES.production)
    ).toBe(false);
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
    const url = buildRedirectUrl('https://example.com/cb#frag', { code: 'abc', state: 'xyz' });
    expect(url).toBe('https://example.com/cb?code=abc&state=xyz');
  });
});
