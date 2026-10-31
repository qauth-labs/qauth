import { describe, expect, it } from 'vitest';

import {
  type FirstPartyClientFields,
  firstPartyPolicySchema,
  isNativeBrowserLegRedirectUri,
  resolveFirstPartyProfile,
} from './first-party-profile';

/** A row the operator flagged `native_backend`, as every CHECK allows it. */
function nativeClient(overrides: Partial<FirstPartyClientFields> = {}): FirstPartyClientFields {
  return {
    firstPartyProfile: 'native_backend',
    firstPartyPolicy: { flows: ['login'], email_code_after_password: false, pkce_required: true },
    tokenEndpointAuthMethod: 'private_key_jwt',
    grantTypes: ['authorization_code', 'refresh_token'],
    developerId: null,
    isAgent: false,
    dynamicRegisteredAt: null,
    metadata: null,
    ...overrides,
  };
}

/** The portal's system client after provisioning. */
function webClient(overrides: Partial<FirstPartyClientFields> = {}): FirstPartyClientFields {
  return nativeClient({ firstPartyProfile: 'web_redirect', firstPartyPolicy: null, ...overrides });
}

describe('firstPartyPolicySchema (#631)', () => {
  it('fills the defaults: login only, no email code after the password, PKCE required', () => {
    expect(firstPartyPolicySchema.parse({})).toEqual({
      flows: ['login'],
      email_code_after_password: false,
      pkce_required: true,
    });
  });

  it('keeps what the operator wrote', () => {
    expect(
      firstPartyPolicySchema.parse({
        flows: ['login', 'register', 'reset'],
        email_code_after_password: true,
        pkce_required: false,
      })
    ).toEqual({
      flows: ['login', 'register', 'reset'],
      email_code_after_password: true,
      pkce_required: false,
    });
  });

  it('refuses an empty, unknown or repeated flow, an unknown member and a wrong type', () => {
    for (const policy of [
      { flows: [] },
      { flows: ['login', 'sign_up'] },
      { flows: ['login', 'login'] },
      { flows: 'login' },
      { flows: ['login'], dpop: true },
      { pkce_required: 'false' },
      { email_code_after_password: 1 },
      null,
      [],
      'login',
    ]) {
      expect(firstPartyPolicySchema.safeParse(policy).success, JSON.stringify(policy)).toBe(false);
    }
  });
});

describe('resolveFirstPartyProfile (#631)', () => {
  it('resolves a native backend with its parsed policy', () => {
    expect(resolveFirstPartyProfile(nativeClient())).toEqual({
      profile: 'native_backend',
      policy: { flows: ['login'], email_code_after_password: false, pkce_required: true },
    });
  });

  it('fills the policy defaults from a stored empty object', () => {
    expect(resolveFirstPartyProfile(nativeClient({ firstPartyPolicy: {} }))).toEqual({
      profile: 'native_backend',
      policy: { flows: ['login'], email_code_after_password: false, pkce_required: true },
    });
  });

  it('resolves a web front-end with no policy', () => {
    expect(resolveFirstPartyProfile(webClient())).toEqual({ profile: 'web_redirect' });
  });

  it('reads a client with no profile, or an unknown one, as not first party', () => {
    expect(resolveFirstPartyProfile(nativeClient({ firstPartyProfile: null }))).toBeNull();
    expect(resolveFirstPartyProfile(nativeClient({ firstPartyProfile: 'native_attested' }))).toBe(
      null
    );
    expect(resolveFirstPartyProfile(nativeClient({ firstPartyProfile: 'NATIVE_BACKEND' }))).toBe(
      null
    );
  });

  it('reads a native backend whose policy does not parse as not first party', () => {
    for (const firstPartyPolicy of [
      null,
      undefined,
      { flows: [] },
      { flows: ['login'], extra: true },
      { pkce_required: 'no' },
      'login',
      [],
    ]) {
      expect(
        resolveFirstPartyProfile(nativeClient({ firstPartyPolicy })),
        JSON.stringify(firstPartyPolicy)
      ).toBeNull();
    }
  });

  it('reads a web front-end that carries a policy as not first party', () => {
    expect(resolveFirstPartyProfile(webClient({ firstPartyPolicy: {} }))).toBeNull();
  });

  it('fails closed on a row that breaks a rule the database CHECKs hold', () => {
    const broken: Array<[string, Partial<FirstPartyClientFields>]> = [
      ['a secret-based client', { tokenEndpointAuthMethod: 'client_secret_basic' }],
      ['a public client', { tokenEndpointAuthMethod: 'none' }],
      ['a developer-owned client', { developerId: '0190f0b4-7d1c-7c3a-8a50-6b1d2c3e4f50' }],
      ['an agent', { isAgent: true }],
      ['a dynamically registered client', { dynamicRegisteredAt: 1_790_000_000_000 }],
      ['a dynamic registration marker', { metadata: { registrationType: 'dynamic' } }],
      ['a CIMD client', { metadata: { registrationType: 'cimd' } }],
    ];
    for (const [label, overrides] of broken) {
      expect(resolveFirstPartyProfile(nativeClient(overrides)), label).toBeNull();
      expect(resolveFirstPartyProfile(webClient(overrides)), label).toBeNull();
    }
  });

  it('reads a native backend without the authorization_code grant as not first party', () => {
    expect(resolveFirstPartyProfile(nativeClient({ grantTypes: ['refresh_token'] }))).toBeNull();
    // A web front-end is not held to it here: its redirect flow needs the grant anyway.
    expect(resolveFirstPartyProfile(webClient({ grantTypes: ['refresh_token'] }))).toEqual({
      profile: 'web_redirect',
    });
  });
});

describe('isNativeBrowserLegRedirectUri (#631)', () => {
  it('accepts https, a reverse-domain private-use scheme and an http loopback IP literal', () => {
    for (const uri of [
      'https://notes.example.com/app/callback',
      'https://127.0.0.1/cb',
      'com.example.notes:/callback',
      'com.example.notes://callback',
      'http://127.0.0.1:53817/callback',
      'http://127.0.0.2/cb',
      'http://[::1]:8080/cb',
    ]) {
      expect(isNativeBrowserLegRedirectUri(uri), uri).toBe(true);
    }
  });

  it('refuses plain http to a host, localhost by name, a scheme with no domain and what the screen cannot show', () => {
    for (const uri of [
      'http://notes.example.com/callback',
      'http://localhost:8080/callback',
      'http://dev.localhost/callback',
      'http://0.0.0.0/callback',
      'http://[::]/callback',
      'notes:/callback',
      'javascript:alert(1)',
      'data:text/html,hi',
      'file:///etc/passwd',
      'https://bad_host.example.com/cb',
      `com.example.${'a'.repeat(60)}:/cb`,
      'not a uri',
      '',
    ]) {
      expect(isNativeBrowserLegRedirectUri(uri), uri).toBe(false);
    }
  });
});
