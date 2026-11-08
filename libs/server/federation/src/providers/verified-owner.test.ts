import { describe, expect, it } from 'vitest';

import { buildPasswordCredentialData } from './password.provider';
import { credentialIsProved, credentialKindOf, decideVerifiedOwner } from './verified-owner';

/** A passkey's `credential_data` as a registration stores it. */
function passkeyData(userVerified: boolean | undefined): Record<string, unknown> {
  return {
    public_key: 'pQECAyYgASFYIK_voW-Xypst',
    algorithm: -7,
    sign_count: 0,
    transports: ['internal'],
    backup_eligible: false,
    backed_up: false,
    aaguid: '00000000-0000-0000-0000-000000000000',
    ...(userVerified === undefined ? {} : { user_verified: userVerified }),
    rp_id: 'auth.example.com',
    user_handle: 'dXNlci1oYW5kbGU',
    nickname: null,
    created_at: 1,
    last_used_at: null,
    sign_counter_regressed_at: null,
  };
}

const WALLET_DATA = {
  credential_format: 'dc+sd-jwt',
  credential_type: 'https://credentials.example.com/identity',
  issuer: 'https://issuer.example.com',
  wallet_binding: 'binding',
  subject_resolution: 'asserted',
  enrolled_at: 1,
};

const UPSTREAM_DATA = { kind: 'upstream', iss: 'https://idp.example.com', verified: true };

const CONFIRMED_PASSWORD = {
  providerType: 'password',
  credentialData: buildPasswordCredentialData('$argon2id$h', true, 'nfc'),
};
const UNCONFIRMED_PASSWORD = {
  providerType: 'password',
  credentialData: buildPasswordCredentialData('$argon2id$h', false, 'nfc'),
};

/** `credential` as the account's primary one, or as one added later. */
const primary = <T extends object>(credential: T) => ({ ...credential, isPrimary: true });
const later = <T extends object>(credential: T) => ({ ...credential, isPrimary: false });

describe('credentialIsProved (ADR-015 Decision 8, amended 2026-11-08; #846)', () => {
  describe('a password', () => {
    it('is proved once the mailbox code set email_verified on the credential', () => {
      expect(credentialIsProved(CONFIRMED_PASSWORD)).toBe(true);
    });

    it('proves nothing while the address is unconfirmed: the password alone is no proof', () => {
      expect(credentialIsProved(UNCONFIRMED_PASSWORD)).toBe(false);
    });

    it('proves nothing with malformed data', () => {
      expect(
        credentialIsProved({ providerType: 'password', credentialData: { email_verified: true } })
      ).toBe(false);
    });

    it('never reads an upstream provider', () => {
      expect(credentialIsProved(UNCONFIRMED_PASSWORD, { marksVerified: true })).toBe(false);
    });
  });

  describe('a passkey', () => {
    it('is proved when its registration checked the user-verification flag', () => {
      expect(
        credentialIsProved({ providerType: 'webauthn', credentialData: passkeyData(true) })
      ).toBe(true);
    });

    it('is proved when it was registered before the flag was stored, which every such registration required', () => {
      expect(
        credentialIsProved({ providerType: 'webauthn', credentialData: passkeyData(undefined) })
      ).toBe(true);
    });

    it('proves nothing when its registration says the flag was not set', () => {
      expect(
        credentialIsProved({ providerType: 'webauthn', credentialData: passkeyData(false) })
      ).toBe(false);
    });
  });

  describe('a wallet credential', () => {
    it("is proved: only QAuth's verifier writes one", () => {
      expect(credentialIsProved({ providerType: 'wallet', credentialData: WALLET_DATA })).toBe(
        true
      );
    });

    it('proves nothing with data no verifier wrote', () => {
      expect(credentialIsProved({ providerType: 'wallet', credentialData: {} })).toBe(false);
    });
  });

  describe('an upstream identity', () => {
    const upstream = { providerType: 'oidc_corp', credentialData: UPSTREAM_DATA };

    it("is proved while the provider's verified switch is on", () => {
      expect(credentialIsProved(upstream, { marksVerified: true })).toBe(true);
    });

    it('proves nothing with the switch off, whatever the credential says', () => {
      expect(credentialIsProved(upstream, { marksVerified: false })).toBe(false);
    });

    it('proves nothing once the realm no longer offers the provider', () => {
      expect(credentialIsProved(upstream, undefined)).toBe(false);
    });

    it("counts a plugin's identity as one, and proves nothing without its issuer form", () => {
      expect(
        credentialIsProved(
          { providerType: 'corp_sso', credentialData: UPSTREAM_DATA },
          { marksVerified: true }
        )
      ).toBe(true);
      expect(
        credentialIsProved(
          { providerType: 'oidc_corp', credentialData: { kind: 'upstream' } },
          { marksVerified: true }
        )
      ).toBe(false);
    });
  });

  it('proves nothing for a type with no proof', () => {
    for (const providerType of ['totp', 'did', 'test']) {
      expect(credentialIsProved({ providerType, credentialData: {} })).toBe(false);
    }
  });
});

describe('decideVerifiedOwner (ADR-015 Decision 8, amended 2026-11-08; #846)', () => {
  it('verifies an account by its primary credential', () => {
    expect(decideVerifiedOwner([primary(CONFIRMED_PASSWORD)])).toEqual({
      verified: true,
      proof: 'password',
      primaryIdentity: 'password',
    });
  });

  it('verifies an unconfirmed password account by a passkey added later (question 13, amended)', () => {
    expect(
      decideVerifiedOwner([
        primary(UNCONFIRMED_PASSWORD),
        later({ providerType: 'webauthn', credentialData: passkeyData(true) }),
      ])
    ).toEqual({ verified: true, proof: 'passkey', primaryIdentity: 'password' });
  });

  it("verifies an account by an upstream identity linked later, while the provider's switch is on", () => {
    const credentials = [
      primary(UNCONFIRMED_PASSWORD),
      later({ providerType: 'oidc_corp', credentialData: UPSTREAM_DATA }),
    ];
    expect(decideVerifiedOwner(credentials, () => ({ marksVerified: true }))).toEqual({
      verified: true,
      proof: 'upstream',
      primaryIdentity: 'password',
    });
    expect(decideVerifiedOwner(credentials, () => ({ marksVerified: false }))).toEqual({
      verified: false,
      reason: 'account_not_verified',
      primaryIdentity: 'password',
    });
  });

  it('names the primary credential when it counts, whatever the order', () => {
    expect(
      decideVerifiedOwner([
        later({ providerType: 'webauthn', credentialData: passkeyData(true) }),
        primary({ providerType: 'wallet', credentialData: WALLET_DATA }),
      ])
    ).toEqual({ verified: true, proof: 'wallet', primaryIdentity: 'wallet' });
  });

  it('refuses an account none of whose credentials is proved', () => {
    expect(
      decideVerifiedOwner([
        primary(UNCONFIRMED_PASSWORD),
        later({ providerType: 'webauthn', credentialData: passkeyData(false) }),
        later({ providerType: 'totp', credentialData: {} }),
      ])
    ).toEqual({ verified: false, reason: 'account_not_verified', primaryIdentity: 'password' });
  });

  it('refuses an account that holds no credential', () => {
    expect(decideVerifiedOwner([])).toEqual({
      verified: false,
      reason: 'no_credentials',
      primaryIdentity: 'none',
    });
  });

  it('still decides for an account whose primary credential was removed', () => {
    expect(
      decideVerifiedOwner([later({ providerType: 'webauthn', credentialData: passkeyData(true) })])
    ).toEqual({ verified: true, proof: 'passkey', primaryIdentity: 'none' });
  });

  it('reads the upstream provider only for an upstream identity', () => {
    const lookups: string[] = [];
    decideVerifiedOwner(
      [
        primary(UNCONFIRMED_PASSWORD),
        later({ providerType: 'oidc_corp', credentialData: UPSTREAM_DATA }),
      ],
      (providerType) => {
        lookups.push(providerType);
        return undefined;
      }
    );
    expect(lookups).toEqual(['oidc_corp']);
  });
});

describe('credentialKindOf', () => {
  it('tells the kind of a credential by its type, and an upstream one by its data', () => {
    expect(credentialKindOf({ providerType: 'password', credentialData: {} })).toBe('password');
    expect(credentialKindOf({ providerType: 'webauthn', credentialData: {} })).toBe('passkey');
    expect(credentialKindOf({ providerType: 'wallet', credentialData: {} })).toBe('wallet');
    expect(credentialKindOf({ providerType: 'oidc_corp', credentialData: UPSTREAM_DATA })).toBe(
      'upstream'
    );
    expect(credentialKindOf({ providerType: 'oidc_corp', credentialData: {} })).toBe('other');
  });
});
