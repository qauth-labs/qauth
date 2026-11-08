import { describe, expect, it } from 'vitest';

import { buildPasswordCredentialData } from './password.provider';
import { decideVerifiedOwner, primaryIdentityKindOf } from './verified-owner';

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

describe('decideVerifiedOwner (ADR-015 Decision 8, #846)', () => {
  describe('a password account', () => {
    it('is verified once the mailbox code set email_verified on the credential', () => {
      expect(
        decideVerifiedOwner({
          providerType: 'password',
          credentialData: buildPasswordCredentialData('$argon2id$h', true, 'nfc'),
        })
      ).toEqual({ verified: true, identity: 'password' });
    });

    it('is not verified while the address is unconfirmed', () => {
      expect(
        decideVerifiedOwner({
          providerType: 'password',
          credentialData: buildPasswordCredentialData('$argon2id$h', false, 'nfc'),
        })
      ).toEqual({ verified: false, identity: 'password', reason: 'account_not_verified' });
    });

    it('proves nothing with malformed data', () => {
      expect(
        decideVerifiedOwner({ providerType: 'password', credentialData: { email_verified: true } })
      ).toEqual({ verified: false, identity: 'password', reason: 'account_not_verified' });
    });
  });

  describe('a passkey account', () => {
    it('is verified when its registration checked the user-verification flag', () => {
      expect(
        decideVerifiedOwner({ providerType: 'webauthn', credentialData: passkeyData(true) })
      ).toEqual({ verified: true, identity: 'passkey' });
    });

    it('is verified when it was registered before the flag was stored, which every such registration required', () => {
      expect(
        decideVerifiedOwner({ providerType: 'webauthn', credentialData: passkeyData(undefined) })
      ).toEqual({ verified: true, identity: 'passkey' });
    });

    it('is not verified when its registration says the flag was not set', () => {
      expect(
        decideVerifiedOwner({ providerType: 'webauthn', credentialData: passkeyData(false) })
      ).toEqual({ verified: false, identity: 'passkey', reason: 'account_not_verified' });
    });
  });

  describe('a wallet account', () => {
    it("is verified: only QAuth's verifier writes a wallet credential", () => {
      expect(decideVerifiedOwner({ providerType: 'wallet', credentialData: WALLET_DATA })).toEqual({
        verified: true,
        identity: 'wallet',
      });
    });

    it('proves nothing with data no verifier wrote', () => {
      expect(decideVerifiedOwner({ providerType: 'wallet', credentialData: {} })).toEqual({
        verified: false,
        identity: 'wallet',
        reason: 'account_not_verified',
      });
    });
  });

  describe('an upstream account', () => {
    const primary = { providerType: 'oidc_corp', credentialData: UPSTREAM_DATA };

    it("is verified while the provider's verified switch is on", () => {
      expect(decideVerifiedOwner(primary, { marksVerified: true })).toEqual({
        verified: true,
        identity: 'upstream',
      });
    });

    it('is not verified with the switch off, whatever the credential says', () => {
      expect(decideVerifiedOwner(primary, { marksVerified: false })).toEqual({
        verified: false,
        identity: 'upstream',
        reason: 'account_not_verified',
      });
    });

    it('is not verified once the realm no longer offers the provider', () => {
      expect(decideVerifiedOwner(primary, undefined)).toEqual({
        verified: false,
        identity: 'upstream',
        reason: 'account_not_verified',
      });
    });

    it("counts a plugin's identity as one, and proves nothing without its issuer form", () => {
      expect(
        decideVerifiedOwner(
          { providerType: 'corp_sso', credentialData: UPSTREAM_DATA },
          { marksVerified: true }
        )
      ).toEqual({ verified: true, identity: 'upstream' });
      expect(
        decideVerifiedOwner(
          { providerType: 'oidc_corp', credentialData: { kind: 'upstream' } },
          { marksVerified: true }
        )
      ).toEqual({ verified: false, identity: 'upstream', reason: 'account_not_verified' });
    });
  });

  describe("an operator's verification of the account (#1052)", () => {
    it('makes an account verified whose primary identity is not proved, and says so', () => {
      const unconfirmed = {
        providerType: 'password',
        credentialData: buildPasswordCredentialData('$argon2id$h', false, 'nfc'),
      };
      expect(decideVerifiedOwner(unconfirmed, undefined, { operatorVerified: true })).toEqual({
        verified: true,
        identity: 'password',
        operatorVerified: true,
      });
      expect(
        decideVerifiedOwner(
          { providerType: 'oidc_corp', credentialData: UPSTREAM_DATA },
          { marksVerified: false },
          { operatorVerified: true }
        )
      ).toEqual({ verified: true, identity: 'upstream', operatorVerified: true });
      expect(decideVerifiedOwner(unconfirmed, undefined, { operatorVerified: false })).toEqual({
        verified: false,
        identity: 'password',
        reason: 'account_not_verified',
      });
    });

    it('leaves the decision of a proved primary identity as it is', () => {
      expect(
        decideVerifiedOwner(
          {
            providerType: 'password',
            credentialData: buildPasswordCredentialData('$argon2id$h', true, 'nfc'),
          },
          undefined,
          { operatorVerified: true }
        )
      ).toEqual({ verified: true, identity: 'password' });
    });

    it('does not verify an account that has no primary identity left', () => {
      expect(decideVerifiedOwner(undefined, undefined, { operatorVerified: true })).toEqual({
        verified: false,
        identity: 'none',
        reason: 'no_primary_identity',
      });
    });
  });

  it('refuses an account with no primary identity', () => {
    expect(decideVerifiedOwner(undefined)).toEqual({
      verified: false,
      identity: 'none',
      reason: 'no_primary_identity',
    });
  });

  it('refuses a primary credential of a type with no proof', () => {
    for (const providerType of ['totp', 'did', 'test']) {
      expect(decideVerifiedOwner({ providerType, credentialData: {} })).toEqual({
        verified: false,
        identity: 'other',
        reason: 'account_not_verified',
      });
    }
  });

  it('never reads the upstream provider for an identity that is not upstream', () => {
    // An unconfirmed password stays unconfirmed, whatever a provider says.
    expect(
      decideVerifiedOwner(
        {
          providerType: 'password',
          credentialData: buildPasswordCredentialData('$argon2id$h', false, null),
        },
        { marksVerified: true }
      )
    ).toEqual({ verified: false, identity: 'password', reason: 'account_not_verified' });
  });

  it('tells the kind of a primary credential by its type, and an upstream one by its data', () => {
    expect(primaryIdentityKindOf({ providerType: 'password', credentialData: {} })).toBe(
      'password'
    );
    expect(primaryIdentityKindOf({ providerType: 'webauthn', credentialData: {} })).toBe('passkey');
    expect(primaryIdentityKindOf({ providerType: 'wallet', credentialData: {} })).toBe('wallet');
    expect(
      primaryIdentityKindOf({ providerType: 'oidc_corp', credentialData: UPSTREAM_DATA })
    ).toBe('upstream');
    expect(primaryIdentityKindOf({ providerType: 'oidc_corp', credentialData: {} })).toBe('other');
  });
});
