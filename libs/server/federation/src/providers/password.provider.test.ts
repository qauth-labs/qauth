import { describe, expect, it } from 'vitest';

import {
  buildPasswordCredentialData,
  createPasswordProvider,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  passwordSetAtOf,
  presentedPasswordFor,
  SELF_REPORTED_SOURCE,
} from './password.provider';

describe('PasswordProvider (ADR-003)', () => {
  const provider = createPasswordProvider();

  it('registers under the password type', () => {
    expect(provider.type).toBe(PASSWORD_PROVIDER_TYPE);
  });

  describe('verify', () => {
    it('returns a normalized VerifiedIdentity with assuranceLevel low', async () => {
      const identity = await provider.verify({
        email: 'user@example.com',
        passwordHash: '$argon2id$fake',
        emailVerified: true,
      });

      expect(identity).toEqual({
        externalSub: 'user@example.com',
        assuranceLevel: 'low',
        rawClaims: { email: 'user@example.com', email_verified: true },
      });
    });

    it('normalizes mixed-case email into externalSub', async () => {
      const identity = await provider.verify({
        email: '  User@Example.COM ',
        passwordHash: '$argon2id$fake',
        emailVerified: false,
      });

      expect(identity.externalSub).toBe('user@example.com');
      // rawClaims carries the email exactly as provided by the caller.
      expect(identity.rawClaims['email']).toBe('  User@Example.COM ');
    });

    it.each([
      ['missing email', { passwordHash: 'h', emailVerified: false }],
      ['empty email', { email: '', passwordHash: 'h', emailVerified: false }],
      ['missing passwordHash', { email: 'a@b.co', emailVerified: false }],
      ['missing emailVerified', { email: 'a@b.co', passwordHash: 'h' }],
      ['mistyped emailVerified', { email: 'a@b.co', passwordHash: 'h', emailVerified: 'yes' }],
      ['unknown extra key', { email: 'a@b.co', passwordHash: 'h', emailVerified: false, x: 1 }],
      ['non-object input', 'not-an-object'],
    ])('rejects malformed input: %s', async (_label, input) => {
      await expect(provider.verify(input)).rejects.toThrow(/malformed input/);
    });
  });

  describe('extractAttributes', () => {
    it('maps a verified identity to the backfill-shaped email attribute', async () => {
      const identity = await provider.verify({
        email: 'user@example.com',
        passwordHash: '$argon2id$fake',
        emailVerified: true,
      });

      expect(provider.extractAttributes(identity)).toEqual([
        {
          source: SELF_REPORTED_SOURCE,
          attrKey: 'email',
          attrValue: 'user@example.com',
          verified: true,
        },
      ]);
    });

    it('carries verified=false through for unverified emails', async () => {
      const identity = await provider.verify({
        email: 'user@example.com',
        passwordHash: '$argon2id$fake',
        emailVerified: false,
      });

      expect(provider.extractAttributes(identity)[0].verified).toBe(false);
    });

    it('rejects rawClaims without the email produced by verify()', () => {
      expect(() =>
        provider.extractAttributes({
          externalSub: 'x',
          assuranceLevel: 'low',
          rawClaims: {},
        })
      ).toThrow(/rawClaims\.email/);
    });
  });

  describe('credential_data shape ownership', () => {
    it('buildPasswordCredentialData emits the exact snake_case shape', () => {
      expect(buildPasswordCredentialData('$argon2id$h', true, null, 1_700_000_000_000)).toEqual({
        password_hash: '$argon2id$h',
        email_verified: true,
        password_set_at: 1_700_000_000_000,
      });
    });

    it('records the NFC marker of a password hashed under the policy (#634)', () => {
      const data = buildPasswordCredentialData('$argon2id$h', false, 'nfc', 1_700_000_000_000);

      expect(data).toEqual({
        password_hash: '$argon2id$h',
        email_verified: false,
        password_normalization: 'nfc',
        password_set_at: 1_700_000_000_000,
      });
      // The set time is no member of the schema a sign-in reads (#1107).
      const { password_set_at: _setAt, ...read } = data;
      expect(passwordCredentialDataSchema.parse(data)).toEqual(read);
    });

    it('records when the password was set, now unless told (#1107)', () => {
      const before = Date.now();
      const data = buildPasswordCredentialData('$argon2id$h', true, 'nfc');

      expect(data.password_set_at).toBeGreaterThanOrEqual(before);
      expect(data.password_set_at).toBeLessThanOrEqual(Date.now());
      expect(passwordSetAtOf(data)).toBe(data.password_set_at);
    });

    it('reads no set time from a credential written before #1107, or one that is no time', () => {
      expect(passwordSetAtOf({ password_hash: '$argon2id$h', email_verified: true })).toBe(
        undefined
      );
      for (const value of ['1700000000000', 0, -1, 1.5, Number.MAX_SAFE_INTEGER + 2, null]) {
        expect(passwordSetAtOf({ password_set_at: value }), String(value)).toBe(undefined);
      }
      expect(passwordSetAtOf(null)).toBe(undefined);
      expect(passwordSetAtOf('data')).toBe(undefined);
      // A value that is no time never makes the password unreadable.
      expect(
        passwordCredentialDataSchema.safeParse({
          password_hash: '$argon2id$h',
          email_verified: true,
          password_set_at: 'yesterday',
        }).success
      ).toBe(true);
    });

    it('reads a credential without the marker, as every credential before #634 is', () => {
      const parsed = passwordCredentialDataSchema.parse({
        password_hash: '$argon2id$h',
        email_verified: true,
      });

      expect(parsed.password_normalization).toBeUndefined();
    });

    it('refuses a marker of another value, rather than verify the password the wrong way', () => {
      for (const marker of ['nfd', 'NFC', 'nfkc', true, '']) {
        expect(
          passwordCredentialDataSchema.safeParse({
            password_hash: '$argon2id$h',
            email_verified: true,
            password_normalization: marker,
          }).success
        ).toBe(false);
      }
    });

    it('presents the password in NFC to a credential with the marker, and as typed to one without', () => {
      const composed = 'caf\u00e9-terrace-at-night';
      const decomposed = 'cafe\u0301-terrace-at-night';

      expect(presentedPasswordFor({ password_normalization: 'nfc' }, decomposed)).toBe(composed);
      expect(presentedPasswordFor({ password_normalization: 'nfc' }, composed)).toBe(composed);
      expect(presentedPasswordFor({}, decomposed)).toBe(decomposed);
      expect(presentedPasswordFor({}, composed)).toBe(composed);
    });

    it('passwordCredentialDataSchema accepts forward-compatible sibling keys', () => {
      const parsed = passwordCredentialDataSchema.safeParse({
        password_hash: '$argon2id$h',
        email_verified: false,
        future_key: 'tolerated',
      });
      expect(parsed.success).toBe(true);
    });

    it('passwordCredentialDataSchema rejects a camelCase drift', () => {
      const parsed = passwordCredentialDataSchema.safeParse({
        passwordHash: '$argon2id$h',
        emailVerified: false,
      });
      expect(parsed.success).toBe(false);
    });
  });
});
