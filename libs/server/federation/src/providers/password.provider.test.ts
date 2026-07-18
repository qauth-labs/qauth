import { describe, expect, it } from 'vitest';

import {
  buildPasswordCredentialData,
  createPasswordProvider,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
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
      expect(buildPasswordCredentialData('$argon2id$h', true)).toEqual({
        password_hash: '$argon2id$h',
        email_verified: true,
      });
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
