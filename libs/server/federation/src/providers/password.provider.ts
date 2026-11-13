import {
  normalizeEmail,
  PASSWORD_NORMALIZATION_NFC,
  passwordForVerification,
  type PasswordNormalization,
} from '@qauth-labs/shared-validation';
import { z } from 'zod';

import type {
  CredentialProvider,
  UserAttribute,
  VerifiedIdentity,
} from './credential-provider.interface';

/**
 * PasswordProvider — the first {@link CredentialProvider} (ADR-003, issue #228).
 *
 * ## Division of responsibility (caller precondition)
 *
 * For `type='password'` the secret check does NOT happen inside `verify()`:
 * the caller MUST have already compared the presented plaintext password
 * against `credential_data.password_hash` (argon2id via the fastify password
 * plugin) and only call `verify()` after that comparison succeeded. This is
 * fixed by the ADR-003 input contract — `verify({ email, passwordHash,
 * emailVerified })` carries no plaintext — and keeps this lib framework-free.
 * `verify()` validates the credential-record shape and derives the normalized
 * {@link VerifiedIdentity}. Future providers (wallet, upstream OIDC) verify
 * their cryptography inside `verify()`; password is the one type whose secret
 * check already has a home in the route layer.
 *
 * ## Shape ownership
 *
 * This module is the single owner of the `credential_data` JSONB shape for
 * `provider_type='password'` ({@link passwordCredentialDataSchema},
 * {@link buildPasswordCredentialData}): `{ password_hash, email_verified }`
 * with snake_case keys — the exact shape written by the #226 backfill and read
 * by the auth routes — and, since #634, the optional normalisation marker
 * `password_normalization`, and, since #1107, `password_set_at`, when the
 * password was set. A camelCase drift here would pass every DB constraint and
 * strand every login, so nothing else may hand-roll this object.
 */

/** `user_credentials.provider_type` / registry key for this provider. */
export const PASSWORD_PROVIDER_TYPE = 'password';

/** `user_attributes.source` for password-derived (user-asserted) attributes. */
export const SELF_REPORTED_SOURCE = 'self_reported';

/** `user_attributes.attr_key` of the email attribute this provider extracts. */
export const EMAIL_ATTR_KEY = 'email';

/**
 * Input contract of {@link CredentialProvider.verify} for `'password'`
 * (ADR-003): the credential record's fields, never the plaintext password.
 * `.strict()` because callers construct this object in-process — an unknown
 * key means a programming error, not forward-compatible data.
 */
export const passwordVerifyInputSchema = z
  .object({
    email: z.string().min(1),
    passwordHash: z.string().min(1),
    emailVerified: z.boolean(),
  })
  .strict();

export type PasswordVerifyInput = z.infer<typeof passwordVerifyInputSchema>;

/**
 * `credential_data` JSONB shape for `provider_type='password'` rows.
 * Deliberately NOT `.strict()`: later issues may add sibling keys to
 * `credential_data`, and readers of today's binary must keep parsing then.
 *
 * `password_normalization` (#634, ADR-017 Decision 8) records how the
 * password was normalised before it was hashed: `'nfc'` for a password set
 * under the one password policy, absent for one set before it, which was
 * hashed as typed. Every verifier presents the password the way the marker
 * says ({@link presentedPasswordFor}). A marker of another value fails this
 * schema, so a credential this release cannot verify correctly is refused as
 * unreadable rather than checked the wrong way.
 *
 * `password_set_at` (#1107) is no member here: it says only when the password
 * was set, which no sign-in reads, so a value of it that is no time can never
 * make a password unreadable. {@link passwordSetAtOf} reads it.
 */
export const passwordCredentialDataSchema = z.object({
  password_hash: z.string().min(1),
  email_verified: z.boolean(),
  password_normalization: z.literal(PASSWORD_NORMALIZATION_NFC).optional(),
});

export type PasswordCredentialData = z.infer<typeof passwordCredentialDataSchema>;

/** The `credential_data` of a password just set: the shape, and when it was set. */
export type BuiltPasswordCredentialData = PasswordCredentialData & {
  /** When the password was set, in epoch milliseconds (#1107). */
  readonly password_set_at: number;
};

/**
 * Build the `credential_data` object for a password credential row. The only
 * sanctioned constructor of this shape (see module JSDoc).
 *
 * Every caller writes the hash it passes as the credential's new password, so
 * the object records when that password was set (`password_set_at`, #1107):
 * the account API reads it as the password's `changedAt`.
 *
 * @param passwordHash - The Argon2id hash of the password in the form
 *   `normalization` names.
 * @param emailVerified - Whether the address is confirmed.
 * @param normalization - The normalisation the password went through before
 *   it was hashed: the `normalization` the password policy's check returned
 *   for a new password, `null` for a hash of a password as typed (one carried
 *   over from elsewhere). Required, so no caller records a hash without saying
 *   which.
 * @param setAt - When the password is set, in epoch milliseconds: now, unless
 *   the caller has its own clock.
 */
export function buildPasswordCredentialData(
  passwordHash: string,
  emailVerified: boolean,
  normalization: PasswordNormalization | null,
  setAt: number = Date.now()
): BuiltPasswordCredentialData {
  return {
    password_hash: passwordHash,
    email_verified: emailVerified,
    ...(normalization === null ? {} : { password_normalization: normalization }),
    password_set_at: setAt,
  };
}

/**
 * When the password of a password credential was set (#1107), from its
 * `credential_data`: `password_set_at`. `undefined` for a credential whose
 * password was set before #1107 recorded it, or a value that is no time.
 */
export function passwordSetAtOf(credentialData: unknown): number | undefined {
  if (typeof credentialData !== 'object' || credentialData === null) return undefined;
  const value = (credentialData as Record<string, unknown>)['password_set_at'];
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

/**
 * The presented password to verify against a credential's hash: in NFC when
 * the credential records the NFC marker, as typed when it records none (#634).
 * Every password verifier goes through this, so two spellings of one text
 * verify against a hash made under the policy, and a password set before it
 * still verifies as it was typed.
 */
export function presentedPasswordFor(
  credential: Pick<PasswordCredentialData, 'password_normalization'>,
  presented: string
): string {
  return passwordForVerification(presented, credential.password_normalization);
}

/**
 * Create the password {@link CredentialProvider}.
 *
 * Stateless and dependency-free — safe to construct once at bootstrap and
 * register in the provider registry.
 */
export function createPasswordProvider(): CredentialProvider {
  return {
    type: PASSWORD_PROVIDER_TYPE,

    /**
     * Validate the credential record shape and derive the normalized identity.
     *
     * PRECONDITION: the caller has already argon2-verified the presented
     * plaintext against `credential_data.password_hash` (see module JSDoc).
     *
     * @throws Error on input-shape violation — an internal invariant breach
     * (routes validate `credential_data` before calling), never mapped to a
     * wire error.
     */
    async verify(input: unknown): Promise<VerifiedIdentity> {
      const parsed = passwordVerifyInputSchema.safeParse(input);
      if (!parsed.success) {
        throw new Error(
          `PasswordProvider.verify received a malformed input: ${parsed.error.message}`
        );
      }
      const { email, emailVerified } = parsed.data;
      return {
        // Guarantees externalSub === user_credentials.external_sub regardless
        // of caller discipline (normalizeEmail is idempotent).
        externalSub: normalizeEmail(email),
        // Self-asserted email/password carries the lowest eIDAS LoA; 'low'
        // emits no acr claim per ADR-003.
        assuranceLevel: 'low',
        rawClaims: {
          email,
          email_verified: emailVerified,
        },
      };
    },

    extractAttributes(result: VerifiedIdentity): UserAttribute[] {
      const email = result.rawClaims['email'];
      if (typeof email !== 'string' || email.length === 0) {
        throw new Error(
          'PasswordProvider.extractAttributes requires rawClaims.email produced by verify()'
        );
      }
      return [
        {
          source: SELF_REPORTED_SOURCE,
          attrKey: EMAIL_ATTR_KEY,
          attrValue: email,
          // Matches the #226 backfill row shape: verified mirrors the
          // credential's email_verified flag.
          verified: result.rawClaims['email_verified'] === true,
        },
      ];
    },
  };
}
