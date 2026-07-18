import { normalizeEmail } from '@qauth-labs/shared-validation';
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
 * by the auth routes. A camelCase drift here would pass every DB constraint
 * and strand every login, so nothing else may hand-roll this object.
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
 */
export const passwordCredentialDataSchema = z.object({
  password_hash: z.string().min(1),
  email_verified: z.boolean(),
});

export type PasswordCredentialData = z.infer<typeof passwordCredentialDataSchema>;

/**
 * Build the `credential_data` object for a password credential row. The only
 * sanctioned constructor of this shape (see module JSDoc).
 */
export function buildPasswordCredentialData(
  passwordHash: string,
  emailVerified: boolean
): PasswordCredentialData {
  return {
    password_hash: passwordHash,
    email_verified: emailVerified,
  };
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
