import { z } from 'zod';

import { WEBAUTHN_ALGORITHMS, WEBAUTHN_TRANSPORTS } from '../webauthn/webauthn.types';

/**
 * The `credential_data` JSONB shape for `provider_type='webauthn'` rows
 * (ADR-017 Decision 14, issue #467). This module is its only owner, as
 * `password.provider.ts` is for password rows: nothing else may hand-roll the
 * object. `external_sub` is the credential id; everything else about the
 * passkey is here.
 *
 * Keys are snake_case, like every `credential_data` shape. Deliberately NOT
 * `.strict()`: a later change may add a sibling key, and today's binary must
 * keep reading the row then.
 */
export const webauthnCredentialDataSchema = z.object({
  /** The credential public key, a COSE_Key exactly as the authenticator wrote it, base64url. */
  public_key: z.string().min(1),
  /** Its COSE algorithm: EdDSA (-8), ES256 (-7) or RS256 (-257). */
  algorithm: z.union(WEBAUTHN_ALGORITHMS.map((alg) => z.literal(alg))),
  /** The highest signature counter seen (WebAuthn Level 3 §6.1.1). */
  sign_count: z.number().int().min(0).max(0xffff_ffff),
  /** The transports the client reported at registration, for `allowCredentials` hints. */
  transports: z.array(z.enum(WEBAUTHN_TRANSPORTS)),
  /** The BE flag at registration. Fixed for the credential's life (§6.1.3). */
  backup_eligible: z.boolean(),
  /** The BS flag as last seen: whether the passkey is synced now. */
  backed_up: z.boolean(),
  /** The authenticator's AAGUID as reported, unverified (no attestation is trusted). */
  aaguid: z.string(),
  /** The RP ID the credential was created under. */
  rp_id: z.string().min(1),
  /** The WebAuthn user handle the credential was created for, base64url. */
  user_handle: z.string().min(1),
  /** The name the user gave the passkey, or `null`. */
  nickname: z.string().max(64).nullable(),
  /** Epoch milliseconds of the registration. */
  created_at: z.number().int(),
  /** Epoch milliseconds of the last accepted assertion, or `null`. */
  last_used_at: z.number().int().nullable(),
  /**
   * Epoch milliseconds of the last assertion whose counter did not grow past a
   * nonzero stored counter, or `null`. A signal that the authenticator may
   * have been cloned (§6.1.1); see `WebAuthnProvider.verify`.
   */
  sign_counter_regressed_at: z.number().int().nullable(),
});

export type WebAuthnCredentialData = z.infer<typeof webauthnCredentialDataSchema>;

/** Longest nickname kept, in characters. */
export const WEBAUTHN_NICKNAME_MAX_LENGTH = 64;

/**
 * Tidy a user-given passkey name: trimmed, control characters removed, at most
 * {@link WEBAUTHN_NICKNAME_MAX_LENGTH} characters. Empty becomes `null`.
 */
export function normalisePasskeyNickname(nickname: string | null | undefined): string | null {
  if (nickname === null || nickname === undefined) return null;
  // eslint-disable-next-line no-control-regex -- removing control characters is the point
  const cleaned = nickname.replace(/[\u0000-\u001f\u007f-\u009f]/gu, '').trim();
  if (cleaned === '') return null;
  return Array.from(cleaned).slice(0, WEBAUTHN_NICKNAME_MAX_LENGTH).join('');
}
