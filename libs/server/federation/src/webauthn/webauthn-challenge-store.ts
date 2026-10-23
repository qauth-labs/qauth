import { z } from 'zod';

import { WEBAUTHN_PURPOSES, type WebAuthnPurpose } from './webauthn.types';

/**
 * Where a WebAuthn ceremony waits between its two rounds (issue #467).
 *
 * A ceremony is two requests: QAuth sends options with a fresh challenge, and
 * the browser answers. The state that binds the answer to the question lives
 * here, keyed by the TRANSACTION the ceremony belongs to (a FiPA
 * `auth_session`, a hosted page's flow, an approval request). So a challenge is
 * bound to its transaction: an answer is checked only against the state stored
 * under the transaction it arrives with.
 *
 * Single use is this port's job: {@link WebAuthnChallengeStore.take} removes
 * the state in the same atomic step that reads it (Redis `GETDEL` in the
 * deployment store), so of two answers racing for one challenge exactly one
 * finds it. The provider calls `take` BEFORE it verifies anything, so a failed
 * answer burns the challenge too.
 */
export interface WebAuthnChallengeStore {
  /**
   * Store the state of a ceremony that is starting, for `ttlMs`, REPLACING any
   * ceremony the transaction has waiting (a plain Redis `SET … PX` in the
   * deployment store).
   *
   * A transaction runs one ceremony at a time, and the newest start wins. A
   * user who dismisses the platform prompt, or a page whose autofill request is
   * still pending when the user picks the passkey button, asks for new options
   * on the same transaction; refusing that until the old state expired would
   * lock the user out for the ceremony timeout. Replacing costs nothing: an
   * answer to the replaced challenge is refused (`challenge-mismatch`).
   */
  begin(transactionId: string, state: WebAuthnCeremonyState, ttlMs: number): Promise<void>;

  /**
   * Remove the transaction's ceremony state and return it, in one atomic step.
   * `undefined` when there is none: never started, expired, or already taken.
   */
  take(transactionId: string): Promise<WebAuthnCeremonyState | undefined>;
}

/**
 * What a ceremony's answer must match, fixed when the ceremony starts. Every
 * member comes from the server (the realm, the client, the account), never
 * from the answer, so the answer cannot widen what it is checked against.
 */
export const webauthnCeremonyStateSchema = z
  .object({
    ceremony: z.enum(['registration', 'authentication']),
    purpose: z.enum(WEBAUTHN_PURPOSES as [WebAuthnPurpose, ...WebAuthnPurpose[]]),
    /** The challenge, base64url. */
    challenge: z.string().min(1),
    /** The RP ID the ceremony runs under. */
    rpId: z.string().min(1),
    /** The origins an answer may come from: the realm's, and the client's operator-set ones. */
    origins: z.array(z.string().min(1)).min(1),
    /** Registration only: the user handle the credential is created for, base64url. */
    userHandle: z.string().min(1).optional(),
    /**
     * Authentication only: the credentials that may answer, base64url. Empty
     * means any discoverable credential of the RP ID (a passkey-first sign-in,
     * where the account is not known yet).
     */
    allowCredentialIds: z.array(z.string().min(1)).optional(),
    /** Epoch milliseconds after which the answer is refused, whatever the store's TTL did. */
    expiresAt: z.number().int(),
  })
  .strict();

export type WebAuthnCeremonyState = z.infer<typeof webauthnCeremonyStateSchema>;
