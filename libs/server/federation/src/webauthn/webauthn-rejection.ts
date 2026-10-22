/**
 * Why a WebAuthn ceremony was refused (ADR-017 Decision 14, issue #467).
 *
 * The reason is for the SERVER: logs, metrics, and tests that must show a
 * refusal fired for the right cause. A caller may branch on it, but must not put
 * it, or this error's message, on a response. A response that told a caller
 * "wrong origin" from "bad signature" would help an attacker tune a forged
 * assertion; the wire answer is the same for every reason.
 *
 * - `malformed-response` — the browser response or one of its parts does not
 *   decode, or is inconsistent with itself (the credential id in the
 *   authenticator data is not the one the response names; BS set without BE).
 * - `challenge-unavailable` — no live ceremony for this transaction: never
 *   started, expired, or already answered. A reused challenge lands here,
 *   because the first answer consumed it.
 * - `ceremony-mismatch` — `clientDataJSON.type` is not the ceremony the
 *   transaction started (`webauthn.create` for registration, `webauthn.get`
 *   for authentication), or the transaction was started for the other one.
 * - `challenge-mismatch` — `clientDataJSON.challenge` is not this
 *   transaction's challenge.
 * - `origin-mismatch` — `clientDataJSON.origin` is not an origin the
 *   transaction allows.
 * - `cross-origin` — the ceremony ran in a cross-origin iframe. QAuth's pages
 *   are never framed, and a first-party app does not frame them.
 * - `rp-id-mismatch` — the authenticator data's RP ID hash is not the SHA-256
 *   of the transaction's RP ID.
 * - `user-not-present` — the UP flag is not set.
 * - `user-not-verified` — the transaction requires user verification and the
 *   UV flag is not set. Sign-in always requires it.
 * - `unsupported-algorithm` — the credential's key is not ES256, EdDSA or
 *   RS256.
 * - `attestation-invalid` — the attestation statement does not verify.
 * - `signature-invalid` — the assertion signature does not verify under the
 *   stored public key.
 * - `credential-mismatch` — the response names a credential the transaction
 *   does not allow, or not the stored credential it is checked against.
 * - `user-handle-mismatch` — the response's user handle is not the one stored
 *   with the credential.
 * - `backup-eligibility-changed` — the BE flag differs from the one recorded at
 *   registration (WebAuthn Level 3 §7.2 step 18).
 */
export type WebAuthnRejectionReason =
  | 'malformed-response'
  | 'challenge-unavailable'
  | 'ceremony-mismatch'
  | 'challenge-mismatch'
  | 'origin-mismatch'
  | 'cross-origin'
  | 'rp-id-mismatch'
  | 'user-not-present'
  | 'user-not-verified'
  | 'unsupported-algorithm'
  | 'attestation-invalid'
  | 'signature-invalid'
  | 'credential-mismatch'
  | 'user-handle-mismatch'
  | 'backup-eligibility-changed';

/**
 * A refused WebAuthn registration or assertion. `message` is fixed text that
 * names no value from the request; `reason` says why, for the server only.
 */
export class WebAuthnRejection extends Error {
  readonly statusCode = 401;
  readonly code = 'WEBAUTHN_REJECTED';

  constructor(
    public readonly reason: WebAuthnRejectionReason,
    options?: { cause?: unknown }
  ) {
    super('The passkey response was refused', options);
    this.name = 'WebAuthnRejection';
    Object.setPrototypeOf(this, WebAuthnRejection.prototype);
  }
}
