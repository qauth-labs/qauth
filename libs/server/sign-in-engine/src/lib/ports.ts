import type { StepName } from '@qauth-labs/server-step-grammar';

/**
 * THE ENGINE'S PORTS: everything the sign-in engine reads or calls, as
 * interfaces. The engine itself does no I/O; each deployment passes the
 * adapters (`@qauth-labs/fastify-plugin-sign-in-engine` holds the auth
 * server's), and a test passes fakes (`src/testing/`).
 */

/**
 * An authenticator type the engine ranks or asks for. `password` and
 * `passkey` are first factors; `totp` is a second factor (#653). An email
 * code is not an authenticator and is never here (ADR-017 Decision 5).
 */
export const FACTOR_TYPES = ['password', 'passkey', 'totp'] as const;
export type FactorType = (typeof FACTOR_TYPES)[number];

/**
 * One authenticator bound to an account. A disabled one (the ladder's hard
 * action, `user_credentials.disabled_at`, #615) cannot be used, and still
 * counts as bound for the downgrade rule and the MFA policy (ADR-017
 * Decisions 4 and 7).
 */
export type BoundFactor =
  | {
      readonly type: 'password';
      readonly disabled: boolean;
      /**
       * The stored Argon2id hash, or `null` when the credential's data cannot
       * be read: the engine then verifies against the dummy hash and refuses,
       * as for an account with no password.
       */
      readonly hash: string | null;
    }
  | { readonly type: 'passkey' | 'totp'; readonly disabled: boolean };

/** What the engine knows of an account. Nothing of it reaches an answer before a factor succeeds. */
export interface SignInAccount {
  /** The user id: the subject a completed sign-in carries. */
  readonly userId: string;
  /** `users.enabled`. A disabled user is answered as a wrong password and never changed. */
  readonly enabled: boolean;
  /**
   * Whether the account's primary identity is proved (for a password
   * account, its address). `REQUIRE_VERIFIED_ACCOUNT` refuses an unverified
   * one like a wrong password until PRO-15 (#638) verifies it inline.
   */
  readonly verified: boolean;
  /** Whether the account holds an admin role in the realm, for the `required_for_admins` MFA policy. */
  readonly admin: boolean;
  /** Every authenticator bound to it, disabled ones included. */
  readonly factors: readonly BoundFactor[];
}

/** Where the engine reads accounts. */
export interface AccountDirectory {
  /**
   * The account `identifier` names in the realm, or `null` when none does.
   * `identifier` is already checked and normalised.
   */
  findByIdentifier(realmId: string, identifier: string): Promise<SignInAccount | null>;
}

/** Argon2id, for the password step. */
export interface PasswordVerifier {
  /** Whether `presented` is the password `hash` was made from. */
  verify(hash: string, presented: string): Promise<boolean>;
  /**
   * Spend one verification of `presented` against a dummy hash, for an
   * identifier with no usable password, so it costs what a real check does
   * (ADR-017 Decision 7). Never throws for a wrong password.
   */
  verifyDecoy(presented: string): Promise<void>;
}

/** How a realm or a client sets MFA (ADR-020): off, optional, required, or required for admins. */
export const MFA_MODES = ['off', 'optional', 'required', 'required_for_admins'] as const;
export type MfaMode = (typeof MFA_MODES)[number];

/** The MFA policy that applies to one round: the realm's and the client's. */
export interface MfaPolicy {
  readonly realm: MfaMode;
  readonly client: MfaMode;
}

/**
 * Where the engine reads the MFA policy: on every round, never from the
 * transaction, so a change reaches live transactions (ADR-017 Decision 4).
 * A read that throws refuses the round.
 */
export interface MfaPolicyReader {
  read(input: { readonly realmId: string; readonly clientId: string }): Promise<MfaPolicy>;
}

/**
 * The policy until its storage exists (Foundations, the admin console): no
 * second factor is required, for the realm or for any client.
 */
export const NO_SECOND_FACTOR_POLICY: MfaPolicyReader = Object.freeze({
  read: async () => Object.freeze({ realm: 'off', client: 'off' }) as MfaPolicy,
});

/**
 * The keyed HMAC of an identifier: HMAC-SHA-256 under a server-side key,
 * base64url without padding (43 characters), bound to the realm. It names
 * the person in audit records while no user is resolved, and keys the
 * ladder whether or not an account holds the identifier.
 */
export type IdentifierDigest = (input: {
  readonly realmId: string;
  readonly identifier: string;
}) => Promise<string>;

/** Why an audit record refused or ended: a closed set, which grows with the steps. */
export const SIGN_IN_AUDIT_REASONS = [
  /** A refused credential: a wrong password, no account, no usable password. */
  'invalid_credentials',
  /** The password was right, and the user is disabled. */
  'account_disabled',
  /** The password was right, and the account is unverified while `REQUIRE_VERIFIED_ACCOUNT` is on. */
  'email_not_verified',
  /** The identifier's ladder is inside a wait: not verified, not counted. */
  'locked_out',
  /** One subject per transaction: another identifier, or another user's proof. */
  'subject_mismatch',
  /** A bot challenge was answered wrongly (PRO-19). */
  'captcha_failed',
] as const;
export type SignInAuditReason = (typeof SIGN_IN_AUDIT_REASONS)[number];

/**
 * One audit record of a round: what happened to one step. It never holds a
 * password, a code or the identifier: the person is named by the user id once
 * a factor resolved one, and by the identifier's keyed HMAC before. Exactly
 * one of the two is set.
 */
export type SignInAuditRecord = {
  /** `passed`: the step's answer was accepted. `refused`: it was not. `ended`: the transaction ended. */
  readonly outcome: 'passed' | 'refused' | 'ended';
  readonly step: StepName;
  /** Why it was refused or ended; absent when it passed. */
  readonly reason?: SignInAuditReason;
} & (
  | { readonly userId: string; readonly identifierHmac?: undefined }
  | { readonly identifierHmac: string; readonly userId?: undefined }
);

/** Where a round's audit records go: the transport's event writer, in order. A write that fails fails the round. */
export type AuditSink = (record: SignInAuditRecord) => Promise<void>;

/** The engine's clock: `now` in epoch milliseconds, and a wait. */
export interface Clock {
  now(): number;
  sleep(milliseconds: number): Promise<void>;
}

/** The system clock. */
export const SYSTEM_CLOCK: Clock = Object.freeze({
  now: () => Date.now(),
  sleep: (milliseconds: number) =>
    new Promise<void>((resolve) => {
      setTimeout(resolve, milliseconds);
    }),
});
