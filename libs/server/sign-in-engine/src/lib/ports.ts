import type { StepName } from '@qauth-labs/server-step-grammar';
import type {
  PasswordNormalization,
  PasswordRejectionReason,
} from '@qauth-labs/shared-validation';

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
 * A counter of the failure ladder (#615): one per factor, and the email
 * codes' (#638, ADR-017 Decision 7: "the same key, a separate counter"),
 * which counts wrong codes and is never a factor.
 */
export const LADDER_COUNTERS = [...FACTOR_TYPES, 'email_code'] as const;
export type LadderCounter = (typeof LADDER_COUNTERS)[number];

/**
 * One authenticator bound to an account. A disabled one (the ladder's hard
 * action, `user_credentials.disabled_at`, #615) cannot be used, and still
 * counts as bound for the downgrade rule and the MFA policy (ADR-017
 * Decisions 4 and 7).
 */
export interface BoundFactor {
  readonly type: FactorType;
  readonly disabled: boolean;
}

/**
 * What the first factor needs of the account an identifier names, and no
 * more: it is read before any credential is checked, so the read must cost
 * and risk as little as it can for an account that exists. Nothing of it
 * reaches an answer before a factor succeeds.
 */
export interface SignInCandidate {
  /** The user id: the subject a completed sign-in carries. */
  readonly userId: string;
  /** `users.enabled`. A disabled user is answered as a wrong password and never changed. */
  readonly enabled: boolean;
  /**
   * Whether the account's primary identity is proved (for a password
   * account, its address). An engine built with `emailCodes` proves an
   * unverified one's password and verifies its address inline (#638); one
   * built without refuses it like a wrong password under
   * `REQUIRE_VERIFIED_ACCOUNT`.
   */
  readonly verified: boolean;
  /**
   * The account's password, when it has one: whether it is disabled, and its
   * Argon2id hash, `null` when the credential's data cannot be read. Without
   * a usable one the engine verifies against the dummy hash and refuses.
   *
   * `disabled` is the ladder's disabled mark while the hard action is armed
   * (#615); while it is unarmed the lookup ignores a mark, reports it as
   * `ignoredMark`, and a successful sign-in clears it.
   *
   * `normalization` is the credential's normalisation marker (#634): `'nfc'`
   * when the password was hashed in NFC, so the presented one is verified in
   * NFC too; absent when it was hashed as typed.
   */
  readonly password: {
    readonly disabled: boolean;
    readonly hash: string | null;
    readonly normalization?: PasswordNormalization;
    readonly ignoredMark?: boolean;
  } | null;
}

/**
 * What an account may owe before its next sign-in completes (#635, the
 * `user_required_actions` table): a new password, a second factor, a passkey,
 * its profile. The engine acts on `update_password`; the others are the steps
 * of PRO-28 and PRO-29.
 */
export const REQUIRED_ACTIONS = [
  'update_password',
  'setup_mfa',
  'setup_passkey',
  'complete_profile',
] as const;
export type RequiredAction = (typeof REQUIRED_ACTIONS)[number];

/** What rule 8 needs of the account a factor proved: read only after the proof. */
export interface SignInAccount {
  readonly userId: string;
  /** `users.enabled`, read again: an account disabled after its factor ends the transaction. */
  readonly enabled: boolean;
  /** Whether the account holds an admin role in the realm, for the `required_for_admins` MFA policy. */
  readonly admin: boolean;
  /**
   * Whether its primary identity is proved, read again: an account whose
   * password credential's address is not proved yet is verified inline after
   * its password (#638). An account with no password credential (a passkey or
   * a wallet is its primary identity) has no address to prove and is
   * verified.
   */
  readonly verified: boolean;
  /** Every authenticator bound to it, disabled ones included. */
  readonly factors: readonly BoundFactor[];
  /**
   * The required actions it holds (#635): `update_password` asks for a new
   * password before the sign-in completes, as a password on the breach list
   * does. An admin's request or the person's "this wasn't me" writes it; the
   * forced update clears it.
   */
  readonly requiredActions: readonly RequiredAction[];
}

/** Where the engine reads accounts. */
export interface AccountDirectory {
  /**
   * What the first factor needs of the account `identifier` names in the
   * realm, or `null` when none does. `identifier` is already checked and
   * normalised.
   */
  findByIdentifier(realmId: string, identifier: string): Promise<SignInCandidate | null>;
  /** The account of a user a factor proved, every factor included, or `null` when the realm has none. */
  findByUserId(realmId: string, userId: string): Promise<SignInAccount | null>;
}

/** Argon2id, for the password step. */
export interface PasswordVerifier {
  /**
   * Whether `presented` is the password `hash` was made from. A hash it
   * cannot read answers `false`: a throw is an outage, which refuses the
   * round, and must not depend on the account.
   */
  verify(hash: string, presented: string): Promise<boolean>;
  /**
   * Spend one verification of `presented` against a dummy hash, for an
   * identifier with no usable password, so it costs what a real check does
   * (ADR-017 Decision 7). It fails only as {@link verify} would.
   */
  verifyDecoy(presented: string): Promise<void>;
}

/** Which password the hard action is about: the one `identifier` names in the realm, of `userId`. */
export interface PasswordHardActionInput {
  readonly realmId: string;
  readonly userId: string;
  /** The normalised identifier: the password credential's own key. */
  readonly identifier: string;
}

/**
 * The hard action of the password's failure ladder (ADR-017 Decision 7,
 * #615). The engine calls it after the verdict is made, and a failure of it
 * never changes the answer: it is reported through `onUnavailable`.
 */
export interface PasswordHardAction {
  /**
   * A failure of the password counted at or past the ladder's hard ceiling,
   * for an account that exists and is enabled: disable the password, notify
   * the owner and alert the operator. Only while the hard action is armed,
   * which the adapter checks at run time (the hosted reset is on and the
   * deployment can send the notices); unarmed, it changes nothing. Idempotent.
   */
  ceilingReached(input: PasswordHardActionInput): Promise<void>;
  /**
   * The password proved the account while the lookup ignored its disabled
   * mark (the hard action unarmed): clear the mark, as the owner's reset
   * would.
   */
  clearIgnoredMark(input: PasswordHardActionInput): Promise<void>;
}

/** No hard action: a ceiling disables nothing and a mark stays. The default, for tests. */
export const NO_HARD_ACTION: PasswordHardAction = Object.freeze({
  ceilingReached: async () => undefined,
  clearIgnoredMark: async () => undefined,
});

/**
 * Why a breach-list check could not be made (#635): the realm names a source
 * the deployment has not configured (`not_configured`), the local list has
 * not loaded (`list_not_loaded`), the egress client refused the lookup
 * (`lookup_blocked`), the lookup failed or answered an error
 * (`lookup_failed`), its answer could not be read (`bad_response`), or the
 * port threw (`unavailable`).
 */
export const BREACH_CHECK_FAILURES = [
  'not_configured',
  'list_not_loaded',
  'lookup_blocked',
  'lookup_failed',
  'bad_response',
  'unavailable',
] as const;
export type BreachCheckFailure = (typeof BREACH_CHECK_FAILURES)[number];

/** What a breach-list check found. */
export type BreachCheckVerdict =
  /** The realm checks no breach list (`password.breachListSource` is `off`): nothing was checked or sent. */
  | { readonly kind: 'off' }
  | { readonly kind: 'not_listed' }
  | { readonly kind: 'listed' }
  /** The check could not be made: never a refusal, and recorded (ADR-020 §3, #635). */
  | { readonly kind: 'failed'; readonly failure: BreachCheckFailure };

/**
 * Where the engine checks a password against the realm's breach list (#635,
 * ADR-020 §3): an operator's local list matched by the password's SHA-1, or a
 * k-anonymity range lookup through the egress client that carries the first
 * five hex characters of that SHA-1 and nothing else of the password. The
 * adapter reads the realm's source and counts the check on its metric.
 */
export interface BreachedPasswordCheck {
  /**
   * Check `password` as the credential hashes it: the presented password as
   * it was verified, or a new one in NFC. A check that cannot be made answers
   * `failed`; a throw is read as `failed` (`unavailable`) too, so no check
   * ever blocks a sign-in.
   */
  check(input: { readonly realmId: string; readonly password: string }): Promise<BreachCheckVerdict>;
}

/** No breach list: every check is `off`. The default, until a deployment passes its own. */
export const NO_BREACH_CHECK: BreachedPasswordCheck = Object.freeze({
  check: async () => Object.freeze({ kind: 'off' as const }),
});

/** What the realm's password policy made of a new password (ADR-017 Decision 8, #634). */
export type NewPasswordCheck =
  /** Accepted: `password` is its NFC form, what is hashed, and `normalization` the marker to store. */
  | {
      readonly kind: 'accepted';
      readonly password: string;
      readonly normalization: PasswordNormalization;
    }
  /** Refused, with every reason found, in the order checked. */
  | { readonly kind: 'rejected'; readonly reasons: readonly PasswordRejectionReason[] };

/** What replacing a password found. */
export type PasswordReplacement =
  /** The new password is stored, and the account's `update_password` required action cleared. */
  | { readonly kind: 'replaced' }
  /**
   * Nothing was written: the account is disabled (`account_disabled`), or
   * the identifier names no password credential of the subject
   * (`subject_mismatch`). The transaction ends.
   */
  | { readonly kind: 'refused'; readonly reason: 'account_disabled' | 'subject_mismatch' };

/**
 * The forced password update (#635; ADR-017 Decisions 4 and 8): the realm's
 * policy for a new password, and the one write that replaces it. Every method
 * that throws refuses the round, with nothing written.
 */
export interface PasswordUpdates {
  /** The realm's `password.minLength`: the `new_password` step's `min_length`. */
  minLength(realmId: string): Promise<number>;
  /**
   * Check a new password against the realm's password policy, with the
   * address `identifier` and the realm's and service's names as context
   * words. No breach list here: the engine checks it through
   * {@link BreachedPasswordCheck}.
   */
  check(input: {
    readonly realmId: string;
    readonly identifier: string;
    readonly password: string;
  }): Promise<NewPasswordCheck>;
  /**
   * Replace the password of the credential `identifier` names, of `userId`
   * in the realm, with an Argon2id hash of `password` (already in NFC) and
   * its normalisation marker; clear the failure ladder's disabled mark and the
   * account's `update_password` required action. In one database transaction,
   * and only while the user is enabled.
   */
  replace(input: {
    readonly realmId: string;
    readonly userId: string;
    readonly identifier: string;
    readonly password: string;
    readonly normalization: PasswordNormalization;
  }): Promise<PasswordReplacement>;
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
  /**
   * The password was right, and the account is unverified while
   * `REQUIRE_VERIFIED_ACCOUNT` is on, in an engine built without email codes.
   */
  'email_not_verified',
  /** A wrong email code (#638): refused and counted, in the transaction and on its ladder. */
  'invalid_code',
  /** An email code answered after its 10 minutes: nothing was compared or counted. */
  'code_expired',
  /** The 5th wrong email code of a transaction: the code is burned, and the transaction ends. */
  'code_burned',
  /** A send cap that answers 429 refused the code's mail (#637): nothing was mailed. */
  'send_capped',
  /** The identifier's ladder is inside a wait: not verified, not counted. */
  'locked_out',
  /** One subject per transaction: another identifier, or another user's proof. */
  'subject_mismatch',
  /** A bot challenge was answered wrongly (PRO-19). */
  'captcha_failed',
  /**
   * The transaction the transport handed back is not one this round may use:
   * malformed, of another realm or client, or starting too far in the future.
   */
  'transaction_invalid',
  /** The transaction is older than `SIGN_IN_TRANSACTION_MAX_AGE_MS`. */
  'transaction_expired',
  /** A limiter refused the round (rule 3; PRO-13). */
  'rate_limited',
  /** The transport's request checks refused the round (rule 4). */
  'request_refused',
  /** The answer is malformed: nothing was verified or counted. */
  'invalid_answer',
  /** The realm's password policy refused a new password (#635): too short, too long, blocklisted or too weak. */
  'password_rejected',
  /** A new password is on the realm's breach list (#635): refused as blocklisted. */
  'password_breached',
  /**
   * A breach-list check could not be made (#635), on a record whose outcome
   * is `unchecked`: the answer was accepted all the same.
   */
  'breach_check_failed',
] as const;
export type SignInAuditReason = (typeof SIGN_IN_AUDIT_REASONS)[number];

/**
 * One audit record of a round: what happened to one step. It never holds a
 * password, a code or the identifier: the person is named by the user id once
 * a factor fixed the transaction's subject, and by the identifier's keyed
 * HMAC before. At most one of the two is set; a step refused before the
 * transaction holds any identifier (a bot challenge, a discoverable passkey)
 * names nobody.
 */
export type SignInAuditRecord = {
  /**
   * `passed`: the step's answer was accepted. `refused`: it was not. `ended`:
   * the transaction ended. `unchecked`: a check the step's answer goes
   * through could not be made, and the answer was accepted without it: a
   * breach-list check that failed (#635), which never blocks a sign-in.
   */
  readonly outcome: 'passed' | 'refused' | 'ended' | 'unchecked';
  readonly step: StepName;
  /** Why it was refused, ended or went unchecked; absent when it passed. */
  readonly reason?: SignInAuditReason;
  /** For `unchecked`: why the breach-list check could not be made. */
  readonly failure?: BreachCheckFailure;
} & (
  | { readonly userId: string; readonly identifierHmac?: undefined }
  | { readonly identifierHmac: string; readonly userId?: undefined }
  | { readonly userId?: undefined; readonly identifierHmac?: undefined }
);

/** Where a round's audit records go: the transport's event writer, in order. A write that fails fails the round. */
export type AuditSink = (record: SignInAuditRecord) => Promise<void>;

/**
 * An email code's keyed HMAC (#638): HMAC-SHA-256 under a server-side key,
 * over the realm, the code's own salt and the code, base64url without padding
 * (43 characters). The transaction holds this and the salt, never the code.
 * A throw is an outage, which refuses the round.
 */
export type EmailCodeDigest = (input: {
  readonly realmId: string;
  readonly salt: string;
  readonly code: string;
}) => Promise<string>;

/** What marking an address verified found. */
export type AddressVerification =
  /** The address is verified now. */
  | { readonly kind: 'verified' }
  /**
   * Nothing was written: the account is disabled (`account_disabled`), or the
   * address names no password credential of the subject (`subject_mismatch`).
   * The transaction ends.
   */
  | { readonly kind: 'refused'; readonly reason: 'account_disabled' | 'subject_mismatch' };

/** Where the engine marks an address verified: its only write to an account. */
export interface AddressVerifier {
  /**
   * Mark `identifier`, the address of the password credential of `userId` in
   * the realm, verified: the credential's `email_verified` and the email
   * attribute's verified flag, in one database transaction, and only while
   * the user is enabled. Idempotent. A throw is an outage, which refuses the
   * round with nothing written.
   */
  markVerified(input: {
    readonly realmId: string;
    readonly userId: string;
    readonly identifier: string;
  }): Promise<AddressVerification>;
}

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
