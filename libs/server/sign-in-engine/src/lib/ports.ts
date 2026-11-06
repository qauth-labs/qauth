import type { StepName, StepParams } from '@qauth-labs/server-step-grammar';
import type { PasswordNormalization, PasswordRejectionReason } from '@qauth-labs/shared-validation';

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
 * A counter of the failure ladder (#615): one per factor, the email codes'
 * (#638, ADR-017 Decision 7: "the same key, a separate counter"), which
 * counts wrong codes and is never a factor, and the recovery codes' (#649),
 * keyed on the account rather than the identifier: only a holder of the
 * first factor reaches one.
 */
export const LADDER_COUNTERS = [...FACTOR_TYPES, 'email_code', 'recovery_code'] as const;
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
  /**
   * The identifier of its password credential, when it holds one: the
   * address a sign-in a discoverable factor proved (a passkey, #651) goes on
   * with, for the steps that name it (an inline address check, a forced
   * password update, an enrolment's user name).
   */
  readonly identifier?: string;
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
  check(input: {
    readonly realmId: string;
    readonly password: string;
  }): Promise<BreachCheckVerdict>;
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
/** What creating an account found (#640). */
export type AccountRegistration =
  /**
   * The account was created: its `users` row, and its verified password
   * credential and its verified address, or its passkey (#655).
   */
  | { readonly kind: 'created'; readonly userId: string }
  /**
   * Nothing was written: another account took the address first, or the
   * realm holds the passkey's credential id already (a unique-constraint
   * race). The transaction ends, as FiPA's `invalid_session` does.
   */
  | { readonly kind: 'conflict' };

/**
 * Registration (#640; ADR-017 Decision 8): the gate and the one write that
 * creates an account. The new password's policy and the breach list are the
 * forced update's ({@link PasswordUpdates}, {@link BreachedPasswordCheck}):
 * one password policy for every new password. Every method that throws
 * refuses the round, with nothing written.
 */
export interface AccountRegistrations {
  /**
   * Whether the realm and the client both allow registration: the realm's
   * sign-up switch, and the client's allowed flows (a redirect-flow
   * client's `hosted_flows`, a native client's `first_party_policy.flows`)
   * listing `register`. Read on every round of a registration.
   */
  allowed(input: { readonly realmId: string; readonly clientId: string }): Promise<boolean>;
  /**
   * Whether a registration of this realm and client must pass a bot
   * challenge before its address is asked for (#643; ADR-017 Decision 7,
   * F1b): the realm's `botChallenge.requiredAtSignUp`, or the client's own
   * requirement. Read on every round of a registration until the transaction
   * passed one. Absent: a registration needs one only where a soft threshold
   * asks for it, as every round does.
   */
  challengeRequired?(input: {
    readonly realmId: string;
    readonly clientId: string;
  }): Promise<boolean>;
  /**
   * Create the account of `identifier`, whose mailbox the transaction proved:
   * in one database transaction, the `users` row, the verified `password`
   * credential holding an Argon2id hash of `password` (already in NFC) with
   * its normalisation marker, and the verified `email` attribute. An address
   * another account holds by then is a `conflict`, with nothing written.
   */
  create(input: {
    readonly realmId: string;
    readonly clientId: string;
    readonly identifier: string;
    readonly password: string;
    readonly normalization: PasswordNormalization;
  }): Promise<AccountRegistration>;
  /**
   * Create an account whose primary identity is a passkey, with no address
   * (#655; ADR-017 Decision 8, question 30), from a registration
   * {@link PasskeyCeremonies.verifyRegistration} verified with no account
   * named: in one database transaction, the `users` row, the `webauthn`
   * credential, and the account's `user.registered` event. No email
   * attribute and no password are written: the registration ceremony
   * proved the account, which is verified from its first moment. A
   * credential id the realm holds by then is a `conflict`, with nothing
   * written. Absent: the engine registers password accounts alone.
   */
  createWithPasskey?(input: {
    readonly realmId: string;
    readonly clientId: string;
    readonly registration: string;
  }): Promise<AccountRegistration>;
}

/** What replacing a password at a reset found (#642). */
export type AccountResetOutcome =
  /**
   * The password is replaced, and everything the old one opened ended. The
   * session epoch the reset advanced the account to comes back: whatever the
   * reset finishes is ended by a later reset of the account.
   */
  | { readonly kind: 'reset'; readonly epoch: number }
  /**
   * Nothing was written: the address's password credential is not the
   * subject's (`subject_mismatch`), or the user is disabled
   * (`account_disabled`). The transaction ends.
   */
  | { readonly kind: 'refused'; readonly reason: 'account_disabled' | 'subject_mismatch' };

/** One reset's write (#642): the account, its address and the new password. */
export interface AccountReset {
  readonly realmId: string;
  readonly clientId: string;
  /** The account the reset's mailbox proof fixed. */
  readonly userId: string;
  /** The address the reset proved, normalised: the password credential's `external_sub`. */
  readonly identifier: string;
  /** The new password, in the stored form the password policy's check returned. */
  readonly password: string;
  readonly normalization: PasswordNormalization;
}

/**
 * The owner's password reset (#642; ADR-017 Decision 8, ADR-019 Decision 3):
 * its gate and the write that replaces the password. The new password's
 * policy and the breach list are the forced update's ({@link PasswordUpdates},
 * {@link BreachedPasswordCheck}): one password policy for every new password.
 * Every method that throws refuses the round.
 */
export interface AccountResets {
  /**
   * Whether the client may run the reset flow: on the Interaction API, a
   * usable client (the hosted pages offer it to every one); at the FiPA
   * endpoint, a `first_party_policy.flows` that lists `reset`. Read on every
   * round of a reset, and before the password step offers one.
   */
  allowed(input: { readonly realmId: string; readonly clientId: string }): Promise<boolean>;
  /**
   * Replace the password of `userId`, whose mailbox (and every other
   * authenticator it holds) the transaction proved. In one database
   * transaction: the `password` credential's hash and normalisation marker,
   * its address marked verified, its disabled mark cleared (never a second
   * factor's), the `update_password` required action removed, every refresh
   * family of the user revoked, and the user's session epoch advanced. Once
   * that commits: the user's browser sessions end, the password's failure
   * counters clear, and the "password changed" notice goes out, once. A
   * failure after the commit is logged and changes nothing: the epoch
   * already refuses every older session.
   */
  reset(input: AccountReset): Promise<AccountResetOutcome>;
}

/**
 * The accounts' session epochs (#642; ADR-017 Decision 8, ADR-019 Decision
 * 3): when each account's password was last reset. A sign-in transaction
 * that began at or before that time ends at its next round, as a browser
 * session created before it is absent: a reset ends whatever the old
 * password opened.
 */
export interface SessionEpochReader {
  /**
   * The time, in epoch milliseconds, at or before which a transaction of the
   * account no longer counts: when its password was last reset, with the
   * transport's allowance for clock skew. `null` when it never was. A throw
   * refuses the round.
   */
  notBefore(input: { readonly realmId: string; readonly userId: string }): Promise<number | null>;
}

/** One account of a realm, as the recovery-code port names it. */
export interface RecoveryCodeAccount {
  readonly realmId: string;
  readonly userId: string;
}

/** What the account holds of recovery codes (#649). */
export interface RecoveryCodeStatus {
  /** Whether the account holds a set, used up or not. */
  readonly issued: boolean;
  /** How many codes of the set are still unused: 0 to 10. */
  readonly unused: number;
  /**
   * Whether the person confirmed they saved the set: `false` while the
   * account holds none. A set nobody confirmed is owed again.
   */
  readonly confirmed: boolean;
}

/** A new set of recovery codes (#649). */
export interface RecoveryCodeSet {
  /** The codes in their shown form: returned once and kept nowhere by the port. */
  readonly codes: readonly string[];
  /** The set's id, which only this set holds: what {@link RecoveryCodes.confirm} names. */
  readonly setId: string;
}

/** What a recovery code answered at sign-in did (#649). */
export type RecoveryCodeRedemption =
  /** An unused code of the account's set: it is used now, and the user is told. */
  | { readonly kind: 'redeemed' }
  /** No unused code of the set: a wrong code, a used one, or one another round took first. */
  | { readonly kind: 'refused' };

/**
 * The accounts' recovery codes (#649; ADR-017 Decision 8, ADR-018 §3). A set
 * is 10 codes of 80 bits from a CSPRNG, stored only as salted hashes from the
 * password hasher and used once each (`createRecoveryCodeService` holds those
 * rules over a store). On the hosted pages a code stands in for the factor
 * rule 8 asks for after the first factor; it adds no `amr` value and never
 * `mfa`. A throw refuses the round, as a store outage does.
 */
export interface RecoveryCodes {
  /** What the account holds. */
  status(input: RecoveryCodeAccount): Promise<RecoveryCodeStatus>;
  /**
   * Replace the account's set, if any, with a new one, and return its codes
   * in their shown form and its id. The codes are returned once and never
   * kept: the engine hands them to the round's answer alone. `null` when the
   * account holds a set the person confirmed by now (another sign-in showed
   * it): that set stays, and nothing is written.
   */
  issue(input: RecoveryCodeAccount): Promise<RecoveryCodeSet | null>;
  /**
   * Take `code`, as the person typed it, if it is an unused code of the
   * account's set: it is marked used in the write that takes it, so it works
   * once, and the "a recovery code was used" notice goes out. The check costs
   * the same however many codes are left.
   */
  redeem(
    input: RecoveryCodeAccount & { readonly clientId: string; readonly code: string }
  ): Promise<RecoveryCodeRedemption>;
  /**
   * A wrong code counted at or past the recovery-code ladder's hard ceiling,
   * 100 in a row (ADR-017 Decision 7): tell the user, at most once a day, and
   * the operator. A failure here is reported and changes no answer.
   */
  ceilingReached(input: RecoveryCodeAccount): Promise<void>;
  /**
   * Mark the set `setId` confirmed: the person said they saved it. Until
   * then the set counts as never seen, and the next sign-in that owes one
   * shows a new set in its place. `false` when another set replaced it
   * meanwhile (another sign-in, a regeneration): the codes the person saved
   * no longer work, and nothing is confirmed.
   */
  confirm(input: RecoveryCodeAccount & { readonly setId: string }): Promise<boolean>;
  /**
   * The account `code`, as the person typed it, is an unused code of, when
   * that account's set can be found by the code alone (#655): only the
   * sets of accounts whose primary identity is a passkey, with no address,
   * carry what finds them. `null` for any other code, the same whatever it
   * is. It takes nothing: {@link redeem} checks and takes the code after the
   * engine read the account. The work costs the same for any answer.
   * Absent: no code is redeemed before a first factor.
   */
  findAccount?(input: {
    readonly realmId: string;
    readonly code: string;
  }): Promise<{ readonly userId: string } | null>;
}

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

/**
 * One upstream identity provider as the `upstream` step lists it (#639): its
 * AuthMethod type (`oidc_corp`), which the answer names; the name its button
 * shows, as the operator set it; and an icon URL, when one is set.
 */
export interface UpstreamProviderEntry {
  readonly provider: string;
  readonly name: string;
  readonly icon?: string;
}

/**
 * Where the engine reads the upstream identity providers a realm offers on
 * its first step (#639): the enabled ones an operator has not hidden, in the
 * order the screen shows them. Read on every round that offers the step,
 * never kept, and never for an account: the list is the same for everyone. A
 * throw is an outage, which refuses the round.
 */
export interface UpstreamProviderDirectory {
  offered(input: {
    readonly realmId: string;
    readonly clientId: string;
  }): Promise<readonly UpstreamProviderEntry[]>;
}

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
  /**
   * The upstream provider the person picked could not be started (#639): its
   * discovery document cannot be read, for instance. The step is offered
   * again with `provider_unavailable`.
   */
  'provider_unavailable',
  /**
   * The realm or the client does not allow registration (#640): the round
   * of a registration was refused, with nothing mailed or written.
   */
  'registration_closed',
  /**
   * Another account took the address while the registration set its password
   * (#640): nothing was created, and the transaction ends.
   */
  'registration_conflict',
  /**
   * The client may not run the reset flow (#642): the round of a reset was
   * refused, with nothing mailed or written.
   */
  'reset_closed',
  /**
   * The account's password was reset after the transaction began (#642): the
   * transaction ends, as every browser session created before the reset
   * does.
   */
  'reset_since',
  /**
   * The account's address was never proved: it is unclaimed (ADR-017
   * Decision 8), and someone other than the mailbox owner may have created
   * it. A reset would keep its `sub`, so its right code is answered as a
   * wrong one and nothing changes, until #641 ends such an account at this
   * proof and gives the mailbox owner a new one.
   */
  'account_unclaimed',
  /**
   * A binding needs a factor proved at most 5 minutes ago (ADR-017
   * Decision 8), and the transaction's is older (#653): nothing is bound,
   * and the transaction ends, so a fresh sign-in starts again.
   */
  'authentication_stale',
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
   *
   * With `upstream`, `identifier` is the address an upstream provider gave an
   * account it created and whose verified switch is off (#639): the provider's
   * credential of `userId` and its `email` attribute with that address are
   * marked verified instead.
   */
  markVerified(input: {
    readonly realmId: string;
    readonly userId: string;
    readonly identifier: string;
    /** The upstream provider's type, for an account an upstream provider created (#639). */
    readonly upstream?: string;
  }): Promise<AddressVerification>;
}

/**
 * What an assertion of the `webauthn_get` step proved (#651): the account the
 * passkey belongs to, and whether the authenticator data it signed carries
 * the user-verification (UV) flag. `refused` for anything else: no ceremony
 * held under the key or one taken already, an unknown or disabled passkey,
 * another challenge, RP ID or origin, a bad signature, a malformed response.
 * The engine refuses every one alike, as `invalid_credentials`.
 */
export type PasskeyAssertion =
  | { readonly kind: 'verified'; readonly userId: string; readonly userVerified: boolean }
  | { readonly kind: 'refused' };

/**
 * The creation options of a `webauthn_create` step (#651) and its personal
 * data, as the step grammar holds them: a new user handle, the account's
 * identifier as its name, and the account's passkeys to exclude.
 */
export interface PasskeyRegistrationStart {
  readonly options: StepParams<'webauthn_create'>['options'];
  readonly personal: Readonly<Record<string, unknown>>;
}

/**
 * What a `webauthn_create` answer made (#651): a new passkey, verified with
 * user verification and not bound yet, as an opaque string the engine holds
 * in the transaction until it binds it (at most
 * {@link PASSKEY_REGISTRATION_MAX_LENGTH} characters); or `refused`, for
 * anything else.
 */
export type PasskeyRegistration =
  | { readonly kind: 'verified'; readonly registration: string }
  | { readonly kind: 'refused' };

/** The longest held registration the engine keeps in a transaction: a passkey's public key and data. */
export const PASSKEY_REGISTRATION_MAX_LENGTH = 16384;

/** What binding a verified passkey to an account found (#651). */
export type PasskeyBinding =
  /**
   * The passkey is bound and the binding notice is queued. The security log's
   * own event of it comes with the account pages (#686).
   */
  | { readonly kind: 'bound' }
  /**
   * Nothing was bound: the realm holds the credential id already
   * (`credential_exists`, the step is offered again), or the account is
   * disabled or gone (`account_disabled`, `subject_mismatch`: the transaction
   * ends).
   */
  | {
      readonly kind: 'refused';
      readonly reason: 'credential_exists' | 'account_disabled' | 'subject_mismatch';
    };

/**
 * The WebAuthn ceremonies of the passkey steps (#651; ADR-017 Decisions 4, 8
 * and 14): the realm's relying party, the challenge store and the realm's
 * passkeys, behind one port. Each ceremony is named by a key the engine draws
 * and holds in the transaction, so an answer is checked only against the
 * ceremony its transaction started; the store keeps a ceremony at least 5
 * minutes. Every verification takes the ceremony first, so a challenge is
 * answered once, right or wrong. A throw is an outage, which refuses the
 * round.
 */
export interface PasskeyCeremonies {
  /**
   * Start an assertion ceremony under `key`: the request options of the
   * `webauthn_get` step, for the realm's RP ID, with user verification
   * required and no `allowCredentials`, so they name no account.
   */
  startAssertion(input: {
    readonly realmId: string;
    readonly clientId: string;
    readonly key: string;
  }): Promise<StepParams<'webauthn_get'>>;
  /**
   * Take the ceremony under `key` and verify `response`, the browser's
   * `PublicKeyCredential.toJSON()` as a JSON string, against the realm's
   * passkeys: a disabled one never verifies. A verified one has its sign
   * counter and last use updated.
   */
  verifyAssertion(input: {
    readonly realmId: string;
    readonly clientId: string;
    readonly key: string;
    readonly response: string;
  }): Promise<PasskeyAssertion>;
  /**
   * Start a registration ceremony under `key`, for a discoverable passkey of
   * `userId` with user verification required and attestation `none`, named
   * by `identifier`. With no `userId`, the ceremony is a registration's
   * (#655): a new user handle, nothing excluded. With no `identifier` (an
   * account with no address), the port makes the account's name.
   */
  startRegistration(input: {
    readonly realmId: string;
    readonly clientId: string;
    readonly key: string;
    readonly userId?: string;
    readonly identifier?: string;
  }): Promise<PasskeyRegistrationStart>;
  /**
   * Take the ceremony under `key` and verify the registration `response`,
   * without binding it. `userId` is the account the ceremony was started
   * for; none for a registration's (#655).
   */
  verifyRegistration(input: {
    readonly realmId: string;
    readonly clientId: string;
    readonly key: string;
    readonly userId?: string;
    readonly response: string;
  }): Promise<PasskeyRegistration>;
  /**
   * Bind a registration {@link verifyRegistration} verified to `userId`, while
   * the account is enabled, then queue the binding notice of NIST SP 800-63B-4
   * §4.1.2.1. A notice that fails is reported and binds the passkey all the
   * same. The engine records the binding as the `webauthn_create` step passed;
   * the security log's own event comes with its account pages (#686).
   */
  bind(input: {
    readonly realmId: string;
    readonly clientId: string;
    readonly userId: string;
    readonly registration: string;
  }): Promise<PasskeyBinding>;
}

/** One account of a realm, as the TOTP port names it (#653). */
export interface TotpAccount {
  readonly realmId: string;
  readonly userId: string;
}

/** What a code answered to the account's bound TOTP did (#653). */
export type TotpVerification =
  /** A code of a later time step than the last one accepted: that step is taken now. */
  | { readonly kind: 'accepted' }
  /**
   * Anything else: a wrong code, a step accepted already or an earlier one, a
   * step another round took first, a disabled TOTP or none. The engine
   * refuses every one alike, as `invalid_credentials`.
   */
  | { readonly kind: 'refused' };

/** How the set-up step shows a secret: its personal data, for this round's answer alone. */
export interface TotpDisplay {
  /** The secret, 160 bits as 32 characters of unpadded uppercase base32 (RFC 4648 §6). */
  readonly secret: string;
  /** The same secret as an `otpauth://totp/` URI, for the page's QR code. */
  readonly otpauthUri: string;
}

/** A new secret for the set-up step (#653). */
export interface TotpEnrolmentStart {
  /**
   * The secret as a `data_at_rest` ciphertext of the realm (ADR-019
   * Decision 9): what the transaction holds until it binds it, at most
   * {@link TOTP_SEALED_MAX_LENGTH} characters. The transaction never holds
   * the secret in clear.
   */
  readonly sealed: string;
  readonly display: TotpDisplay;
}

/** What a first code answered to the set-up step is to its new secret (#653). */
export type TotpSetupCheck =
  /** Valid for `step`, which becomes the bound TOTP's last accepted step. */
  { readonly kind: 'valid'; readonly step: number } | { readonly kind: 'refused' };

/** What binding a new secret to an account found (#653). */
export type TotpBinding =
  /** The secret is the account's TOTP now, replacing a disabled one, and the notice is queued. */
  | { readonly kind: 'bound' }
  /**
   * Nothing was bound: the account is disabled or gone (`account_disabled`,
   * `subject_mismatch`), or its address was never proved
   * (`account_unclaimed`, ADR-017 Decision 8). The transaction ends.
   */
  | {
      readonly kind: 'refused';
      readonly reason: 'account_disabled' | 'subject_mismatch' | 'account_unclaimed';
    };

/** The longest ciphertext of a new secret the engine keeps in a transaction. */
export const TOTP_SEALED_MAX_LENGTH = 1024;

/**
 * The accounts' TOTPs (#653; ADR-017 Decisions 7 and 8, ADR-020 §3): the
 * fixed parameters of `createTotpService`, a secret stored only as a
 * `data_at_rest` ciphertext, and the last time step each TOTP accepted. The
 * engine never sees a secret but the set-up step's display; it holds a new
 * one only as its ciphertext. A throw is an outage, which refuses the round.
 */
export interface TotpCredentials {
  /**
   * Check `code` against the account's TOTP: one step of tolerance either
   * way, and a later step than the last one accepted, which is taken in the
   * write that accepts it, so a code works once.
   */
  verify(
    input: TotpAccount & { readonly clientId: string; readonly code: string }
  ): Promise<TotpVerification>;
  /** Draw a new secret for the set-up step, sealed at once, with how it is shown. */
  start(input: TotpAccount & { readonly identifier: string }): Promise<TotpEnrolmentStart>;
  /** Show a secret {@link start} sealed again, for a round that offers the step again. */
  display(
    input: TotpAccount & { readonly identifier: string; readonly sealed: string }
  ): Promise<TotpDisplay>;
  /** Check a first code against a sealed secret, without binding it. */
  check(
    input: TotpAccount & { readonly sealed: string; readonly code: string }
  ): Promise<TotpSetupCheck>;
  /**
   * Bind a sealed secret to the account, with `step` as its last accepted
   * step, replacing the TOTP it holds, then queue the "TOTP added" notice; a
   * notice that fails is reported and binds the secret all the same. The
   * account's TOTP counter ends with the old secret.
   */
  bind(
    input: TotpAccount & {
      readonly clientId: string;
      readonly sealed: string;
      readonly step: number;
    }
  ): Promise<TotpBinding>;
  /**
   * A wrong code counted at or past the TOTP ladder's hard ceiling, 100 in a
   * row (ADR-017 Decision 7): disable the TOTP and tell the user, only while
   * the hard action is armed (the hosted pages are on, and the account keeps
   * an unused recovery code or another usable factor beyond the password).
   * Idempotent. A failure here is reported and changes no answer.
   */
  ceilingReached(input: TotpAccount): Promise<void>;
  /**
   * A wrong code after a correct password in the same transaction: tell the
   * user, at most once per 24 hours per account. No realm can switch this
   * notice off (ADR-020 "Emails"). A failure here is reported and changes no
   * answer.
   */
  failedAfterPassword(input: TotpAccount & { readonly clientId: string }): Promise<void>;
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
