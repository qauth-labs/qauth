import {
  createInteractionMapper,
  grammarStep,
  isStepName,
  type OfferedStep,
  type ReadAnswer,
  STEP_NAMES,
  STEP_URNS,
  type StepAnswer,
  StepAnswerError,
  type StepErrorCode,
  type StepName,
  stepNameOfUrn,
  type StepOffer,
  type StepParams,
  transactionAmr,
} from '@qauth-labs/server-step-grammar';
import {
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH_FLOOR,
  PASSWORD_NORMALIZATION_NFC,
  PASSWORD_REJECTION_REASONS,
  type PasswordNormalization,
  type PasswordRejectionReason,
} from '@qauth-labs/shared-validation';

import { checkedChallengeParams } from './bot-challenge';
import {
  answerEmailCode,
  countWrongEmailCode,
  EMAIL_CODE_HMAC_PATTERN,
  EMAIL_CODE_TTL_MS,
  emailCodeExpired,
  type EmailCodeLength,
  emailCodeLength,
  emailCodeParams,
  type EmailCodePurpose,
  emailCodeResendDue,
  generateEmailCode,
  generateEmailCodeSalt,
  type HeldEmailCode,
  heldEmailCode,
} from './email-code';
import {
  factorStrength,
  FIRST_FACTOR_STRENGTH,
  provenFactorStrength,
  provesMfa,
  secondFactorRequired,
  strongestBoundFactor,
} from './factors';
import {
  type CredentialRoundReservation,
  type HookRound,
  type LadderReservation,
  NO_LADDER,
  type SignInHooks,
} from './hooks';
import { readIdentifier } from './identifier';
import {
  type AccountDirectory,
  type AccountRegistrations,
  type AccountResets,
  type AddressVerifier,
  type BreachCheckFailure,
  type BreachCheckVerdict,
  type BreachedPasswordCheck,
  type Clock,
  type EmailCodeDigest,
  type IdentifierDigest,
  MFA_MODES,
  type MfaPolicy,
  type MfaPolicyReader,
  NO_HARD_ACTION,
  type PasswordHardAction,
  type PasswordUpdates,
  type PasswordVerifier,
  type SessionEpochReader,
  type SignInAccount,
  type SignInAuditReason,
  type SignInAuditRecord,
  type SignInCandidate,
  SYSTEM_CLOCK,
  type UpstreamProviderDirectory,
  type UpstreamProviderEntry,
} from './ports';
import type {
  RegistrationMail,
  ResetMail,
  RoundAnswer,
  RoundContext,
  RoundResult,
  UpstreamProof,
} from './round';
import { isCredentialAnswer, roundEnvironmentOf } from './round-limits';
import type {
  AnyStepHandler,
  ProvedAccount,
  StepHandler,
  StepRound,
  StepVerdict,
} from './steps/handler';
import { createIdentifierStep } from './steps/identifier';
import { checkBreachList, createPasswordStep } from './steps/password';
import { fromStore, SignInStoreUnavailableError } from './store';
import {
  freezeTransaction,
  newSignInTransaction,
  readSignInTransaction,
  SIGN_IN_TRANSACTION_CLOCK_SKEW_MS,
  SIGN_IN_TRANSACTION_MAX_AGE_MS,
  type SignInTransaction,
} from './transaction';

/**
 * THE SIGN-IN ENGINE (PRO-09, #614; ADR-017 Decisions 4 and 7, ADR-019
 * Decision 6): one engine decides every step of a sign-in, whatever the
 * transport. The Interaction API (browser ceremonies) and the FiPA
 * authorization challenge endpoint (native apps) each call
 * {@link SignInEngine.advance} once per round, and map its answer onto their
 * wire with the step grammar's mappers. The flow is graphed in
 * `graphs/flows/core/sign-in/flow.yaml`.
 *
 * Each round runs the rules of ADR-017 Decision 4 in order; the first unmet
 * one produces the answer. The transport's own checks (rule 1) and client
 * authentication (rule 2) come before the call.
 *
 * 3. The MFA policy is read (a policy that cannot be read refuses the round),
 *    then the limiters' hook (#636): a round from an end-user IP inside its
 *    hard block, or above the client's rounds a minute, is refused. Every
 *    credential round (a password, an `otp`, a recovery code, a WebAuthn
 *    response) is reserved on the same hook before its credential is
 *    verified, and before the account's ladder: inside a delay or past a
 *    hard limit it is refused, neither verified nor counted.
 * 4. The transport's request checks' hook.
 * 5. The bot challenge (#643): due while a soft threshold of the limiters
 *    (rule 3) or of the ladder (the round's identifier past its free
 *    failures) holds, while a registration the realm or the client requires
 *    one for has not passed one, or when the `botChallenge` hook says so. A
 *    transport that serves the `captcha` step gets it before every other
 *    step, once per credential round; the pending step resumes after it. One
 *    that does not (a FiPA client that did not list it) meets the delay and
 *    the hard 429 of rules 3 and 7 alone, never a redirect. With no provider
 *    the round is refused, never passed.
 * 6. The identifier: the request's `login_hint`, else an answer's. The first
 *    one is fixed; a different one ends the transaction (`subject_mismatch`).
 *    With none, the identifier step, or a discoverable first factor before it
 *    once #651 adds one, and the realm's upstream identity providers beside
 *    them (#639): a pick sends the browser to the provider, whose callback
 *    proves the account it holds ({@link SignInEngine.completeUpstream}). An
 *    upstream sign-in ranks with the password in rule 8's downgrade rule.
 * 7. The first factor, offered alike to every account: the password here, and
 *    from #651 a passkey beside it. Its answer is reserved on the ladder's hook
 *    before it is verified.
 * 8. After a first factor: the downgrade rule (the account's strongest bound
 *    factor, a disabled one included), then the MFA policy just read, then,
 *    with `emailCodes`, the inline verification of an address not proved yet
 *    (#638): an emailed code, never a factor, whatever
 *    `REQUIRE_VERIFIED_ACCOUNT` says, before the second factor the policy
 *    asks for. An account that lacks the second factor the policy requires
 *    gets the set-up step first, never a code. Then the forced password
 *    update (#635): a password on the realm's breach list, or an
 *    `update_password` required action, asks for a new password before the
 *    sign-in completes, after a factor beyond the password (the account's
 *    second factor or passkey) or, on an account whose only factor is its
 *    password, a code mailed to its address.
 * 9. Complete: the transport mints the session or the code.
 *
 * A registration (#640; `RoundContext.flow` `register`, from `prompt=create`)
 * runs the same rules with its own gate after rule 4: the realm and the
 * client must both allow it, on every round. Rule 6 asks for the address
 * alone; then its mailbox is proved with an 8-digit code, the same step for a
 * new address and an existing one, and a new address sets its password and
 * the account is created (ADR-017 Decision 8). An account that holds the
 * address is helped to sign in to it: rule 7 on. The flow is graphed in
 * `graphs/flows/core/sign-up/flow.yaml`.
 *
 * A password reset (#642; ADR-017 Decision 8) starts from rule 7's password
 * step, which offers `password_reset` beside the password while the client
 * may reset and the request asks for no fresh sign-in, or at round 0 for a
 * transport that starts one (`RoundContext.flow` `reset`). Its own gate runs
 * after rule 4 on every round. The mailbox comes first, with an 8-digit
 * `recovery` code, the same step for every address, mailed only to an enabled
 * account with a password; then any other authenticator the account holds,
 * never an email code in its place; then the new password, and the write that
 * replaces it and ends what the old one opened. It completes with no `amr` and
 * no `auth_time`. A transaction that began before its account's last reset
 * ends at its next round (the session epoch). The flow is graphed in
 * `graphs/flows/core/password-reset/flow.yaml`.
 *
 * Until a factor succeeds, nothing the engine answers depends on the account:
 * an unknown identifier, a password-only, passkey-only, disabled or locked
 * account and an unverified one under `REQUIRE_VERIFIED_ACCOUNT` get the same
 * offer, in body and in timing. Every round answers no earlier than
 * {@link SIGN_IN_MIN_RESPONSE_TIME_MS} after it arrived.
 *
 * An answer is verified only when its step is the one the engine asks for
 * next (an eager answer); any other is ignored, with no verification and no
 * failure counted.
 */

/** Every round answers no earlier than this after it arrived: `MIN_RESPONSE_TIME_MS.LOGIN` (ADR-017 Decision 7). */
export const SIGN_IN_MIN_RESPONSE_TIME_MS = 500;

/**
 * What the inline verification of an account's address needs (#638, ADR-017
 * Decisions 5 and 8). The round's capped sender comes with each round
 * (`RoundContext.sendCode`), bound to its request; the email-code ladder is
 * the `ladder` hook's `email_code` counter.
 */
export interface EmailCodeDependencies {
  /** The code's keyed HMAC: what the transaction holds in the code's place. */
  readonly digest: EmailCodeDigest;
  /** Marks the address verified once its code is answered right: the engine's one write to an account. */
  readonly addresses: AddressVerifier;
}

/** What the engine is built from. */
export interface SignInEngineDependencies {
  readonly accounts: AccountDirectory;
  readonly passwords: PasswordVerifier;
  /** The realm's and the client's MFA policy, read on every round. */
  readonly policy: MfaPolicyReader;
  readonly identifierDigest: IdentifierDigest;
  /**
   * `REQUIRE_VERIFIED_ACCOUNT`, as the deployment set it. It decides only for
   * an engine built without `emailCodes`: with them, an unverified account is
   * verified inline after its correct password whatever it says (ADR-017
   * Decision 8).
   */
  readonly requireVerifiedAccount: boolean;
  /**
   * The email codes of the inline verification (#638). With them, a correct
   * password proves an account whose address is not verified yet, and rule 8
   * mails it a code before the sign-in completes. Without them, an unverified
   * account is refused like a wrong password while `requireVerifiedAccount`
   * is on, and signs in while it is off.
   */
  readonly emailCodes?: EmailCodeDependencies;
  /**
   * The realm's breach list (#635, ADR-020 §3): a right password is checked
   * against it, and a listed one asks for a new password before the sign-in
   * completes; a new password is checked against it too. A check that fails
   * never blocks a sign-in: it is recorded as an `unchecked` audit record.
   * Without it nothing is checked.
   */
  readonly breachCheck?: BreachedPasswordCheck;
  /**
   * The forced password update (#635): the realm's policy for a new password
   * and the write that replaces it. Without it, a sign-in that owes a new
   * password (a listed one, or an `update_password` required action) is
   * answered with a redirect, never completed.
   */
  readonly passwordUpdates?: PasswordUpdates;
  /**
   * Registration (#640; ADR-017 Decision 8): its gate and the write that
   * creates an account. A registration also needs `emailCodes` and
   * `passwordUpdates`, whose policy sets the new password. Without all
   * three, a registration is answered with a redirect.
   */
  readonly registrations?: AccountRegistrations;
  /**
   * The owner's password reset (#642; ADR-017 Decision 8): its gate and the
   * write that replaces the password. A reset also needs `emailCodes` and
   * `passwordUpdates`, whose policy sets the new password. Without all three
   * the password step offers no reset, and a reset is answered with a
   * redirect.
   */
  readonly resets?: AccountResets;
  /**
   * The accounts' session epochs (#642): a transaction that proved an account
   * and began before that account's last reset ends at its next round.
   * Without it no transaction is checked.
   */
  readonly sessionEpochs?: SessionEpochReader;
  readonly hooks?: SignInHooks;
  /**
   * The password ladder's hard action (#615): called when a failure counts at
   * the ladder's hard ceiling, and when a password proves an account whose
   * ignored disabled mark must be cleared. None by default; the plugin of
   * `@qauth-labs/fastify-plugin-sign-in-engine` refuses a production engine
   * without one.
   */
  readonly passwordHardAction?: PasswordHardAction;
  /**
   * The steps later issues add (passkeys, TOTP, the bot challenge), in the
   * order they are preferred. The identifier and password steps are the
   * engine's own.
   */
  readonly steps?: readonly AnyStepHandler[];
  /**
   * The realm's upstream identity providers (#639): offered as the `upstream`
   * step beside the identifier step, while nobody is named, on a round whose
   * transport can start one (`RoundContext.startUpstream`). Without it the
   * step is never offered.
   */
  readonly upstream?: UpstreamProviderDirectory;
  readonly clock?: Clock;
  /**
   * Told when a store refused a round, or when settling a ladder reservation
   * failed (which changes no answer), for the transport's log.
   */
  readonly onUnavailable?: (error: SignInStoreUnavailableError) => void;
}

/** The engine. */
export interface SignInEngine {
  /**
   * Run one round of a sign-in: `transaction` is what the last round
   * returned (`null` for round 0), `answer` the round's answer, if any.
   * The returned transaction is the one to keep. A completed sign-in, a
   * redirect and a refusal that ends the transaction return `null` in its
   * place. A failed audit write rejects.
   *
   * The transaction is not sealed, so the engine trusts what it says once it
   * is well formed, of `context`'s realm and client, and young enough: the
   * transport must keep it server-side under an unguessable handle bound to
   * the realm and the client, and never take one back from the client.
   */
  advance(
    transaction: SignInTransaction | null,
    answer: RoundAnswer | null,
    context: RoundContext
  ): Promise<RoundResult>;
  /**
   * Run the round of an upstream provider's callback (#639): `proof` names
   * the account that holds the provider's identity. It proves the `upstream`
   * step, which ranks with the password, and the rules go on from rule 8 as
   * after any first factor: the account's passkey when it holds one, the MFA
   * policy, the inline verification of an address the provider did not
   * vouch for. The transaction must be the one that sent the person to that
   * provider, with nobody named since; any other, and a disabled account,
   * is refused as `invalid_answer`, audited, with the transaction as it was.
   */
  completeUpstream(
    transaction: SignInTransaction | null,
    proof: UpstreamProof,
    context: RoundContext
  ): Promise<RoundResult>;
}

/**
 * The steps whose answer may carry the identifier: the identifier step, and
 * the password step for a page that asks for both at once. An answer to any
 * other step the engine did not ask for is ignored, its `login_hint` too.
 */
const STEPS_WITH_LOGIN_HINT: ReadonlySet<StepName> = new Set<StepName>(['identifier', 'password']);

/**
 * The ladder counters whose soft threshold asks for a bot challenge (#643;
 * ADR-017 Decision 7, "bot challenge from F1b"): the password's and the email
 * codes'. A second factor's counter joins with its step (#653).
 */
const CHALLENGE_LADDER_COUNTERS = Object.freeze(['password', 'email_code'] as const);

/** An identifier HMAC: HMAC-SHA-256, base64url without padding. */
const IDENTIFIER_HMAC_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const TRANSACTION_ENDED: RoundResult = Object.freeze({
  kind: 'refused' as const,
  reason: 'transaction_ended' as const,
  transaction: null,
});

/**
 * The steps no role may take: an email code is never an authenticator
 * (ADR-017 Decision 5), and a new password proves nothing; both are the
 * engine's own.
 */
const NEVER_A_FACTOR: readonly StepName[] = Object.freeze(['email_code', 'new_password']);

/**
 * An email code that verifies an account after its password: 6 digits
 * (ADR-017 Decision 5). The Interaction API never offers `confirm_sign_in`,
 * the FiPA endpoint's per-client check (PRO-22), and this engine offers it to
 * no transport yet.
 */
const VERIFY_ACCOUNT = 'verify_account' as const;

/**
 * An email code that proves the mailbox of an account whose only factor is
 * its password, before a forced password update (#635): the purpose and the 8
 * digits of a reset's code, as ADR-017 Decision 4 rule 8 asks ("as a reset
 * does", decided 2026-10-23).
 */
const RECOVERY = 'recovery' as const;

/** The email-code purposes of a sign-in: verifying an address, and proving a mailbox before a forced update. */
type SignInCodePurpose = typeof VERIFY_ACCOUNT | typeof RECOVERY;

/** The steps a registration needs the transport to serve (#640). */
const REGISTRATION_STEPS: readonly StepName[] = Object.freeze([
  'identifier',
  'email_code',
  'new_password',
]);

/**
 * The code of the refusal of a registration the realm or the client does not
 * allow (#640): `RoundResult` `request_refused`.
 */
export const REGISTRATION_NOT_ALLOWED = 'registration_not_allowed';

/** The steps a reset needs the transport to serve (#642). */
const RESET_STEPS: readonly StepName[] = Object.freeze([
  'password_reset',
  'email_code',
  'new_password',
]);

/** The step whose answer may carry a reset's address (#642): its start. */
const RESET_STEPS_WITH_LOGIN_HINT: ReadonlySet<StepName> = new Set<StepName>(['password_reset']);

/**
 * The code of the refusal of a reset the client may not run (#642):
 * `RoundResult` `request_refused`.
 */
export const RESET_NOT_ALLOWED = 'reset_not_allowed';

/** Check the handlers a deployment adds, and order every handler by role. */
function buildHandlers(deps: SignInEngineDependencies) {
  const identifier = createIdentifierStep();
  const password = createPasswordStep({
    accounts: deps.accounts,
    passwords: deps.passwords,
    ladder: deps.hooks?.ladder ?? NO_LADDER,
    hardAction: deps.passwordHardAction ?? NO_HARD_ACTION,
    // With email codes, an unverified account's right password proves it,
    // and rule 8 verifies its address (#638, ADR-017 Decision 8).
    requireVerifiedAccount: deps.requireVerifiedAccount && deps.emailCodes === undefined,
    ...(deps.onUnavailable === undefined ? {} : { onSettleFailure: deps.onUnavailable }),
    ...(deps.breachCheck === undefined ? {} : { breachCheck: deps.breachCheck }),
  });
  const extra = deps.steps ?? [];
  const byStep = new Map<StepName, AnyStepHandler>([
    ['identifier', identifier],
    ['password', password],
  ]);
  for (const handler of extra) {
    if (!isStepName(handler.step)) throw new Error(`sign-in engine: unknown step ${handler.step}`);
    if (byStep.has(handler.step)) {
      throw new Error(`sign-in engine: step ${handler.step} has a handler already`);
    }
    if (NEVER_A_FACTOR.includes(handler.step)) {
      throw new Error(`sign-in engine: ${handler.step} is never a sign-in step`);
    }
    if ((handler.role === 'challenge') !== (handler.step === 'captcha')) {
      throw new Error('sign-in engine: the bot challenge is the captcha step, and only it');
    }
    if (handler.role === 'identifier') {
      throw new Error('sign-in engine: the identifier step is the engine’s own');
    }
    if (
      (handler.role === 'first_factor' || handler.role === 'second_factor') &&
      handler.factor === undefined
    ) {
      throw new Error(`sign-in engine: factor step ${handler.step} names no factor`);
    }
    if (
      handler.role === 'first_factor' &&
      handler.factor !== undefined &&
      FIRST_FACTOR_STRENGTH[handler.factor] === undefined
    ) {
      throw new Error(`sign-in engine: ${handler.factor} is not a first factor`);
    }
    if (handler.discoverable === true && handler.role !== 'first_factor') {
      throw new Error(`sign-in engine: only a first factor is discoverable (${handler.step})`);
    }
    // A one-time code proves possession of a device, never who the person is:
    // alone it would complete a sign-in wherever no MFA policy applies.
    if (handler.step === 'totp' && handler.role !== 'second_factor') {
      throw new Error('sign-in engine: totp is only a second factor');
    }
    byStep.set(handler.step, handler);
  }
  const ofRole = (role: AnyStepHandler['role']) => extra.filter((handler) => handler.role === role);
  const firstFactors = [...ofRole('first_factor'), password];
  return Object.freeze({
    byStep,
    identifier,
    challenge: ofRole('challenge')[0],
    // The first factors that need an identifier (the password) come before
    // the discoverable ones once the transaction holds one (ADR-017
    // Decision 4: "the same password-required shape for every account, with
    // webauthn_get offered").
    firstFactors: Object.freeze([
      ...firstFactors.filter((handler) => handler.discoverable !== true),
      ...firstFactors.filter((handler) => handler.discoverable === true),
    ]),
    discoverable: Object.freeze(firstFactors.filter((handler) => handler.discoverable === true)),
    secondFactors: Object.freeze(ofRole('second_factor')),
  });
}

/** A policy the reader returned, checked: a value outside the known modes is a store fault. */
function checkedPolicy(policy: unknown): MfaPolicy {
  const modes = MFA_MODES as readonly unknown[];
  const value = policy as Partial<MfaPolicy> | null;
  if (value === null || typeof value !== 'object') {
    throw new SignInStoreUnavailableError('policy', new Error('not a policy'));
  }
  if (!modes.includes(value.realm) || !modes.includes(value.client)) {
    throw new SignInStoreUnavailableError('policy', new Error('unknown MFA mode'));
  }
  return { realm: value.realm as MfaPolicy['realm'], client: value.client as MfaPolicy['client'] };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The transaction a round works on: what a refusal hands back is as far as the round took it. */
interface RoundState {
  transaction: SignInTransaction;
}

/** The most providers the `upstream` step lists (#639): its schema's bound. */
const MAX_UPSTREAM_PROVIDERS = 16;

/** Something the engine can offer: a step handler, or the `upstream` step (#639). */
interface Offerable {
  readonly step: StepName;
  params(round: StepRound): unknown;
}

/** A reset's start (#642): the `password_reset` step, a path marker with no params. */
const RESET_START: Offerable = Object.freeze({
  step: 'password_reset',
  params: () => Object.freeze({}),
});

/** The params of an `upstream` step listing `providers`, or `null` outside the step's schema. */
function upstreamParams(
  providers: readonly UpstreamProviderEntry[]
): StepParams<'upstream'> | null {
  const parsed = grammarStep('upstream').params.safeParse({ providers });
  return parsed.success ? (parsed.data as StepParams<'upstream'>) : null;
}

/** Build a sign-in engine. */
export function createSignInEngine(deps: SignInEngineDependencies): SignInEngine {
  const handlers = buildHandlers(deps);
  const hooks = deps.hooks ?? {};
  const clock = deps.clock ?? SYSTEM_CLOCK;
  // The step grammar's one answer reader, shared with both transports.
  const grammar = createInteractionMapper();
  const factorOf = (step: StepName) => handlers.byStep.get(step)?.factor;
  const { emailCodes } = deps;
  const ladder = deps.hooks?.ladder ?? NO_LADDER;
  /**
   * Whether the engine answers `step` itself: a handler's, the email code of
   * the inline verification, or the new password of the forced update.
   */
  const knows = (step: StepName) =>
    handlers.byStep.has(step) ||
    (step === 'email_code' && emailCodes !== undefined) ||
    (step === 'new_password' && deps.passwordUpdates !== undefined) ||
    (step === 'upstream' && deps.upstream !== undefined) ||
    (step === 'password_reset' && deps.resets !== undefined);
  /** Report a failure that changes no answer: a reporter that throws changes nothing either. */
  const report = (port: string, error: unknown) => {
    try {
      deps.onUnavailable?.(new SignInStoreUnavailableError(port, error));
    } catch {
      // Nothing to do: the answer stands.
    }
  };
  /**
   * Settle a credential round's reservation on the limiters (#636). A failure
   * stays counted when settling fails, so a settle error is reported and
   * changes no answer.
   */
  const settleRound = async (
    reservation: CredentialRoundReservation | null,
    outcome: 'success' | 'failure' | 'withdrawn',
    userId?: string
  ): Promise<void> => {
    if (reservation === null) return;
    try {
      await reservation.settle(outcome, userId === undefined ? undefined : { userId });
    } catch (error) {
      report('limits', error);
    }
  };
  /**
   * Settle an email-code reservation. A failure stays counted when settling
   * fails, so a settle error is reported and changes no answer.
   */
  const settleCode = async (
    reservation: LadderReservation,
    outcome: 'success' | 'failure'
  ): Promise<void> => {
    try {
      await reservation.settle(outcome);
    } catch (error) {
      report('ladder', error);
    }
  };

  async function advance(
    stored: SignInTransaction | null,
    answer: RoundAnswer | null,
    context: RoundContext
  ): Promise<RoundResult> {
    const startedAt = context.receivedAt ?? clock.now();
    try {
      return await round(stored, answer, context);
    } finally {
      // The timing floor, success or failure: no round tells its outcome by
      // its time.
      const left = SIGN_IN_MIN_RESPONSE_TIME_MS - (clock.now() - startedAt);
      if (left > 0) await clock.sleep(left);
    }
  }

  async function completeUpstream(
    stored: SignInTransaction | null,
    proof: UpstreamProof,
    context: RoundContext
  ): Promise<RoundResult> {
    const startedAt = context.receivedAt ?? clock.now();
    try {
      return await round(stored, null, context, proof);
    } finally {
      // The same floor as every round: no callback tells its outcome by its time.
      const left = SIGN_IN_MIN_RESPONSE_TIME_MS - (clock.now() - startedAt);
      if (left > 0) await clock.sleep(left);
    }
  }

  /**
   * End a transaction the round may not use, before anything in it is read.
   * The record names nobody: nothing in such a transaction can be trusted to
   * name the person. It names the answered step when the engine has a
   * handler for it, else the identifier step, where every transaction starts.
   */
  async function endUnusable(
    answer: RoundAnswer | null,
    context: RoundContext,
    reason: 'transaction_invalid' | 'transaction_expired',
    proof?: UpstreamProof
  ): Promise<RoundResult> {
    const named =
      proof !== undefined
        ? 'upstream'
        : answer !== null && typeof answer.step === 'string'
          ? stepNameOfUrn(answer.step)
          : undefined;
    const step = named !== undefined && knows(named) ? named : 'identifier';
    await context.audit(Object.freeze({ outcome: 'ended', step, reason }));
    return TRANSACTION_ENDED;
  }

  async function round(
    stored: SignInTransaction | null,
    answer: RoundAnswer | null,
    context: RoundContext,
    proof?: UpstreamProof
  ): Promise<RoundResult> {
    const now = clock.now();
    if (context.flow !== undefined && context.flow !== 'register' && context.flow !== 'reset') {
      throw new Error('sign-in engine: an unknown flow');
    }
    const found =
      stored === null
        ? newSignInTransaction({
            realmId: context.realm.id,
            clientId: context.client.id,
            createdAt: now,
            ...(context.flow === undefined ? {} : { flow: context.flow }),
          })
        : readSignInTransaction(stored);
    // A transaction that is not well formed ends: nothing in it can be trusted.
    if (found === null) return endUnusable(answer, context, 'transaction_invalid', proof);
    // Nor can one of another realm or client, or one that starts in the future.
    if (
      found.realmId !== context.realm.id ||
      found.clientId !== context.client.id ||
      found.createdAt > now + SIGN_IN_TRANSACTION_CLOCK_SKEW_MS
    ) {
      return endUnusable(answer, context, 'transaction_invalid', proof);
    }
    if (now - found.createdAt > SIGN_IN_TRANSACTION_MAX_AGE_MS) {
      return endUnusable(answer, context, 'transaction_expired', proof);
    }
    // A transaction runs the flow it began with (#640): a sign-in never
    // becomes a registration, nor a registration a sign-in. A sign-in may
    // become a reset at its password step (#642), and goes on as one on the
    // rounds of the sign-in it was.
    if (found.flow !== context.flow && !(found.flow === 'reset' && context.flow === undefined)) {
      return endUnusable(answer, context, 'transaction_invalid', proof);
    }
    // A subject without an identifier comes only from a discoverable factor,
    // or from an upstream provider's callback (#639).
    if (
      found.subject !== undefined &&
      found.identifier === undefined &&
      !found.verified.some(
        (step) => step.step === 'upstream' || handlers.byStep.get(step.step)?.discoverable === true
      )
    ) {
      return endUnusable(answer, context, 'transaction_invalid', proof);
    }
    const state: RoundState = { transaction: found };
    try {
      return await rules(state, answer, context, { fresh: stored === null, proof });
    } catch (error) {
      if (!(error instanceof SignInStoreUnavailableError)) throw error;
      deps.onUnavailable?.(error);
      return Object.freeze({
        kind: 'refused',
        reason: 'unavailable',
        transaction: freezeTransaction(state.transaction),
      });
    }
  }

  async function rules(
    state: RoundState,
    answer: RoundAnswer | null,
    context: RoundContext,
    upstreamRound: { readonly fresh: boolean; readonly proof?: UpstreamProof }
  ): Promise<RoundResult> {
    const found = state.transaction;
    const realmId = context.realm.id;
    const clientId = context.client.id;
    // ADR-008 §5: only `development` relaxes the limiters; anything else is production.
    const environment = roundEnvironmentOf(context.environment ?? 'production');
    const served = new Set<StepName>(context.serves ?? STEP_NAMES);
    /** A registration (#640), not a sign-in. */
    const registering = state.transaction.flow === 'register';
    /** A password reset (#642), not a sign-in: one this round turns into a reset is not, yet. */
    const resetting = state.transaction.flow === 'reset';
    const answeredName =
      answer !== null && typeof answer.step === 'string' ? stepNameOfUrn(answer.step) : undefined;
    /** The round's answer while no step has taken it. */
    const turn: { pending: { readonly name: StepName; readonly answer: RoundAnswer } | null } = {
      pending:
        answer !== null && answeredName !== undefined ? { name: answeredName, answer } : null,
    };

    /** The keyed HMAC of `identifier`, checked: a key that answers anything else is a store fault. */
    const digestOf = (identifier: string): Promise<string> =>
      fromStore('identifierDigest', async () => {
        const digest = await deps.identifierDigest({ realmId, identifier });
        if (typeof digest !== 'string' || !IDENTIFIER_HMAC_PATTERN.test(digest)) {
          throw new Error('not an identifier HMAC');
        }
        return digest;
      });
    let hmac: Promise<string> | undefined;
    /**
     * The HMAC of the transaction's identifier or, for an account an upstream
     * provider proved (#639), of the address that provider gave: the address
     * rule 8 verifies, whose email-code ladder it keys.
     */
    const identifierHmac = (): Promise<string> => {
      const identifier = state.transaction.identifier ?? state.transaction.upstream?.address;
      if (identifier === undefined) throw new Error('sign-in engine: no identifier to digest');
      hmac ??= digestOf(identifier);
      return hmac;
    };
    /**
     * Spend the bot challenge a transaction passed (#643): a credential was
     * checked, right or wrong, so the next one under a soft threshold needs a
     * new one.
     */
    const spendChallenge = (): void => {
      if (state.transaction.captchaPassed === true) {
        state.transaction = { ...state.transaction, captchaPassed: undefined };
      }
    };
    const stepRound = (): StepRound =>
      Object.freeze({
        realmId,
        clientId,
        transaction: state.transaction,
        ...(state.transaction.identifier === undefined
          ? {}
          : { identifier: state.transaction.identifier }),
        ...(context.endUserIp === undefined ? {} : { endUserIp: context.endUserIp }),
        identifierHmac,
      });

    /**
     * Write one audit record. The person is named by the transaction's
     * subject once a factor fixed one, by the identifier's HMAC before; with
     * neither (a bot challenge or a discoverable factor refused before any
     * identifier), the record names nobody, and is still written.
     */
    const audit = async (
      outcome: SignInAuditRecord['outcome'],
      step: StepName,
      reason?: SignInAuditReason
    ): Promise<void> => {
      const base = { outcome, step, ...(reason === undefined ? {} : { reason }) };
      let record: SignInAuditRecord;
      const { subject, identifier } = state.transaction;
      if (subject !== undefined) record = { ...base, userId: subject };
      else if (identifier !== undefined)
        record = { ...base, identifierHmac: await identifierHmac() };
      else record = base;
      await context.audit(Object.freeze(record));
    };

    /**
     * Record that `step`'s answer was accepted without its breach-list check,
     * which could not be made (#635): never a refusal.
     */
    const unchecked = async (step: StepName, failure: BreachCheckFailure): Promise<void> => {
      const { subject } = state.transaction;
      if (subject === undefined)
        throw new Error('sign-in engine: an unchecked step without a subject');
      await context.audit(
        Object.freeze({
          outcome: 'unchecked',
          step,
          reason: 'breach_check_failed',
          failure,
          userId: subject,
        })
      );
    };

    const ended = async (step: StepName, reason: SignInAuditReason): Promise<RoundResult> => {
      await audit('ended', step, reason);
      return TRANSACTION_ENDED;
    };
    const throttled = (retryAfterSeconds: number): RoundResult =>
      Object.freeze({
        kind: 'refused',
        reason: 'throttled',
        retryAfterSeconds,
        transaction: freezeTransaction(state.transaction),
      });
    /** Refuse a malformed answer to `step`, audited: nothing was verified or counted. */
    const invalidAnswer = async (step: StepName): Promise<RoundResult> => {
      await audit('refused', step, 'invalid_answer');
      return Object.freeze({
        kind: 'refused',
        reason: 'invalid_answer',
        transaction: freezeTransaction(state.transaction),
      });
    };
    /**
     * Reserve a credential round of `step` on the limiters (#636; ADR-017
     * Decision 7), before its credential is verified and before the
     * account's ladder: an answer that carries a password, an `otp`, a
     * recovery code or a WebAuthn response. Returns the round's refusal
     * when a delay or a hard limit holds (audited as `rate_limited`, nothing
     * verified or counted), else the reservation to settle once the
     * credential is checked, or `null` without a limiter. A reservation left
     * unsettled, because the verification failed, stays a failed round.
     */
    const reserveCredentialRound = async (
      step: StepName
    ): Promise<
      | { readonly refused: RoundResult }
      | { readonly reservation: CredentialRoundReservation | null }
    > => {
      const { limits } = hooks;
      if (limits === undefined) return { reservation: null };
      const named = state.transaction.identifier ?? state.transaction.upstream?.address;
      const identifierDigest = named === undefined ? undefined : await identifierHmac();
      const verdict = await fromStore('limits', () =>
        limits.reserve({
          realmId,
          clientId,
          environment,
          ...(context.endUserIp === undefined ? {} : { endUserIp: context.endUserIp }),
          ...(identifierDigest === undefined ? {} : { identifierHmac: identifierDigest }),
        })
      );
      if (verdict?.kind === 'throttled') {
        await audit('refused', step, 'rate_limited');
        return { refused: throttled(Math.max(1, Math.ceil(verdict.retryAfterSeconds))) };
      }
      if (verdict?.kind !== 'reserved' || typeof verdict.settle !== 'function') {
        throw new SignInStoreUnavailableError('limits', new Error('not a reservation'));
      }
      return { reservation: verdict };
    };
    /**
     * The step a refusal of the whole round names: the answered one when the
     * engine has a handler for it, else the identifier step, where every
     * transaction starts. Never a step only the client named.
     */
    const roundStep = (): StepName =>
      answeredName !== undefined && knows(answeredName) ? answeredName : 'identifier';
    const redirect = (reason: 'step_not_available' | 'request'): RoundResult =>
      Object.freeze({ kind: 'redirect', reason, transaction: null });

    /** The offer of `steps`, the first one current, with their params for this round. */
    const offerOf = async (
      steps: readonly Offerable[],
      options: { readonly preferred?: boolean } = {}
    ): Promise<StepOffer> => {
      const current = stepRound();
      const offered = await Promise.all(
        steps.map(async (handler) => ({
          step: handler.step,
          params: await handler.params(current),
        }))
      );
      const [first, ...alternatives] = offered;
      if (first === undefined) throw new Error('sign-in engine: an empty offer');
      return Object.freeze({
        current: Object.freeze(first),
        alternatives: Object.freeze(alternatives.map((step) => Object.freeze(step))),
        // A step that one of its alternatives may replace (a discoverable
        // passkey before any identifier) is preferred, not required.
        ...(options.preferred === true && alternatives.length > 0 ? { required: false } : {}),
      } as StepOffer);
    };
    const offerStep = (offer: StepOffer, error?: StepErrorCode): RoundResult => {
      const current =
        error === undefined
          ? offer.current
          : Object.freeze({ ...offer.current, error } as StepOffer['current']);
      const handler = handlers.byStep.get(current.step) as StepHandler | undefined;
      // The email code's screen names the address the code went to (for an
      // account an upstream provider proved, the address it gave, #639), and
      // the new password's the account it is for.
      const identifier =
        current.step === 'email_code'
          ? (state.transaction.identifier ?? state.transaction.upstream?.address)
          : state.transaction.identifier;
      const personal =
        current.step === 'email_code' || current.step === 'new_password'
          ? identifier === undefined
            ? {}
            : { identifier }
          : (handler?.personal?.(stepRound()) ?? {});
      return Object.freeze({
        kind: 'step',
        transaction: freezeTransaction(state.transaction),
        offer: Object.freeze({ ...offer, current }),
        personal: Object.freeze({ ...personal }),
      });
    };
    /** Whether the round's answer is to one of `offer`'s steps. */
    const answers = (offer: StepOffer): boolean => {
      const { pending } = turn;
      return (
        pending !== null &&
        [offer.current.step, ...offer.alternatives.map((step) => step.step)].includes(pending.name)
      );
    };
    /** Read the pending answer against `offer` with the step grammar; `null` when it is malformed. */
    const readPending = (offer: StepOffer): ReadAnswer | null => {
      const { pending } = turn;
      if (pending === null) throw new Error('sign-in engine: no answer to read');
      try {
        return grammar.readAnswer(
          offer,
          STEP_URNS[pending.name],
          pending.answer.fields,
          pending.answer.encoding ?? 'form'
        );
      } catch (error) {
        if (error instanceof StepAnswerError) return null;
        throw error;
      }
    };
    /** Offer `offer` again with the refused step current and its error; the others stay alternatives. */
    const refusedOffer = (offer: StepOffer, step: StepName): StepOffer => {
      const all = [offer.current, ...offer.alternatives];
      const refused = all.find((offered) => offered.step === step);
      if (refused === undefined) throw new Error(`sign-in engine: ${step} was not offered`);
      const others = all.filter((offered) => offered.step !== step);
      // A preferred step refused stays preferred: its alternatives may still replace it.
      const preferred = offer.required === false && offer.current.step === step;
      return Object.freeze({
        current: Object.freeze({
          step: refused.step,
          params: refused.params,
        } as StepOffer['current']),
        alternatives: Object.freeze(
          others.map((offered) => Object.freeze({ step: offered.step, params: offered.params }))
        ) as StepOffer['alternatives'],
        ...(preferred && others.length > 0 ? { required: false } : {}),
      });
    };
    const refuseAnswer = async (
      offer: StepOffer,
      step: StepName,
      error: StepErrorCode,
      reason: SignInAuditReason
    ): Promise<RoundResult> => {
      await audit('refused', step, reason);
      return offerStep(refusedOffer(offer, step), error);
    };

    /**
     * A factor proved an account. The engine checks what every handler must
     * have checked (an enabled account, verified under the gate) and refuses
     * it like a wrong answer if not, so no step it adds later can fix a
     * disabled user as the subject. Then one subject per transaction, and the
     * step and the time are recorded.
     */
    const prove = async (
      offer: StepOffer,
      account: ProvedAccount,
      read: ReadAnswer,
      breachCheck?: BreachCheckVerdict
    ): Promise<RoundResult | null> => {
      // Another user's proof ends the transaction, whatever that user's state.
      const { subject, identifier } = state.transaction;
      if (subject !== undefined && subject !== account.userId) {
        return ended(read.step, 'subject_mismatch');
      }
      // The first proof of a transaction that holds an identifier must prove
      // the account the identifier names: a discoverable factor names its
      // account by itself, and may name another. The password step proved
      // that account by reading it, so it needs no second read.
      if (subject === undefined && identifier !== undefined && read.step !== 'password') {
        const named = await fromStore('accounts', () =>
          deps.accounts.findByIdentifier(realmId, identifier)
        );
        if (named === null || named.userId !== account.userId) {
          return ended(read.step, 'subject_mismatch');
        }
      }
      if (!account.enabled) {
        return refuseAnswer(offer, read.step, 'invalid_credentials', 'account_disabled');
      }
      if (!account.verified && deps.requireVerifiedAccount && emailCodes === undefined) {
        return refuseAnswer(offer, read.step, 'invalid_credentials', 'email_not_verified');
      }
      state.transaction = {
        ...state.transaction,
        subject: account.userId,
        verified: [
          ...state.transaction.verified,
          { step: read.step, params: read.params } as OfferedStep,
        ],
        authTime: clock.now(),
        // A password on the realm's breach list must be replaced before the
        // sign-in completes (#635): rule 8 asks for a new one.
        ...(breachCheck?.kind === 'listed' ? { breachedPassword: true as const } : {}),
      };
      await audit('passed', read.step);
      if (breachCheck?.kind === 'failed') await unchecked(read.step, breachCheck.failure);
      return null;
    };

    /**
     * Verify the pending answer against `offer`, after the step grammar read
     * it. Returns the round's result when the answer ends the round, or
     * `null` when it proved a factor or passed a challenge and the rules go on.
     */
    const verifyPending = async (offer: StepOffer): Promise<RoundResult | null> => {
      const { pending } = turn;
      if (pending === null) throw new Error('sign-in engine: no answer to verify');
      const read = readPending(offer);
      if (read === null) return invalidAnswer(pending.name);
      turn.pending = null;
      const handler = handlers.byStep.get(read.step) as StepHandler;
      // A credential round meets the limiters first (#636); a bot challenge's
      // answer carries no credential.
      let reservation: CredentialRoundReservation | null = null;
      const credential = isCredentialAnswer(read.answer);
      if (credential) {
        const limited = await reserveCredentialRound(read.step);
        if ('refused' in limited) return limited.refused;
        reservation = limited.reservation;
      }
      const verdict: StepVerdict = await handler.verify(stepRound(), {
        params: read.params,
        answer: read.answer,
      });
      // A credential that was checked spends the bot challenge passed for it.
      if (credential && verdict.kind !== 'throttled') spendChallenge();
      switch (verdict.kind) {
        case 'refused':
          await settleRound(reservation, 'failure');
          return refuseAnswer(offer, read.step, verdict.error, verdict.audit.reason);
        case 'throttled':
          // The account's ladder refused it inside a wait: never verified.
          await settleRound(reservation, 'withdrawn');
          await audit('refused', read.step, verdict.audit.reason);
          return throttled(verdict.retryAfterSeconds);
        case 'proved': {
          if (handler.role !== 'first_factor' && handler.role !== 'second_factor') {
            throw new Error(`sign-in engine: ${read.step} proved an account`);
          }
          const result = await prove(offer, verdict.account, read, verdict.breachCheck);
          // The engine's own checks may still refuse the proof: a failed round.
          await settleRound(
            reservation,
            result === null ? 'success' : 'failure',
            verdict.account.userId
          );
          return result;
        }
        default:
          throw new Error(`sign-in engine: ${read.step} answered ${verdict.kind}`);
      }
    };

    /**
     * The `upstream` step's params for this round (#639): the realm's
     * providers, `null` when it offers none, when the engine has no provider
     * directory, or when the transport can serve or start none. An entry
     * outside the step's schema (a name the screen cannot show) is left out
     * and reported, so one provider's bad row never stops the sign-in; a
     * directory that answers no list is a store fault.
     */
    const upstreamProviders = async (): Promise<StepParams<'upstream'> | null> => {
      const directory = deps.upstream;
      if (
        directory === undefined ||
        context.startUpstream === undefined ||
        !served.has('upstream')
      ) {
        return null;
      }
      const providers: unknown = await fromStore('upstream', () =>
        directory.offered({ realmId, clientId })
      );
      if (!Array.isArray(providers)) {
        throw new SignInStoreUnavailableError('upstream', new Error('not a provider list'));
      }
      const shown = (providers as readonly UpstreamProviderEntry[]).filter(
        (entry) => upstreamParams([entry]) !== null
      );
      if (shown.length < providers.length) {
        report('upstream', new Error('a provider outside the upstream step’s schema was left out'));
      }
      if (shown.length === 0) return null;
      const params = upstreamParams(shown.slice(0, MAX_UPSTREAM_PROVIDERS));
      if (params === null) {
        throw new SignInStoreUnavailableError('upstream', new Error('not a provider list'));
      }
      return params;
    };

    /**
     * Start an upstream provider (#639): the one the pending answer picked
     * from `offer`, or the one the authorization request routes to. The
     * transport keeps the provider's transaction; the engine's records which
     * provider may complete it. A provider that cannot start is refused with
     * `provider_unavailable`, the step offered again.
     */
    const pickUpstream = async (
      offer: StepOffer,
      routed?: UpstreamProviderEntry
    ): Promise<RoundResult> => {
      let entry: UpstreamProviderEntry;
      if (routed === undefined) {
        const read = readPending(offer);
        if (read === null) return invalidAnswer('upstream');
        turn.pending = null;
        const { provider } = read.answer as StepAnswer<'upstream'>;
        const listed = (read.params as StepParams<'upstream'>).providers.find(
          (item) => item.provider === provider
        );
        // A provider the step did not list: the answer is malformed.
        if (listed === undefined) return invalidAnswer('upstream');
        entry = listed;
      } else {
        if (upstreamParams([routed]) === null) {
          throw new Error('sign-in engine: a routed provider outside the upstream step’s schema');
        }
        entry = routed;
      }
      const start = context.startUpstream;
      if (start === undefined)
        throw new Error('sign-in engine: no upstream starter for this round');
      const started = await fromStore('startUpstream', () => start(entry));
      if (started?.kind === 'unavailable') {
        await audit('refused', 'upstream', 'provider_unavailable');
        const listed = [offer.current, ...offer.alternatives].some(
          (offered) => offered.step === 'upstream'
        );
        return listed
          ? offerStep(refusedOffer(offer, 'upstream'), 'provider_unavailable')
          : offerStep(offer);
      }
      if (started?.kind !== 'started' || typeof started.redirectTo !== 'string') {
        throw new SignInStoreUnavailableError('startUpstream', new Error('not a start outcome'));
      }
      state.transaction = { ...state.transaction, upstream: { provider: entry.provider } };
      const shown = offerStep(offer);
      if (shown.kind !== 'step') throw new Error('sign-in engine: an offer that is not a step');
      return Object.freeze({
        kind: 'upstream',
        transaction: shown.transaction,
        offer: shown.offer,
        personal: shown.personal,
        provider: entry.provider,
        redirectTo: started.redirectTo,
      });
    };

    /**
     * Take an upstream provider's proof (#639). Returns the round's refusal,
     * or `null` once the step is proved and the rules go on. A proof is taken
     * only by the transaction that sent the person to that provider, while
     * nobody is named; any other is refused as `invalid_answer`, with the
     * transaction as it was. The checks of every factor follow: an enabled
     * account, verified under the gate.
     */
    const proveUpstream = async (proof: UpstreamProof): Promise<RoundResult | null> => {
      const refuse = async (reason: SignInAuditReason): Promise<RoundResult> => {
        await audit('refused', 'upstream', reason);
        return Object.freeze({
          kind: 'refused',
          reason: 'invalid_answer',
          transaction: freezeTransaction(state.transaction),
        });
      };
      const { subject, identifier, upstream } = state.transaction;
      if (
        subject !== undefined ||
        identifier !== undefined ||
        upstream === undefined ||
        upstream.address !== undefined ||
        upstream.provider !== proof.provider.provider
      ) {
        return refuse('invalid_answer');
      }
      const params = upstreamParams([proof.provider]);
      if (params === null)
        throw new Error('sign-in engine: a proof outside the upstream step’s schema');
      if (!proof.account.enabled) return refuse('account_disabled');
      if (!proof.account.verified && deps.requireVerifiedAccount && emailCodes === undefined) {
        return refuse('email_not_verified');
      }
      const address = proof.address === undefined ? undefined : readIdentifier(proof.address);
      state.transaction = {
        ...state.transaction,
        subject: proof.account.userId,
        verified: [...state.transaction.verified, { step: 'upstream', params } as OfferedStep],
        authTime: clock.now(),
        upstream: {
          provider: proof.provider.provider,
          ...(address === null || address === undefined ? {} : { address }),
        },
      };
      await audit('passed', 'upstream');
      return null;
    };

    /** The `email_code` step for `held` at `at`: the step alone, required. */
    const codeOffer = (held: HeldEmailCode, at: number): StepOffer =>
      Object.freeze({
        current: Object.freeze({
          step: 'email_code',
          params: Object.freeze(emailCodeParams(held, at)),
        }),
        alternatives: Object.freeze([]),
      }) as StepOffer;

    /** Whether this transaction proved the mailbox: an email code answered right, for any purpose. */
    const provedMailbox = (): boolean =>
      state.transaction.verified.some((step) => step.step === 'email_code');
    /** Whether the account has a factor beyond its password: a second factor or a passkey, disabled or not. */
    const boundBeyondPassword = (current: SignInAccount): boolean =>
      current.factors.some((factor) => factor.type !== 'password');
    /** Whether this transaction proved a factor beyond the password. */
    const provedBeyondPassword = (): boolean =>
      state.transaction.verified.some((step) => {
        const factor = factorOf(step.step);
        return factor !== undefined && factor !== 'password';
      });

    /**
     * The rounds of one emailed code (#638), whatever it is for: the inline
     * verification of an account's address, the mailbox proof before a forced
     * update, and a registration's first answer (#640). Returns the round's
     * result while the code is pending, or the params it was answered with
     * once it is answered right; the code is still held then, so a write
     * that fails refuses the round and the same code may be answered again.
     *
     * - The first round mails a code through the capped sender and offers
     *   `email_code`; a cap that answers 429 refuses the round, and nothing
     *   is held. `beforeFirst` may refuse that round first: a registration's
     *   start cap.
     * - An answer with no otp asks for a new code: one is mailed a minute
     *   after the last, and the transaction's count of wrong answers stays.
     * - An expired code is refused with `code_expired`, nothing compared or
     *   counted.
     * - Otherwise the answer is reserved on the limiters, then on the
     *   email-code ladder (the identifier HMAC's `email_code` counter, across
     *   transactions), with no end-user IP: an address not proved has no
     *   owner whose IPs are known. Inside a delay or a wait it is refused,
     *   not compared.
     * - The code is compared HMAC to HMAC, in constant time. A wrong one is
     *   counted, and the 5th of the transaction burns the code and ends it.
     *   A right one that `refuses` refuses is answered exactly as a wrong one.
     *   A right one taken clears the ladder's counter.
     */
    const codeRound = async (
      codes: EmailCodeDependencies,
      spec: {
        readonly purpose: EmailCodePurpose;
        readonly length: EmailCodeLength;
        /** Where the code goes: the normalised address. */
        readonly address: string;
        /** The code follows a correct first factor of this transaction. */
        readonly afterFirstFactor: boolean;
        /** The account a right code settles the limiters' round for, when one is proved. */
        readonly userId?: string;
        /** Before the first code: the round's refusal, or `null` to mail it. */
        readonly beforeFirst?: () => Promise<RoundResult | null>;
        /** What each code's mail says about the address: a registration's (#640). */
        readonly registration?: () => Promise<RegistrationMail>;
        /** Whether each code may be mailed: a reset's (#642). */
        readonly reset?: () => Promise<ResetMail>;
        /**
         * Why a right code may not be taken, read once it compared right: it
         * is then answered exactly as a wrong one, and audited with that
         * reason. `null` takes it.
         */
        readonly refuses?: () => Promise<SignInAuditReason | null>;
      }
    ): Promise<{ readonly result: RoundResult } | { readonly params: unknown }> => {
      const { sendCode } = context;
      if (sendCode === undefined) {
        throw new Error('sign-in engine: no email-code sender for this round');
      }
      const { purpose, length, address } = spec;
      const digestCode = (salt: string, code: string): Promise<string> =>
        fromStore('emailCodeDigest', async () => {
          const digest = await codes.digest({ realmId, salt, code });
          if (typeof digest !== 'string' || !EMAIL_CODE_HMAC_PATTERN.test(digest)) {
            throw new Error('not an email-code HMAC');
          }
          return digest;
        });
      /**
       * Mail a new code, `previous`'s count of wrong answers kept. Returns
       * the round's refusal when a cap answers 429, else `null` with the
       * code held.
       */
      const issue = async (previous?: HeldEmailCode): Promise<RoundResult | null> => {
        // A registration re-reads the address before every code it mints
        // (ADR-017 Decision 8): a disabled user's gets no mail.
        const registration =
          spec.registration === undefined ? undefined : await spec.registration();
        // So does a reset (#642): only an enabled account with a password is
        // mailed.
        const reset = spec.reset === undefined ? undefined : await spec.reset();
        const issuedAt = clock.now();
        const code = generateEmailCode(length);
        const salt = generateEmailCodeSalt();
        const hmac = await digestCode(salt, code);
        const sent = await fromStore('sendCode', () =>
          sendCode({
            realmId,
            address,
            purpose,
            code,
            expiresInSeconds: EMAIL_CODE_TTL_MS / 1000,
            afterFirstFactor: spec.afterFirstFactor,
            ...(registration === undefined ? {} : { registration }),
            ...(reset === undefined ? {} : { reset }),
          })
        );
        if (sent?.kind === 'capped') {
          await audit('refused', 'email_code', 'send_capped');
          return throttled(Math.max(1, Math.ceil(sent.retryAfterSeconds)));
        }
        if (sent?.kind !== 'accepted') {
          throw new SignInStoreUnavailableError('sendCode', new Error('not a send outcome'));
        }
        state.transaction = {
          ...state.transaction,
          emailCode: heldEmailCode({
            purpose,
            length,
            salt,
            hmac,
            issuedAt,
            ...(previous === undefined ? {} : { previous }),
          }),
        };
        return null;
      };
      /** Mail a code and offer the step for it. */
      const issueAndOffer = async (previous?: HeldEmailCode): Promise<RoundResult> => {
        const refused = await issue(previous);
        if (refused !== null) return refused;
        const issued = state.transaction.emailCode;
        if (issued === undefined) throw new Error('sign-in engine: no code was held');
        return offerStep(codeOffer(issued, clock.now()));
      };

      const held = state.transaction.emailCode;
      // The first round: the first code.
      if (held === undefined) {
        const refused = await spec.beforeFirst?.();
        if (refused !== undefined && refused !== null) return { result: refused };
        return { result: await issueAndOffer() };
      }
      const at = clock.now();
      const offer = codeOffer(held, at);
      // An answer to another step is ignored, as every eager answer is; a
      // round with none asks for the code again.
      if (turn.pending?.name !== 'email_code') {
        return {
          result: offerStep(offer, emailCodeExpired(held, at) ? 'code_expired' : undefined),
        };
      }
      const read = readPending(offer);
      if (read === null) return { result: await invalidAnswer('email_code') };
      turn.pending = null;
      const { otp } = read.answer as StepAnswer<'email_code'>;
      if (otp === undefined) {
        // A new code once one is due; before, the same step, nothing mailed.
        return {
          result: emailCodeResendDue(held, at) ? await issueAndOffer(held) : offerStep(offer),
        };
      }
      if (emailCodeExpired(held, at)) {
        await audit('refused', 'email_code', 'code_expired');
        return { result: offerStep(offer, 'code_expired') };
      }
      // A code is a credential round (#636): the limiters first, then the
      // ladder; inside a delay or a wait nothing is compared or counted.
      const limited = await reserveCredentialRound('email_code');
      if ('refused' in limited) return { result: limited.refused };
      const codeRoundReservation = limited.reservation;
      const identifierDigest = await identifierHmac();
      const reservation = await fromStore('ladder', () =>
        ladder.reserve({ realmId, identifierHmac: identifierDigest, factor: 'email_code' })
      );
      if (reservation.kind === 'wait') {
        await settleRound(codeRoundReservation, 'withdrawn');
        await audit('refused', 'email_code', 'locked_out');
        return { result: throttled(reservation.retryAfterSeconds) };
      }
      // A digest that fails leaves the attempt counted, as a store fault
      // after the password's reservation does. The code is checked now: it
      // spends the bot challenge passed for it (#643).
      spendChallenge();
      const presented = await digestCode(held.salt, otp);
      let answered = answerEmailCode(held, presented, at);
      let refusedAs: SignInAuditReason = 'invalid_code';
      // A right code that may not be taken gets the answer of a wrong one.
      if (answered.kind === 'accepted' && spec.refuses !== undefined) {
        const refused = await spec.refuses();
        if (refused !== null) {
          answered = countWrongEmailCode(held);
          refusedAs = refused;
        }
      }
      switch (answered.kind) {
        case 'wrong':
          await settleCode(reservation, 'failure');
          await settleRound(codeRoundReservation, 'failure');
          state.transaction = { ...state.transaction, emailCode: answered.held };
          await audit('refused', 'email_code', refusedAs);
          return { result: offerStep(codeOffer(answered.held, at), 'invalid_credentials') };
        case 'burned':
          await settleCode(reservation, 'failure');
          await settleRound(codeRoundReservation, 'failure');
          state.transaction = { ...state.transaction, emailCode: undefined };
          return { result: await ended('email_code', 'code_burned') };
        case 'accepted':
          break;
        default:
          // `at` is the one clock reading of both checks: an expired code
          // was refused above.
          throw new Error(`sign-in engine: an email code answered ${answered.kind}`);
      }
      // The right code clears the ladder's counter, whatever comes next.
      await settleCode(reservation, 'success');
      await settleRound(codeRoundReservation, 'success', spec.userId);
      return { params: read.params };
    };

    /** Record the code `codeRound` accepted among the verified steps, the code consumed. */
    const codeTaken = async (params: unknown): Promise<void> => {
      state.transaction = {
        ...state.transaction,
        emailCode: undefined,
        verified: [...state.transaction.verified, { step: 'email_code', params } as OfferedStep],
      };
      await audit('passed', 'email_code');
    };

    /**
     * The inline verification of the address the transaction's identifier
     * names, after a factor proved its account (#638; ADR-017 Decisions 5
     * and 8; `graphs/flows/core/account-verification/flow.yaml`). Returns the
     * round's result while the code is pending, or `null` once the address
     * is verified and the rules go on. With the purpose `recovery` it proves
     * the mailbox of a password-only account before a forced password update
     * (#635), with the same rounds and an 8-digit code; the address is
     * marked verified all the same, which it already is.
     *
     * The code's rounds are {@link codeRound}'s, with a 6-digit code for
     * `verify_account`. A right one marks the address verified and is
     * recorded among the verified steps: no `amr` value, no `auth_time`.
     */
    const verifyAddress = async (
      codes: EmailCodeDependencies,
      subject: string,
      purpose: SignInCodePurpose
    ): Promise<RoundResult | null> => {
      const length = emailCodeLength(purpose, { afterPassword: true });
      // The address is the identifier; for an account an upstream provider
      // proved (#639), the address that provider gave.
      const upstreamAddress =
        state.transaction.identifier === undefined ? state.transaction.upstream : undefined;
      const identifier = state.transaction.identifier ?? upstreamAddress?.address;
      // A subject a discoverable factor named holds no address to mail, nor
      // does one a provider proved without an address, and a transport that
      // cannot serve the step cannot take the code.
      if (identifier === undefined || !served.has('email_code')) {
        return redirect('step_not_available');
      }
      const answered = await codeRound(codes, {
        purpose,
        length,
        address: identifier,
        afterFirstFactor: true,
        userId: subject,
      });
      if ('result' in answered) return answered.result;
      // The code is held until the address is written: a write that fails
      // refuses the round, and the same code may be answered again.
      const marked = await fromStore('addresses', () =>
        codes.addresses.markVerified({
          realmId,
          userId: subject,
          identifier,
          ...(upstreamAddress === undefined ? {} : { upstream: upstreamAddress.provider }),
        })
      );
      if (marked?.kind !== 'verified') {
        const reason = marked?.kind === 'refused' ? marked.reason : undefined;
        if (reason !== 'account_disabled' && reason !== 'subject_mismatch') {
          throw new SignInStoreUnavailableError('addresses', new Error('not a verification'));
        }
        state.transaction = { ...state.transaction, emailCode: undefined };
        return ended('email_code', reason);
      }
      await codeTaken(answered.params);
      return null;
    };

    /**
     * The `new_password` step (#635; ADR-017 Decision 8): offered with
     * `purpose` and the realm's minimum length. An answer is checked against
     * the realm's password policy, then against its breach list (a listed
     * one is refused as `blocklisted`, a check that fails accepts it and is
     * recorded), and is then handed to `write`: the forced update's
     * replacement, a registration's creation (#640) or a reset's replacement
     * (#642), which answers the round's result when it refused, else `null`. Returns the round's result
     * while the step is pending, or `null` once the password is set.
     */
    const askNewPassword = async (
      updates: PasswordUpdates,
      identifier: string,
      purpose: 'update_required' | 'register' | 'reset',
      write: (password: string, normalization: PasswordNormalization) => Promise<RoundResult | null>
    ): Promise<RoundResult | null> => {
      const minLength = await fromStore('passwordUpdates', async () => {
        const value = await updates.minLength(realmId);
        if (
          !Number.isInteger(value) ||
          value < PASSWORD_MIN_LENGTH_FLOOR ||
          value > PASSWORD_MAX_LENGTH
        ) {
          throw new Error('not a minimum password length');
        }
        return value;
      });
      const params: StepParams<'new_password'> = Object.freeze({
        purpose,
        min_length: minLength,
        max_length: PASSWORD_MAX_LENGTH,
      });
      const offerWith = (reasons?: readonly PasswordRejectionReason[]): StepOffer =>
        Object.freeze({
          current: Object.freeze({
            step: 'new_password',
            params: Object.freeze(
              reasons === undefined ? params : { ...params, reasons: [...reasons] }
            ),
          }),
          alternatives: Object.freeze([]),
        }) as StepOffer;
      const offer = offerWith();
      const refuse = async (
        reasons: readonly PasswordRejectionReason[],
        reason: SignInAuditReason
      ): Promise<RoundResult> => {
        await audit('refused', 'new_password', reason);
        return offerStep(offerWith(reasons), 'password_rejected');
      };
      // An answer to another step is ignored, as every eager answer is.
      if (turn.pending?.name !== 'new_password') return offerStep(offer);
      const read = readPending(offer);
      if (read === null) return invalidAnswer('new_password');
      turn.pending = null;
      const chosen = (read.answer as StepAnswer<'new_password'>).new_password;
      const checked = await fromStore('passwordUpdates', async () => {
        const result = await updates.check({ realmId, identifier, password: chosen });
        if (result?.kind === 'rejected') {
          const known = PASSWORD_REJECTION_REASONS as readonly unknown[];
          if (
            !Array.isArray(result.reasons) ||
            result.reasons.length === 0 ||
            !result.reasons.every((reason) => known.includes(reason)) ||
            new Set(result.reasons).size !== result.reasons.length
          ) {
            throw new Error('not a password policy refusal');
          }
          return result;
        }
        if (
          result?.kind !== 'accepted' ||
          typeof result.password !== 'string' ||
          result.normalization !== PASSWORD_NORMALIZATION_NFC
        ) {
          throw new Error('not a password policy check');
        }
        return result;
      });
      if (checked.kind === 'rejected') return refuse(checked.reasons, 'password_rejected');
      // The new password must itself pass the breach list: a listed one is
      // the blocklist's refusal (NIST SP 800-63B-4 §3.1.1.2 counts breach
      // corpora among the values a verifier blocks).
      const breach = await checkBreachList(deps.breachCheck, realmId, checked.password);
      if (breach.kind === 'listed') return refuse(['blocklisted'], 'password_breached');
      const written = await write(checked.password, checked.normalization);
      if (written !== null) return written;
      state.transaction = {
        ...state.transaction,
        verified: [
          ...state.transaction.verified,
          { step: 'new_password', params: read.params } as OfferedStep,
        ],
      };
      await audit('passed', 'new_password');
      if (breach.kind === 'failed') await unchecked('new_password', breach.failure);
      return null;
    };

    /**
     * A registration's rounds once the transaction holds the address (#640;
     * ADR-017 Decision 8; `graphs/flows/core/sign-up/flow.yaml`). Returns the
     * round's result, or `null` when an account holds the address and the
     * person is helped to sign in to it: rule 7's first factor.
     *
     * 1. The mailbox first: an 8-digit `verify_account` code, the same step
     *    for a new address and an existing one. The first code is a
     *    registration start, which the limiters cap. The mail says whether an
     *    account holds the address; a disabled user's gets none, and every
     *    code answered for it is answered as a wrong one, so nothing of that
     *    user changes.
     * 2. Then, with no account holding the address, `new_password` with the
     *    purpose `register`: the realm's password policy and its breach list,
     *    as for every new password. Once it passes, the account is created in
     *    one write; an address another account took meanwhile ends the
     *    transaction (`registration_conflict`).
     *
     * No account exists before both pass. The registration completes with no
     * `amr` and no `auth_time` (ADR-017 Decision 10).
     */
    const register = async (identifier: string): Promise<RoundResult | null> => {
      const { registrations, passwordUpdates: updates } = deps;
      if (registrations === undefined || emailCodes === undefined || updates === undefined) {
        throw new Error('sign-in engine: a registration without its dependencies');
      }
      const readCandidate = () =>
        fromStore('accounts', () => deps.accounts.findByIdentifier(realmId, identifier));
      if (!provedMailbox()) {
        const answered = await codeRound(emailCodes, {
          purpose: VERIFY_ACCOUNT,
          length: emailCodeLength(VERIFY_ACCOUNT, { afterPassword: false }),
          address: identifier,
          afterFirstFactor: false,
          beforeFirst: reserveRegistrationStart,
          registration: async () => {
            const candidate = await readCandidate();
            if (candidate === null) return 'new_address';
            return candidate.enabled ? 'account_exists' : 'withheld';
          },
          refuses: async () => {
            const candidate = await readCandidate();
            return candidate === null || candidate.enabled ? null : 'account_disabled';
          },
        });
        if ('result' in answered) return answered.result;
        await codeTaken(answered.params);
      }
      // An account holds the address: the person is helped to sign in to it
      // (ADR-017 Decision 8). An unclaimed one, too, until PRO-17 (#641) ends
      // it instead; its address is verified once its password is proved.
      if ((await readCandidate()) !== null) return null;
      const asked = await askNewPassword(
        updates,
        identifier,
        'register',
        async (password, normalization) => {
          const created = await fromStore('registrations', () =>
            registrations.create({ realmId, clientId, identifier, password, normalization })
          );
          if (created?.kind === 'conflict') return ended('new_password', 'registration_conflict');
          if (
            created?.kind !== 'created' ||
            typeof created.userId !== 'string' ||
            created.userId.length === 0
          ) {
            throw new SignInStoreUnavailableError('registrations', new Error('not a registration'));
          }
          state.transaction = { ...state.transaction, subject: created.userId };
          return null;
        }
      );
      if (asked !== null) return asked;
      const { subject } = state.transaction;
      if (subject === undefined)
        throw new Error('sign-in engine: a registration without its account');
      return Object.freeze({
        kind: 'complete',
        transaction: null,
        signIn: Object.freeze({ subject, identifier, registered: true as const }),
      });
    };

    /**
     * Count a registration start on the limiters (#640; ADR-017 Decision 7):
     * the round's refusal, audited as `rate_limited`, or `null` to go on.
     */
    const reserveRegistrationStart = async (): Promise<RoundResult | null> => {
      const { limits } = hooks;
      if (limits?.reserveRegistrationStart === undefined) return null;
      const reserve = limits.reserveRegistrationStart.bind(limits);
      const verdict = await fromStore('limits', () =>
        reserve({
          realmId,
          clientId,
          environment,
          ...(context.endUserIp === undefined ? {} : { endUserIp: context.endUserIp }),
        })
      );
      if (verdict?.kind === 'throttled') {
        await audit('refused', 'email_code', 'rate_limited');
        return throttled(Math.max(1, Math.ceil(verdict.retryAfterSeconds)));
      }
      if (verdict?.kind !== 'continue') {
        throw new SignInStoreUnavailableError('limits', new Error('not a limit verdict'));
      }
      return null;
    };

    /** The reset gate's verdict (#642): a value that is not a boolean is a store fault. */
    const resetAllowed = async (resets: AccountResets): Promise<boolean> => {
      const allowed: unknown = await fromStore('resets', () =>
        resets.allowed({ realmId, clientId })
      );
      if (typeof allowed !== 'boolean') {
        throw new SignInStoreUnavailableError('resets', new Error('not a gate verdict'));
      }
      return allowed;
    };

    /**
     * Whether this round's password step offers a reset beside the password
     * (#642; ADR-017 Decision 8): the engine holds the reset's ports, the
     * transport serves its steps, the request asks for no fresh sign-in, and
     * the client may reset. Nothing of the account decides it.
     */
    const resetOffered = async (): Promise<boolean> => {
      const { resets } = deps;
      if (resets === undefined || emailCodes === undefined || deps.passwordUpdates === undefined) {
        return false;
      }
      if (!RESET_STEPS.every((step) => served.has(step)) || context.freshSignIn === true) {
        return false;
      }
      return resetAllowed(resets);
    };

    /**
     * Turn the sign-in into a reset (#642): the answer to the
     * `password_reset` step its password step offered. The address it brings,
     * if any, must be the one the transaction holds; a provider this sign-in
     * went out to may no longer complete it. The reset's rounds go on at once.
     */
    const startReset = async (offer: StepOffer): Promise<RoundResult> => {
      const before = state.transaction;
      const read = readPending(offer);
      if (read === null) return invalidAnswer('password_reset');
      turn.pending = null;
      const hint = (read.answer as StepAnswer<'password_reset'>).login_hint;
      if (hint !== undefined) {
        const brought = readIdentifier(hint);
        if (brought === null) return invalidAnswer('password_reset');
        if (brought !== state.transaction.identifier)
          return ended('password_reset', 'subject_mismatch');
      }
      state.transaction = { ...state.transaction, upstream: undefined, flow: 'reset' };
      return recover(before);
    };

    /**
     * A reset's rounds (#642; ADR-017 Decision 8;
     * `graphs/flows/core/password-reset/flow.yaml`), once its gate let the
     * round through. `before` is the transaction as the round found it, which
     * a round that fails before its start is recorded keeps.
     *
     * 1. The address: the `password_reset` step alone while the transaction
     *    holds none, its answer's `login_hint` the address. The start is
     *    recorded among the verified steps, so the transaction's `amr` is
     *    none.
     * 2. The mailbox: an 8-digit `recovery` code, the same step for every
     *    address. Only an enabled account with a password is mailed; for any
     *    other address a right code is answered exactly as a wrong one, so
     *    nothing of a disabled user changes. A right code fixes the account.
     * 3. Any other authenticator the account holds, a disabled one included:
     *    proved before a new password, never an email code in its place. With
     *    none the transport can serve, the person goes on elsewhere (on the
     *    hosted pages, a recovery code once F2c adds them).
     * 4. `new_password` with the purpose `reset`: the realm's password policy
     *    and its breach list. Once it passes, {@link AccountResets.reset}
     *    replaces the password and ends what the old one opened.
     *
     * It completes with no `amr` and no `auth_time` (ADR-017 Decision 10).
     */
    const recover = async (before: SignInTransaction): Promise<RoundResult> => {
      const { resets, passwordUpdates: updates } = deps;
      if (resets === undefined || emailCodes === undefined || updates === undefined) {
        throw new Error('sign-in engine: a reset without its dependencies');
      }
      const { identifier } = state.transaction;
      if (identifier === undefined) {
        // The start was answered with no address: malformed.
        if (turn.pending?.name === 'password_reset') return invalidAnswer('password_reset');
        return offerStep(await offerOf([RESET_START]));
      }
      if (!state.transaction.verified.some((step) => step.step === 'password_reset')) {
        // The start is recorded together with its audit record: a round that
        // fails before the record is written keeps the transaction it found.
        try {
          if (turn.pending?.name === 'password_reset') {
            // The start was the step asked for: its answer is read by the
            // grammar like any other.
            const read = readPending(await offerOf([RESET_START]));
            if (read === null) {
              state.transaction = before;
              return await invalidAnswer('password_reset');
            }
            turn.pending = null;
          }
          state.transaction = {
            ...state.transaction,
            verified: [
              ...state.transaction.verified,
              { step: 'password_reset', params: {} } as OfferedStep,
            ],
          };
          await audit('passed', 'password_reset');
        } catch (error) {
          state.transaction = before;
          throw error;
        }
      }
      // The same address again: nothing more to do with that answer.
      if (turn.pending?.name === 'password_reset') turn.pending = null;

      const readCandidate = () =>
        fromStore('accounts', () => deps.accounts.findByIdentifier(realmId, identifier));
      /**
       * Whether `candidate` is mailed and reset: an enabled account with a
       * password whose address was proved. An unclaimed account (an address
       * never proved, ADR-017 Decision 8) is not: a reset would keep a `sub`
       * someone other than the mailbox owner may have created, until #641
       * ends such an account at this proof.
       */
      const resettable = (candidate: SignInCandidate | null): candidate is SignInCandidate =>
        candidate !== null &&
        candidate.enabled &&
        candidate.verified &&
        candidate.password !== null;
      if (!provedMailbox()) {
        const taken: { candidate: SignInCandidate | null } = { candidate: null };
        const answered = await codeRound(emailCodes, {
          purpose: RECOVERY,
          length: emailCodeLength(RECOVERY, { afterPassword: false }),
          address: identifier,
          afterFirstFactor: false,
          reset: async () => (resettable(await readCandidate()) ? 'account' : 'withheld'),
          refuses: async () => {
            taken.candidate = await readCandidate();
            const { candidate } = taken;
            if (candidate === null || candidate.password === null) return 'invalid_credentials';
            if (!candidate.enabled) return 'account_disabled';
            return candidate.verified ? null : 'account_unclaimed';
          },
        });
        if ('result' in answered) return answered.result;
        const { candidate } = taken;
        if (!resettable(candidate))
          throw new Error('sign-in engine: a reset code taken for nobody');
        state.transaction = { ...state.transaction, subject: candidate.userId };
        await codeTaken(answered.params);
      }

      const subject = state.transaction.subject;
      if (subject === undefined) throw new Error('sign-in engine: a reset without its account');
      /** The account again, every factor included; the round's end when it is gone or disabled. */
      const readResetAccount = async (): Promise<SignInAccount | RoundResult> => {
        const read = await fromStore('accounts', () =>
          deps.accounts.findByUserId(realmId, subject)
        );
        if (read === null || read.userId !== subject) {
          return ended('password_reset', 'subject_mismatch');
        }
        if (!read.enabled) return ended('password_reset', 'account_disabled');
        return read;
      };
      const isAccount = (value: SignInAccount | RoundResult): value is SignInAccount =>
        'factors' in value;
      const account = await readResetAccount();
      if (!isAccount(account)) return account;
      // Any other authenticator the account holds is proved first: an email
      // code never stands in for one (ADR-017 Decision 8). A disabled one
      // still counts as bound, and with no usable one the reset cannot go on
      // here.
      if (boundBeyondPassword(account) && !provedBeyondPassword()) {
        const verifiedSteps = new Set(state.transaction.verified.map((step) => step.step));
        const needed = [...handlers.secondFactors, ...handlers.firstFactors].filter(
          (handler) =>
            served.has(handler.step) &&
            !verifiedSteps.has(handler.step) &&
            handler.factor !== undefined &&
            handler.factor !== 'password' &&
            (handler.usableBy?.(account) ?? false)
        );
        if (needed.length === 0) return redirect('step_not_available');
        const offer = await offerOf(needed);
        if (!answers(offer)) return offerStep(offer);
        const result = await verifyPending(offer);
        if (result !== null) return result;
        const reread = await readResetAccount();
        if (!isAccount(reread)) return reread;
      }

      const written: { epoch?: number } = {};
      const asked = await askNewPassword(
        updates,
        identifier,
        'reset',
        async (password, normalization) => {
          const outcome = await fromStore('resets', () =>
            resets.reset({
              realmId,
              clientId,
              userId: subject,
              identifier,
              password,
              normalization,
            })
          );
          if (outcome?.kind === 'reset') {
            written.epoch = outcome.epoch;
            return null;
          }
          const reason = outcome?.kind === 'refused' ? outcome.reason : undefined;
          if (reason !== 'account_disabled' && reason !== 'subject_mismatch') {
            throw new SignInStoreUnavailableError('resets', new Error('not a reset'));
          }
          return ended('new_password', reason);
        }
      );
      if (asked !== null) return asked;
      const { epoch } = written;
      if (epoch === undefined) throw new Error('sign-in engine: a reset completed unwritten');
      return Object.freeze({
        kind: 'complete',
        transaction: null,
        signIn: Object.freeze({ subject, identifier, recovered: true as const, epoch }),
      });
    };

    // A transaction that proved an account before that account's last reset
    // ends (#642; ADR-017 Decision 8): the reset ended whatever the old
    // password opened, a browser session and a transaction alike.
    const { sessionEpochs } = deps;
    if (sessionEpochs !== undefined && state.transaction.subject !== undefined) {
      const userId = state.transaction.subject;
      const notBefore = await fromStore('sessionEpochs', async () => {
        const value: unknown = await sessionEpochs.notBefore({ realmId, userId });
        if (value !== null && (typeof value !== 'number' || !Number.isFinite(value) || value < 0)) {
          throw new Error('not a session epoch');
        }
        return value;
      });
      if (notBefore !== null && state.transaction.createdAt <= notBefore) {
        return ended(roundStep(), 'reset_since');
      }
    }

    // Rule 8's input, read on every round and never kept: a policy that
    // cannot be read refuses the round (ADR-017 Decision 4).
    const policy = checkedPolicy(
      await fromStore('policy', () => deps.policy.read({ realmId, clientId }))
    );

    const hookRound: HookRound = Object.freeze({
      realmId,
      clientId,
      transaction: found,
      ...(turn.pending === null ? {} : { answered: turn.pending.name }),
      ...(context.endUserIp === undefined ? {} : { endUserIp: context.endUserIp }),
      environment,
    });

    // Rule 3: the limiters, on every round (#636). A soft threshold that
    // holds asks for a bot challenge at rule 5 (#643).
    const { limits, request, botChallenge } = hooks;
    let limitsSoft = false;
    if (limits !== undefined) {
      const verdict = await fromStore('limits', () => limits.round(hookRound));
      if (verdict?.kind === 'throttled') {
        await audit('refused', roundStep(), 'rate_limited');
        return throttled(Math.max(1, Math.ceil(verdict.retryAfterSeconds)));
      }
      if (verdict?.kind !== 'continue') {
        throw new SignInStoreUnavailableError('limits', new Error('not a limit verdict'));
      }
      limitsSoft = verdict.softThreshold === true;
    }

    // Rule 4: the transport's request checks.
    if (request !== undefined) {
      const verdict = await fromStore('request', () => request(hookRound));
      if (verdict.kind === 'refuse') {
        await audit('refused', roundStep(), 'request_refused');
        return Object.freeze({
          kind: 'refused',
          reason: 'request_refused',
          code: verdict.code,
          transaction: found,
        });
      }
      if (verdict.kind === 'redirect') return redirect('request');
    }

    // Rule 4, for a registration (#640; ADR-017 Decision 8): the realm and
    // the client must both allow it, on every round, before anything is
    // mailed or written. A transport or an engine that cannot serve its steps
    // sends the person elsewhere.
    if (registering) {
      const { registrations } = deps;
      if (
        registrations === undefined ||
        emailCodes === undefined ||
        deps.passwordUpdates === undefined ||
        !REGISTRATION_STEPS.every((step) => served.has(step))
      ) {
        return redirect('step_not_available');
      }
      const allowed: unknown = await fromStore('registrations', () =>
        registrations.allowed({ realmId, clientId })
      );
      if (allowed !== true) {
        if (allowed !== false) {
          throw new SignInStoreUnavailableError('registrations', new Error('not a gate verdict'));
        }
        await audit('refused', roundStep(), 'registration_closed');
        return Object.freeze({
          kind: 'refused',
          reason: 'request_refused',
          code: REGISTRATION_NOT_ALLOWED,
          transaction: freezeTransaction(state.transaction),
        });
      }
    }

    // Rule 4, for a reset (#642; ADR-017 Decision 8): the client must allow
    // it, on every round, before anything is mailed or written. A request
    // that asks for a fresh sign-in is never reset: a reset proves no
    // authenticator. A transport or an engine that cannot serve its steps
    // sends the person elsewhere.
    if (resetting) {
      const { resets } = deps;
      if (
        resets === undefined ||
        emailCodes === undefined ||
        deps.passwordUpdates === undefined ||
        !RESET_STEPS.every((step) => served.has(step))
      ) {
        return redirect('step_not_available');
      }
      if (context.freshSignIn === true) return redirect('request');
      if (!(await resetAllowed(resets))) {
        await audit('refused', roundStep(), 'reset_closed');
        return Object.freeze({
          kind: 'refused',
          reason: 'request_refused',
          code: RESET_NOT_ALLOWED,
          transaction: freezeTransaction(state.transaction),
        });
      }
    }

    // Rule 5: the bot challenge (PRO-19, #643; ADR-017 Decisions 4 and 7).
    // A due challenge comes before every other step; any other answer is
    // ignored, so no password is checked and no code mailed while one is due.

    /**
     * The identifier this round is for, before rule 6 fixes it: the
     * transaction's, else the request's `login_hint`, else the one the
     * pending answer brings (a password answer that names its account). Only
     * the ladder's soft threshold reads it; rule 6 still decides which one the
     * transaction holds, and ends one that brings another.
     */
    const roundIdentifier = (): string | undefined => {
      if (state.transaction.identifier !== undefined) return state.transaction.identifier;
      if (context.loginHint !== undefined) {
        const identifier = readIdentifier(context.loginHint);
        if (identifier !== null) return identifier;
      }
      const { pending } = turn;
      const steps = resetting ? RESET_STEPS_WITH_LOGIN_HINT : STEPS_WITH_LOGIN_HINT;
      if (pending === null || !steps.has(pending.name)) return undefined;
      const fields = pending.answer.fields;
      if (!isRecord(fields) || !Object.hasOwn(fields, 'login_hint')) return undefined;
      return readIdentifier(fields['login_hint']) ?? undefined;
    };
    /** Whether the round's identifier is past its ladder's free failures (PRO-12). */
    const ladderSoft = async (): Promise<boolean> => {
      const peek = hooks.ladder;
      if (peek?.softThreshold === undefined) return false;
      const identifier = roundIdentifier();
      if (identifier === undefined) return false;
      const digest =
        identifier === state.transaction.identifier
          ? await identifierHmac()
          : await digestOf(identifier);
      const soft: unknown = await fromStore('ladder', () =>
        peek.softThreshold?.({
          realmId,
          identifierHmac: digest,
          counters: CHALLENGE_LADDER_COUNTERS,
        })
      );
      if (typeof soft !== 'boolean') {
        throw new SignInStoreUnavailableError('ladder', new Error('not a soft threshold'));
      }
      return soft;
    };
    /**
     * Whether a registration still owes its challenge (#643): the realm or
     * the client requires one, and this transaction has passed none.
     */
    const registrationOwesChallenge = async (): Promise<boolean> => {
      const { registrations } = deps;
      if (!registering || registrations?.challengeRequired === undefined) return false;
      if (state.transaction.verified.some((step) => step.step === 'captcha')) return false;
      const required: unknown = await fromStore('registrations', () =>
        registrations.challengeRequired?.({ realmId, clientId })
      );
      if (typeof required !== 'boolean') {
        throw new SignInStoreUnavailableError('registrations', new Error('not a requirement'));
      }
      return required;
    };
    /**
     * Why a challenge is due this round, if one is: a registration that owes
     * one, or, while the transaction holds no unspent pass, a soft threshold
     * of the limiters or of the ladder, or the deployment's own hook.
     */
    const challengeDue = async (): Promise<'registration' | 'threshold' | null> => {
      if (await registrationOwesChallenge()) return 'registration';
      if (state.transaction.captchaPassed === true) return null;
      if (limitsSoft || (await ladderSoft())) return 'threshold';
      if (botChallenge === undefined) return null;
      const verdict = await fromStore('botChallenge', () => botChallenge(hookRound));
      if (verdict?.kind === 'due') return 'threshold';
      if (verdict?.kind !== 'not_due') {
        throw new SignInStoreUnavailableError('botChallenge', new Error('not a verdict'));
      }
      return null;
    };
    /**
     * The challenge's offer: the one the transaction holds, or a new one from
     * `handler`, kept in the transaction so its answer is read against what
     * was offered. Offered alone: the pending step resumes after it.
     */
    const challengeOffer = async (handler: AnyStepHandler): Promise<StepOffer> => {
      let params = state.transaction.captcha;
      if (params === undefined) {
        params = await fromStore('botChallenge', async () =>
          checkedChallengeParams(await handler.params(stepRound()))
        );
        state.transaction = { ...state.transaction, captcha: params };
      }
      return Object.freeze({
        current: Object.freeze({ step: 'captcha', params }),
        alternatives: Object.freeze([]),
      }) as StepOffer;
    };
    /**
     * A wrong answer to the challenge is a failed round of the limiters
     * (ADR-017 Decision 7): counted on the end-user IP, its bucket and the
     * client as a wrong credential is, so a stream of wrong answers meets the
     * hard 429. Inside a delay or past a hard limit the row holds the source
     * back already, and nothing more is counted.
     */
    const countFailedChallenge = async (): Promise<void> => {
      if (limits === undefined) return;
      const verdict = await fromStore('limits', () =>
        limits.reserve({
          realmId,
          clientId,
          environment,
          ...(context.endUserIp === undefined ? {} : { endUserIp: context.endUserIp }),
        })
      );
      if (verdict?.kind === 'throttled') return;
      if (verdict?.kind !== 'reserved' || typeof verdict.settle !== 'function') {
        throw new SignInStoreUnavailableError('limits', new Error('not a reservation'));
      }
      await settleRound(verdict, 'failure');
    };
    /**
     * The challenge's round: its offer, or the answer to it. A right answer
     * leaves a pass the next credential round spends, and the rules go on
     * (`null`); a wrong one is refused with `captcha_failed` and a new
     * challenge. Either way the challenge it answered is gone.
     */
    const challengeRound = async (handler: AnyStepHandler): Promise<RoundResult | null> => {
      const offer = await challengeOffer(handler);
      if (turn.pending?.name !== 'captcha') return offerStep(offer);
      const read = readPending(offer);
      if (read === null) return invalidAnswer('captcha');
      turn.pending = null;
      state.transaction = { ...state.transaction, captcha: undefined };
      const verdict: StepVerdict = await (handler as StepHandler).verify(stepRound(), {
        params: read.params,
        answer: read.answer,
      });
      if (verdict.kind === 'passed') {
        const { verified } = state.transaction;
        state.transaction = {
          ...state.transaction,
          captchaPassed: true,
          // One record of a passed challenge is enough: the list stays short.
          verified: verified.some((step) => step.step === 'captcha')
            ? verified
            : [...verified, { step: 'captcha', params: read.params } as OfferedStep],
        };
        await audit('passed', 'captcha');
        return null;
      }
      if (verdict.kind !== 'refused') {
        throw new Error(`sign-in engine: the captcha step answered ${verdict.kind}`);
      }
      await countFailedChallenge();
      await audit('refused', 'captcha', verdict.audit.reason);
      return offerStep(await challengeOffer(handler), verdict.error);
    };

    const due = await challengeDue();
    if (due !== null) {
      if (served.has('captcha')) {
        // No provider: a due challenge refuses the round, never passes it.
        const handler = handlers.challenge;
        if (handler === undefined) {
          throw new SignInStoreUnavailableError('botChallenge', new Error('no provider'));
        }
        const result = await challengeRound(handler);
        if (result !== null) return result;
      } else if (due === 'registration') {
        // A client that cannot answer the challenge its registration
        // requires: never sent to a browser in its place (ADR-017 Decision 7).
        await audit('refused', roundStep(), 'registration_closed');
        return Object.freeze({
          kind: 'refused',
          reason: 'request_refused',
          code: REGISTRATION_NOT_ALLOWED,
          transaction: freezeTransaction(state.transaction),
        });
      }
      // A client that did not list `captcha`, under a soft threshold: the
      // delay and the hard 429 of rules 3 and 7 alone (ADR-017 Decision 7).
    }

    // An upstream provider's callback (#639): it completes the step this
    // transaction sent the person to, while nobody is named, and the rules
    // go on from rule 8, as after any first factor.
    const { proof } = upstreamRound;
    if (proof !== undefined) {
      const refused = await proveUpstream(proof);
      if (refused !== null) return refused;
    }

    // Rule 6: the identifier. The request's login_hint first, then an
    // answer's; the first is fixed, and a different one ends the transaction.
    const brought: { readonly identifier: string; readonly step: StepName }[] = [];
    if (context.loginHint !== undefined) {
      const identifier = readIdentifier(context.loginHint);
      if (identifier !== null) brought.push({ identifier, step: 'identifier' });
    }
    // A reset's address comes with its start alone (#642).
    const loginHintSteps = resetting ? RESET_STEPS_WITH_LOGIN_HINT : STEPS_WITH_LOGIN_HINT;
    if (turn.pending !== null && loginHintSteps.has(turn.pending.name)) {
      const fields = turn.pending.answer.fields;
      if (isRecord(fields) && Object.hasOwn(fields, 'login_hint')) {
        const identifier = readIdentifier(fields['login_hint']);
        if (identifier === null) return invalidAnswer(turn.pending.name);
        brought.push({ identifier, step: turn.pending.name });
      } else if (turn.pending.name === 'identifier') {
        return invalidAnswer('identifier');
      }
    }
    const beforeIdentifier = state.transaction;
    const heldBefore = beforeIdentifier.identifier;
    /**
     * End on a mismatch. The record names the identifier this round brought
     * first; if writing it fails, the round keeps no identifier, as below.
     */
    const mismatch = async (step: StepName): Promise<RoundResult> => {
      try {
        return await ended(step, 'subject_mismatch');
      } catch (error) {
        state.transaction = beforeIdentifier;
        throw error;
      }
    };
    for (const { identifier, step } of brought) {
      if (state.transaction.identifier === undefined) {
        // A discoverable factor fixed the subject without an identifier: one
        // brought now cannot be checked against it, so it ends the
        // transaction.
        if (state.transaction.subject !== undefined) return mismatch(step);
        state.transaction = { ...state.transaction, identifier };
      } else if (state.transaction.identifier !== identifier) {
        return mismatch(step);
      }
    }

    // A reset (#642): its own rounds, from its address to the new password.
    if (resetting) return recover(beforeIdentifier);

    if (state.transaction.subject === undefined) {
      if (state.transaction.identifier === undefined && registering) {
        // A registration asks for the address alone (#640): no factor, no
        // upstream provider.
        return offerStep(await offerOf([handlers.identifier]));
      }
      if (state.transaction.identifier === undefined) {
        // Nobody is named yet: the identifier step, the same for everyone, or
        // a discoverable first factor before it, with the identifier step and
        // the other first factors beside it (ADR-017 Decision 4); and the
        // realm's upstream providers after them (#639).
        const discoverable = handlers.discoverable.filter((handler) => served.has(handler.step));
        const others = handlers.firstFactors.filter(
          (handler) => handler.discoverable !== true && served.has(handler.step)
        );
        const upstreamOffered = await upstreamProviders();
        const upstreamStep: Offerable[] =
          upstreamOffered === null ? [] : [{ step: 'upstream', params: () => upstreamOffered }];
        // No discoverable factor is registered (this issue's shape): the
        // identifier step alone. One is registered, but this transport cannot
        // serve it: the password it can serve, with the identifier step
        // beside it (ADR-017 Decision 4, amended 2026-10-31). A password
        // offered beside a discoverable factor is answered with its
        // login_hint, which the identifier rule above has already taken.
        const firstSteps: Offerable[] =
          discoverable.length === 0
            ? handlers.discoverable.length === 0
              ? [handlers.identifier]
              : [...others, handlers.identifier]
            : [...discoverable, ...others, handlers.identifier];
        const offer = await offerOf([...firstSteps, ...upstreamStep], { preferred: true });
        const pendingName = turn.pending?.name;
        // The authorization request routes to a provider (#639): at round 0,
        // with no answer, it starts at once. The way back is this offer.
        const { upstreamRoute } = context;
        if (upstreamRound.fresh && turn.pending === null && upstreamRoute !== undefined) {
          return pickUpstream(offer, upstreamRoute);
        }
        if (upstreamOffered !== null && pendingName === 'upstream') return pickUpstream(offer);
        if (!discoverable.some((handler) => handler.step === pendingName)) return offerStep(offer);
        const result = await verifyPending(offer);
        if (result !== null) return result;
      } else {
        if (heldBefore === undefined) {
          // The identifier is fixed together with its audit record: a round
          // that fails before the record is written keeps no identifier, so
          // the next round records it.
          try {
            if (turn.pending?.name === 'identifier') {
              // The identifier step was the one asked for: its answer is read
              // by the grammar like any other, and its handler confirms it.
              const offer = await offerOf([handlers.identifier]);
              const read = readPending(offer);
              if (read === null) {
                state.transaction = beforeIdentifier;
                return await invalidAnswer('identifier');
              }
              turn.pending = null;
              const verdict = await handlers.identifier.verify(stepRound(), {
                params: {},
                answer: read.answer as { login_hint: string },
              });
              if (
                verdict.kind !== 'identified' ||
                verdict.identifier !== state.transaction.identifier
              ) {
                throw new Error(
                  'sign-in engine: the identifier step disagrees with the identifier'
                );
              }
            }
            await audit('passed', 'identifier');
          } catch (error) {
            state.transaction = beforeIdentifier;
            throw error;
          }
        }
        // The same identifier again: nothing more to do with that answer.
        if (turn.pending?.name === 'identifier') turn.pending = null;

        // A registration (#640): the mailbox, then the password, then the
        // account; or, for an address an account holds, rule 7.
        if (registering) {
          const identifier = state.transaction.identifier;
          if (identifier === undefined) throw new Error('sign-in engine: no address to register');
          const result = await register(identifier);
          if (result !== null) return result;
        }

        // Rule 7: the first factor, offered alike to every account until one
        // succeeds. Only an answer to it is verified; any other is ignored.
        const firstFactors = handlers.firstFactors.filter((handler) => served.has(handler.step));
        if (firstFactors.length === 0) return redirect('step_not_available');
        // The owner's reset beside it (#642), the same for every account: a
        // registration helped to sign in is offered none.
        const withReset = !registering && (await resetOffered());
        const offer = await offerOf(withReset ? [...firstFactors, RESET_START] : firstFactors);
        if (withReset && turn.pending?.name === 'password_reset') return startReset(offer);
        if (!answers(offer)) return offerStep(offer);
        const result = await verifyPending(offer);
        if (result !== null) return result;
      }
    }

    // Rule 8: after a first factor. The account is read again, every factor
    // included, now that a factor proved it.
    const subject = state.transaction.subject;
    if (subject === undefined) throw new Error('sign-in engine: rule 8 without a subject');
    const readAccount = (): Promise<SignInAccount | null> =>
      fromStore('accounts', async () => {
        const read = await deps.accounts.findByUserId(realmId, subject);
        // A directory that reads no required actions could let an owed
        // update pass: a store fault, never an empty list.
        if (read !== null && !Array.isArray(read.requiredActions)) {
          throw new Error('an account without its required actions');
        }
        return read;
      });
    const provenAccount = await readAccount();
    if (provenAccount === null || provenAccount.userId !== subject)
      return ended('identifier', 'subject_mismatch');
    if (!provenAccount.enabled) return ended('identifier', 'account_disabled');
    let account: SignInAccount = provenAccount;
    // An `update_password` this transaction saw stays owed to it (#635):
    // another sign-in that sets a new password, and so removes the action,
    // never releases this one, which proved only the old password.
    if (
      provenAccount.requiredActions.includes('update_password') &&
      state.transaction.updatePasswordRequired !== true &&
      !state.transaction.verified.some((step) => step.step === 'new_password')
    ) {
      state.transaction = { ...state.transaction, updatePasswordRequired: true };
    }
    // A registration for an address an account holds (#640): its mailbox was
    // proved before its password, so the same person proved both, and an
    // address not verified yet is verified now, as the inline verification
    // would after the password (ADR-017 Decision 8).
    if (registering && !account.verified && provedMailbox() && emailCodes !== undefined) {
      const { identifier } = state.transaction;
      if (identifier === undefined)
        throw new Error('sign-in engine: a registration without its address');
      const marked = await fromStore('addresses', () =>
        emailCodes.addresses.markVerified({ realmId, userId: subject, identifier })
      );
      if (marked?.kind !== 'verified') {
        const reason = marked?.kind === 'refused' ? marked.reason : undefined;
        if (reason !== 'account_disabled' && reason !== 'subject_mismatch') {
          throw new SignInStoreUnavailableError('addresses', new Error('not a verification'));
        }
        return ended('email_code', reason);
      }
      account = { ...account, verified: true };
    }
    // An address this transaction has still to verify: the account's is not
    // proved, and no code of this transaction proved it.
    const addressPending = (current: SignInAccount): boolean =>
      !current.verified && !state.transaction.verified.some((step) => step.step === 'email_code');
    /** Whether this transaction set a new password: the forced update is done. */
    const passwordUpdated = (): boolean =>
      state.transaction.verified.some((step) => step.step === 'new_password');
    /**
     * Whether the sign-in must set a new password before it completes
     * (#635): the password it proved is on the realm's breach list, or the
     * account holds an `update_password` required action; and the account
     * has a password to replace.
     */
    const updateDue = (current: SignInAccount): boolean =>
      !passwordUpdated() &&
      (state.transaction.breachedPassword === true ||
        state.transaction.updatePasswordRequired === true ||
        current.requiredActions.includes('update_password')) &&
      current.factors.some((factor) => factor.type === 'password');
    /**
     * The forced password update (#635; ADR-017 Decision 4, rule 8, decided
     * 2026-10-23), once every factor the sign-in needs is proved. The
     * password alone never sets a new one: an account with a factor beyond
     * it proved that factor in the loop above; an account whose only factor
     * is its password proves its mailbox first, with an 8-digit code as a
     * reset asks, unless a code this transaction took for that mailbox (its
     * inline verification) already did. A transport that cannot serve the
     * steps, an engine built without them, and a transaction with no
     * identifier to name the password are answered with a redirect: the
     * sign-in never completes while an update is due.
     */
    const forcedUpdate = async (
      current: SignInAccount,
      subject: string
    ): Promise<RoundResult | null> => {
      const updates = deps.passwordUpdates;
      const { identifier } = state.transaction;
      if (updates === undefined || identifier === undefined || !served.has('new_password')) {
        return redirect('step_not_available');
      }
      if (boundBeyondPassword(current)) {
        if (!provedBeyondPassword()) {
          throw new Error('sign-in engine: a forced update before the factor beyond the password');
        }
      } else if (!provedMailbox()) {
        if (emailCodes === undefined) return redirect('step_not_available');
        const result = await verifyAddress(emailCodes, subject, RECOVERY);
        if (result !== null) return result;
      }
      return askNewPassword(
        updates,
        identifier,
        'update_required',
        async (password, normalization) => {
          const replaced = await fromStore('passwordUpdates', () =>
            updates.replace({ realmId, userId: subject, identifier, password, normalization })
          );
          if (replaced?.kind === 'replaced') return null;
          const reason = replaced?.kind === 'refused' ? replaced.reason : undefined;
          if (reason !== 'account_disabled' && reason !== 'subject_mismatch') {
            throw new SignInStoreUnavailableError(
              'passwordUpdates',
              new Error('not a replacement')
            );
          }
          return ended('new_password', reason);
        }
      );
    };

    for (;;) {
      const current: SignInAccount = account;
      const verifiedSteps = new Set(state.transaction.verified.map((step) => step.step));
      const candidate = (handler: AnyStepHandler) =>
        served.has(handler.step) &&
        !verifiedSteps.has(handler.step) &&
        (handler.usableBy?.(current) ?? false);
      let needed: AnyStepHandler[] | null = null;
      const strongest = strongestBoundFactor(current);
      if (provenFactorStrength(state.transaction.verified, factorOf) < strongest) {
        // The downgrade rule: only a factor as strong as the strongest bound
        // one, a disabled one included, completes the sign-in.
        needed = handlers.firstFactors.filter(
          (handler) => candidate(handler) && factorStrength(handler.factor) >= strongest
        );
      } else if (secondFactorRequired(policy, current) && !provesMfa(state.transaction.verified)) {
        // The MFA policy: the transaction's amr must carry mfa.
        needed = [...handlers.secondFactors, ...handlers.firstFactors].filter(candidate);
        // An account that lacks the factor gets the set-up step, below, never
        // a code. One that has it verifies its address first: rule 8 asks for
        // the verification before the second factor (ADR-017 Decision 4).
        if (needed.length > 0 && emailCodes !== undefined && addressPending(current)) {
          const result = await verifyAddress(emailCodes, subject, VERIFY_ACCOUNT);
          if (result !== null) return result;
        }
      } else if (updateDue(current) && boundBeyondPassword(current) && !provedBeyondPassword()) {
        // The forced update (#635): an account with a factor beyond its
        // password proves it first, so a person who knows only the password,
        // a listed one above all, sets no new one (ADR-017 Decision 4, rule
        // 8). An email code never stands in for that factor; a disabled one
        // still counts as bound, and with no usable one the sign-in cannot
        // go on here.
        needed = [...handlers.secondFactors, ...handlers.firstFactors].filter(
          (handler) =>
            candidate(handler) && handler.factor !== undefined && handler.factor !== 'password'
        );
        if (needed.length > 0 && emailCodes !== undefined && addressPending(current)) {
          const result = await verifyAddress(emailCodes, subject, VERIFY_ACCOUNT);
          if (result !== null) return result;
        }
      }
      if (needed === null) break;
      // No step can meet the rule yet, or the transport cannot serve one.
      if (needed.length === 0) return redirect('step_not_available');
      const offer = await offerOf(needed);
      if (!answers(offer)) return offerStep(offer);
      const result = await verifyPending(offer);
      if (result !== null) return result;
      const reread = await readAccount();
      if (reread === null || reread.userId !== subject)
        return ended('identifier', 'subject_mismatch');
      if (!reread.enabled) return ended('identifier', 'account_disabled');
      account = reread;
    }

    // Rule 8: an address not proved yet is verified inline with an emailed
    // code, whatever REQUIRE_VERIFIED_ACCOUNT says (ADR-017 Decision 8). Here
    // when no second factor is asked for; an account the MFA policy needs one
    // of verified it before that factor, above, or was redirected to the
    // set-up step: never a code in its place.
    if (emailCodes !== undefined && addressPending(account)) {
      const result = await verifyAddress(emailCodes, subject, VERIFY_ACCOUNT);
      if (result !== null) return result;
    }

    // Rule 8: the forced password update (#635), after every factor the
    // sign-in needs and the address verified, before any session or code.
    if (updateDue(account)) {
      const result = await forcedUpdate(account, subject);
      if (result !== null) return result;
    }

    // Rule 9: complete. The transport mints the session or the code, and the
    // transaction ends with it. An upstream sign-in adds no `amr` value
    // (ADR-017 Decision 10): alone, it completes with none.
    const amr =
      transactionAmr(state.transaction.verified) ??
      (state.transaction.verified.some((step) => step.step === 'upstream') ? [] : undefined);
    const { authTime, identifier } = state.transaction;
    if (amr === undefined || authTime === undefined) {
      throw new Error('sign-in engine: complete without a factor');
    }
    return Object.freeze({
      kind: 'complete',
      transaction: null,
      signIn: Object.freeze({
        subject,
        ...(identifier === undefined ? {} : { identifier }),
        amr,
        authTime,
      }),
    });
  }

  return Object.freeze({ advance, completeUpstream });
}
