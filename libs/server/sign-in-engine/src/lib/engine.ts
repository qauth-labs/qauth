import {
  createInteractionMapper,
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
  transactionAmr,
} from '@qauth-labs/server-step-grammar';

import {
  answerEmailCode,
  EMAIL_CODE_HMAC_PATTERN,
  EMAIL_CODE_TTL_MS,
  emailCodeExpired,
  emailCodeLength,
  emailCodeParams,
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
import { type HookRound, type LadderReservation, NO_LADDER, type SignInHooks } from './hooks';
import { readIdentifier } from './identifier';
import {
  type AccountDirectory,
  type AddressVerifier,
  type Clock,
  type EmailCodeDigest,
  type IdentifierDigest,
  MFA_MODES,
  type MfaPolicy,
  type MfaPolicyReader,
  NO_HARD_ACTION,
  type PasswordHardAction,
  type PasswordVerifier,
  type SignInAccount,
  type SignInAuditReason,
  type SignInAuditRecord,
  SYSTEM_CLOCK,
} from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import type {
  AnyStepHandler,
  ProvedAccount,
  StepHandler,
  StepRound,
  StepVerdict,
} from './steps/handler';
import { createIdentifierStep } from './steps/identifier';
import { createPasswordStep } from './steps/password';
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
 *    then the limiters' hook.
 * 4. The transport's request checks' hook.
 * 5. The bot challenge's hook: a due challenge comes before every other step.
 * 6. The identifier: the request's `login_hint`, else an answer's. The first
 *    one is fixed; a different one ends the transaction (`subject_mismatch`).
 *    With none, the identifier step, or a discoverable first factor before it
 *    once #651 adds one.
 * 7. The first factor, offered alike to every account: the password here, and
 *    from #651 a passkey beside it. Its answer is reserved on the ladder's hook
 *    before it is verified.
 * 8. After a first factor: the downgrade rule (the account's strongest bound
 *    factor, a disabled one included), then the MFA policy just read, then,
 *    with `emailCodes`, the inline verification of an address not proved yet
 *    (#638): an emailed code, never a factor, whatever
 *    `REQUIRE_VERIFIED_ACCOUNT` says. An account that lacks the second
 *    factor the policy requires gets the set-up step first, never a code.
 * 9. Complete: the transport mints the session or the code.
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
}

/**
 * The steps whose answer may carry the identifier: the identifier step, and
 * the password step for a page that asks for both at once. An answer to any
 * other step the engine did not ask for is ignored, its `login_hint` too.
 */
const STEPS_WITH_LOGIN_HINT: ReadonlySet<StepName> = new Set<StepName>(['identifier', 'password']);

/** An identifier HMAC: HMAC-SHA-256, base64url without padding. */
const IDENTIFIER_HMAC_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const TRANSACTION_ENDED: RoundResult = Object.freeze({
  kind: 'refused' as const,
  reason: 'transaction_ended' as const,
  transaction: null,
});

/** The steps no role may take: an email code is never an authenticator (ADR-017 Decision 5). */
const NEVER_A_FACTOR: readonly StepName[] = Object.freeze(['email_code']);

/**
 * An email code that verifies an account after its password: 6 digits
 * (ADR-017 Decision 5). The Interaction API never offers `confirm_sign_in`,
 * the FiPA endpoint's per-client check (PRO-22), and this engine offers it to
 * no transport yet.
 */
const VERIFY_ACCOUNT = 'verify_account' as const;
const VERIFY_ACCOUNT_LENGTH = emailCodeLength(VERIFY_ACCOUNT, { afterPassword: true });

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
  /** Whether the engine answers `step` itself: a handler's, or the email code of the inline verification. */
  const knows = (step: StepName) =>
    handlers.byStep.has(step) || (step === 'email_code' && emailCodes !== undefined);
  /** Report a failure that changes no answer: a reporter that throws changes nothing either. */
  const report = (port: string, error: unknown) => {
    try {
      deps.onUnavailable?.(new SignInStoreUnavailableError(port, error));
    } catch {
      // Nothing to do: the answer stands.
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

  /**
   * End a transaction the round may not use, before anything in it is read.
   * The record names nobody: nothing in such a transaction can be trusted to
   * name the person. It names the answered step when the engine has a
   * handler for it, else the identifier step, where every transaction starts.
   */
  async function endUnusable(
    answer: RoundAnswer | null,
    context: RoundContext,
    reason: 'transaction_invalid' | 'transaction_expired'
  ): Promise<RoundResult> {
    const named =
      answer !== null && typeof answer.step === 'string' ? stepNameOfUrn(answer.step) : undefined;
    const step = named !== undefined && knows(named) ? named : 'identifier';
    await context.audit(Object.freeze({ outcome: 'ended', step, reason }));
    return TRANSACTION_ENDED;
  }

  async function round(
    stored: SignInTransaction | null,
    answer: RoundAnswer | null,
    context: RoundContext
  ): Promise<RoundResult> {
    const now = clock.now();
    const found =
      stored === null
        ? newSignInTransaction({
            realmId: context.realm.id,
            clientId: context.client.id,
            createdAt: now,
          })
        : readSignInTransaction(stored);
    // A transaction that is not well formed ends: nothing in it can be trusted.
    if (found === null) return endUnusable(answer, context, 'transaction_invalid');
    // Nor can one of another realm or client, or one that starts in the future.
    if (
      found.realmId !== context.realm.id ||
      found.clientId !== context.client.id ||
      found.createdAt > now + SIGN_IN_TRANSACTION_CLOCK_SKEW_MS
    ) {
      return endUnusable(answer, context, 'transaction_invalid');
    }
    if (now - found.createdAt > SIGN_IN_TRANSACTION_MAX_AGE_MS) {
      return endUnusable(answer, context, 'transaction_expired');
    }
    // A subject without an identifier comes only from a discoverable factor.
    if (
      found.subject !== undefined &&
      found.identifier === undefined &&
      !found.verified.some((step) => handlers.byStep.get(step.step)?.discoverable === true)
    ) {
      return endUnusable(answer, context, 'transaction_invalid');
    }
    const state: RoundState = { transaction: found };
    try {
      return await rules(state, answer, context);
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
    context: RoundContext
  ): Promise<RoundResult> {
    const found = state.transaction;
    const realmId = context.realm.id;
    const clientId = context.client.id;
    const served = new Set<StepName>(context.serves ?? STEP_NAMES);
    const answeredName =
      answer !== null && typeof answer.step === 'string' ? stepNameOfUrn(answer.step) : undefined;
    /** The round's answer while no step has taken it. */
    const turn: { pending: { readonly name: StepName; readonly answer: RoundAnswer } | null } = {
      pending:
        answer !== null && answeredName !== undefined ? { name: answeredName, answer } : null,
    };

    let hmac: Promise<string> | undefined;
    const identifierHmac = (): Promise<string> => {
      const { identifier } = state.transaction;
      if (identifier === undefined) throw new Error('sign-in engine: no identifier to digest');
      hmac ??= fromStore('identifierDigest', async () => {
        const digest = await deps.identifierDigest({ realmId, identifier });
        if (typeof digest !== 'string' || !IDENTIFIER_HMAC_PATTERN.test(digest)) {
          throw new Error('not an identifier HMAC');
        }
        return digest;
      });
      return hmac;
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
      steps: readonly AnyStepHandler[],
      options: { readonly preferred?: boolean } = {}
    ): Promise<StepOffer> => {
      const current = stepRound();
      const offered = await Promise.all(
        steps.map(async (handler) => ({
          step: handler.step,
          params: await (handler as StepHandler).params(current),
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
      const { identifier } = state.transaction;
      // The email code's screen names the address the code went to.
      const personal =
        current.step === 'email_code'
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
      read: ReadAnswer
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
      };
      await audit('passed', read.step);
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
      const verdict: StepVerdict = await handler.verify(stepRound(), {
        params: read.params,
        answer: read.answer,
      });
      switch (verdict.kind) {
        case 'refused':
          return refuseAnswer(offer, read.step, verdict.error, verdict.audit.reason);
        case 'throttled':
          await audit('refused', read.step, verdict.audit.reason);
          return throttled(verdict.retryAfterSeconds);
        case 'proved':
          if (handler.role !== 'first_factor' && handler.role !== 'second_factor') {
            throw new Error(`sign-in engine: ${read.step} proved an account`);
          }
          return prove(offer, verdict.account, read);
        case 'passed':
          if (handler.role !== 'challenge') throw new Error(`sign-in engine: ${read.step} passed`);
          state.transaction = {
            ...state.transaction,
            verified: [
              ...state.transaction.verified,
              { step: read.step, params: read.params } as OfferedStep,
            ],
          };
          await audit('passed', read.step);
          return null;
        default:
          throw new Error(`sign-in engine: ${read.step} answered ${verdict.kind}`);
      }
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

    /**
     * The inline verification of the address the transaction's identifier
     * names, after a factor proved its account (#638; ADR-017 Decisions 5
     * and 8; `graphs/flows/core/account-verification/flow.yaml`). Returns the
     * round's result while the code is pending, or `null` once the address
     * is verified and the rules go on.
     *
     * - The first round mails a 6-digit code through the capped sender and
     *   offers `email_code` with `verify_account`; a cap that answers 429
     *   refuses the round, and nothing is held.
     * - An answer with no otp asks for a new code: one is mailed a minute
     *   after the last, and the transaction's count of wrong answers stays.
     * - An expired code is refused with `code_expired`, nothing compared or
     *   counted.
     * - Otherwise the answer is reserved on the email-code ladder (the
     *   identifier HMAC's `email_code` counter, across transactions), with no
     *   end-user IP: an account whose address is not proved has no owner
     *   whose IPs are known. Inside a wait it is refused, not compared.
     * - The code is compared HMAC to HMAC, in constant time. A wrong one is
     *   counted, and the 5th of the transaction burns the code and ends
     *   it. A right one clears the ladder's
     *   counter, marks the address verified, and is recorded among the
     *   verified steps: no `amr` value, no `auth_time`.
     */
    const verifyAddress = async (
      codes: EmailCodeDependencies,
      subject: string
    ): Promise<RoundResult | null> => {
      const { identifier } = state.transaction;
      // A subject a discoverable factor named holds no address to mail, and
      // a transport that cannot serve the step cannot take the code.
      if (identifier === undefined || !served.has('email_code')) {
        return redirect('step_not_available');
      }
      const { sendCode } = context;
      if (sendCode === undefined) {
        throw new Error('sign-in engine: no email-code sender for this round');
      }
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
        const issuedAt = clock.now();
        const code = generateEmailCode(VERIFY_ACCOUNT_LENGTH);
        const salt = generateEmailCodeSalt();
        const hmac = await digestCode(salt, code);
        const sent = await fromStore('sendCode', () =>
          sendCode({
            realmId,
            address: identifier,
            purpose: VERIFY_ACCOUNT,
            code,
            expiresInSeconds: EMAIL_CODE_TTL_MS / 1000,
            afterFirstFactor: true,
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
            purpose: VERIFY_ACCOUNT,
            length: VERIFY_ACCOUNT_LENGTH,
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
      // The round after the factor: the first code.
      if (held === undefined) return issueAndOffer();
      const at = clock.now();
      const offer = codeOffer(held, at);
      // An answer to another step is ignored, as every eager answer is; a
      // round with none asks for the code again.
      if (turn.pending?.name !== 'email_code') {
        return offerStep(offer, emailCodeExpired(held, at) ? 'code_expired' : undefined);
      }
      const read = readPending(offer);
      if (read === null) return invalidAnswer('email_code');
      turn.pending = null;
      const { otp } = read.answer as StepAnswer<'email_code'>;
      if (otp === undefined) {
        // A new code once one is due; before, the same step, nothing mailed.
        return emailCodeResendDue(held, at) ? issueAndOffer(held) : offerStep(offer);
      }
      if (emailCodeExpired(held, at)) {
        await audit('refused', 'email_code', 'code_expired');
        return offerStep(offer, 'code_expired');
      }
      // The ladder first: inside a wait nothing is compared or counted.
      const identifierDigest = await identifierHmac();
      const reservation = await fromStore('ladder', () =>
        ladder.reserve({ realmId, identifierHmac: identifierDigest, factor: 'email_code' })
      );
      if (reservation.kind === 'wait') {
        await audit('refused', 'email_code', 'locked_out');
        return throttled(reservation.retryAfterSeconds);
      }
      // A digest that fails leaves the attempt counted, as a store fault
      // after the password's reservation does.
      const presented = await digestCode(held.salt, otp);
      const answered = answerEmailCode(held, presented, at);
      switch (answered.kind) {
        case 'wrong':
          await settleCode(reservation, 'failure');
          state.transaction = { ...state.transaction, emailCode: answered.held };
          await audit('refused', 'email_code', 'invalid_code');
          return offerStep(codeOffer(answered.held, at), 'invalid_credentials');
        case 'burned':
          await settleCode(reservation, 'failure');
          state.transaction = { ...state.transaction, emailCode: undefined };
          return ended('email_code', 'code_burned');
        case 'accepted':
          break;
        default:
          // `at` is the one clock reading of both checks: an expired code
          // was refused above.
          throw new Error(`sign-in engine: an email code answered ${answered.kind}`);
      }
      // The right code clears the ladder's counter, whatever comes next.
      await settleCode(reservation, 'success');
      // The code is held until the address is written: a write that fails
      // refuses the round, and the same code may be answered again.
      const marked = await fromStore('addresses', () =>
        codes.addresses.markVerified({ realmId, userId: subject, identifier })
      );
      if (marked?.kind !== 'verified') {
        const reason = marked?.kind === 'refused' ? marked.reason : undefined;
        if (reason !== 'account_disabled' && reason !== 'subject_mismatch') {
          throw new SignInStoreUnavailableError('addresses', new Error('not a verification'));
        }
        state.transaction = { ...state.transaction, emailCode: undefined };
        return ended('email_code', reason);
      }
      state.transaction = {
        ...state.transaction,
        emailCode: undefined,
        verified: [
          ...state.transaction.verified,
          { step: 'email_code', params: read.params } as OfferedStep,
        ],
      };
      await audit('passed', 'email_code');
      return null;
    };

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
    });

    // Rule 3: the limiters.
    const { limits, request, botChallenge } = hooks;
    if (limits !== undefined) {
      const verdict = await fromStore('limits', () => limits(hookRound));
      if (verdict.kind === 'throttled') {
        await audit('refused', roundStep(), 'rate_limited');
        return throttled(verdict.retryAfterSeconds);
      }
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

    // Rule 5: a due bot challenge comes before every other step. Any other
    // answer is ignored, so no password is checked while one is due.
    if (botChallenge !== undefined) {
      const verdict = await fromStore('botChallenge', () => botChallenge(hookRound));
      if (verdict.kind === 'due') {
        const challenge = handlers.challenge;
        if (challenge === undefined || !served.has(challenge.step)) {
          return throttled(verdict.retryAfterSeconds);
        }
        const offer = await offerOf([challenge]);
        if (!answers(offer)) return offerStep(offer);
        const result = await verifyPending(offer);
        if (result !== null) return result;
      }
    }

    // Rule 6: the identifier. The request's login_hint first, then an
    // answer's; the first is fixed, and a different one ends the transaction.
    const brought: { readonly identifier: string; readonly step: StepName }[] = [];
    if (context.loginHint !== undefined) {
      const identifier = readIdentifier(context.loginHint);
      if (identifier !== null) brought.push({ identifier, step: 'identifier' });
    }
    if (turn.pending !== null && STEPS_WITH_LOGIN_HINT.has(turn.pending.name)) {
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

    if (state.transaction.subject === undefined) {
      if (state.transaction.identifier === undefined) {
        // Nobody is named yet: the identifier step, the same for everyone, or
        // a discoverable first factor before it, with the identifier step and
        // the other first factors beside it (ADR-017 Decision 4).
        const discoverable = handlers.discoverable.filter((handler) => served.has(handler.step));
        const others = handlers.firstFactors.filter(
          (handler) => handler.discoverable !== true && served.has(handler.step)
        );
        if (discoverable.length === 0) {
          // No discoverable factor is registered (this issue's shape): the
          // identifier step alone. One is registered, but this transport cannot
          // serve it: the password it can serve, with the identifier step
          // beside it (ADR-017 Decision 4, amended 2026-10-31).
          const steps =
            handlers.discoverable.length === 0
              ? [handlers.identifier]
              : [...others, handlers.identifier];
          return offerStep(await offerOf(steps, { preferred: true }));
        }
        // A password offered here is answered with its login_hint, which
        // the identifier rule above has already taken.
        const offer = await offerOf([...discoverable, ...others, handlers.identifier], {
          preferred: true,
        });
        const pendingName = turn.pending?.name;
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

        // Rule 7: the first factor, offered alike to every account until one
        // succeeds. Only an answer to it is verified; any other is ignored.
        const firstFactors = handlers.firstFactors.filter((handler) => served.has(handler.step));
        if (firstFactors.length === 0) return redirect('step_not_available');
        const offer = await offerOf(firstFactors);
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
      fromStore('accounts', () => deps.accounts.findByUserId(realmId, subject));
    const provenAccount = await readAccount();
    if (provenAccount === null || provenAccount.userId !== subject)
      return ended('identifier', 'subject_mismatch');
    if (!provenAccount.enabled) return ended('identifier', 'account_disabled');
    let account: SignInAccount = provenAccount;

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

    // Rule 8, last: an address not proved yet is verified inline with an
    // emailed code, whatever REQUIRE_VERIFIED_ACCOUNT says (ADR-017 Decision
    // 8). An account the MFA policy needs a second factor of has met it, or
    // been redirected to the set-up step, above: never a code in its place.
    if (emailCodes !== undefined && !account.verified) {
      const result = await verifyAddress(emailCodes, subject);
      if (result !== null) return result;
    }

    // Rule 9: complete. The transport mints the session or the code, and the
    // transaction ends with it.
    const amr = transactionAmr(state.transaction.verified);
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

  return Object.freeze({ advance });
}
